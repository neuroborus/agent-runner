import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rmdir,
  unlink,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import {
  fetchNativePackageArchive,
  nativePackageInput,
  NATIVE_PACKAGE_LIMITS,
  preflightNativeTar,
  verifyNativeArchive,
} from "../index.js";

const execute = promisify(execFile);
export const feasibilityDigest = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");
export function requireProviderFeasibilityCI(platform, candidateSha) {
  if (
    process.platform !== platform ||
    process.arch !== "x64" ||
    process.env.CI !== "true" ||
    process.env.GITHUB_ACTIONS !== "true" ||
    process.env.RUNNER_ENVIRONMENT !== "github-hosted" ||
    process.env.RUNNER_OS !==
      { linux: "Linux", darwin: "macOS", win32: "Windows" }[platform] ||
    !/^[a-f0-9]{40}$/u.test(candidateSha ?? "")
  ) {
    const error = new Error(
      "Provider feasibility requires matching hosted CI.",
    );
    error.code = "ERR_NATIVE_FEASIBILITY_WORKER_UNAVAILABLE";
    throw error;
  }
}

export function feasibilityRuntimeMembers(provider, platform) {
  const input = nativePackageInput(`${provider}-${platform}`);
  if (provider === "claude") return [input.entrypoint];
  if (provider !== "codex") throw new Error("Unsupported feasibility package.");
  return [
    input.entrypoint,
    "codex-package.json",
    `codex-path/rg${platform === "win32" ? ".exe" : ""}`,
    ...(platform === "win32"
      ? [
          "codex-resources/codex-command-runner.exe",
          "codex-resources/codex-windows-sandbox-setup.exe",
        ]
      : [
          "codex-resources/zsh/bin/zsh",
          ...(platform === "linux" ? ["codex-resources/bwrap"] : []),
        ]),
  ];
}

/** Matching-platform extraction only after integrity and complete data-only
 * preflight. No package scripts, installer, review bindings, or release claims. */
export async function prepareFeasibilityInputs(platform, candidateSha) {
  requireProviderFeasibilityCI(platform, candidateSha);
  if (
    typeof process.env.RUNNER_TEMP !== "string" ||
    !path.isAbsolute(process.env.RUNNER_TEMP)
  )
    throw new Error("Missing explicit CI storage.");
  const temporary = await realpath(process.env.RUNNER_TEMP);
  if (!path.isAbsolute(temporary)) throw new Error("Missing owned CI storage.");
  const directory = await mkdtemp(
    path.join(temporary, "native-provider-feasibility-"),
  );
  const owned = [];
  const remember = async (file) => {
    const identity = await lstat(file, { bigint: true });
    if (
      identity.isSymbolicLink() ||
      (!identity.isDirectory() && (!identity.isFile() || identity.nlink !== 1n))
    )
      throw new Error("Invalid owned input identity.");
    owned.push({ file, identity });
  };
  await remember(directory);
  const cleanup = async () => {
    const witnesses = [];
    for (const { file, identity } of [...owned].reverse()) {
      const observed = await lstat(file, { bigint: true });
      if (
        observed.dev !== identity.dev ||
        observed.ino !== identity.ino ||
        observed.isDirectory() !== identity.isDirectory() ||
        observed.isSymbolicLink() ||
        (!observed.isDirectory() &&
          (!observed.isFile() || observed.nlink !== 1n))
      )
        throw new Error("Input cleanup refused a substituted object.");
      witnesses.push([String(observed.dev), String(observed.ino)]);
      if (identity.isDirectory()) await rmdir(file);
      else await unlink(file);
    }
    return feasibilityDigest(JSON.stringify(witnesses));
  };
  try {
    const intent = path.join(directory, "intent.json");
    await writeFile(intent, JSON.stringify({ candidateSha, platform }), {
      flag: "wx",
      mode: 0o400,
    });
    await remember(intent);
    const tar =
      platform === "win32"
        ? path.join(process.env.SystemRoot, "System32", "tar.exe")
        : "/usr/bin/tar";
    const tarSha256 = feasibilityDigest(await readFile(tar));
    const version = await execute(tar, ["--version"], {
      timeout: 10000,
      maxBuffer: 4096,
    });
    const tool = {
      role: "tool",
      name: "tar",
      version: version.stdout.trim().split(/\r?\n/u)[0],
      sha256: tarSha256,
    };
    const packages = {};
    for (const provider of ["codex", "claude"]) {
      const input = nativePackageInput(`${provider}-${platform}`),
        chunks = [];
      let bytes = 0;
      for await (const chunk of await fetchNativePackageArchive(input.id)) {
        bytes += chunk.length;
        if (bytes > NATIVE_PACKAGE_LIMITS.archiveBytes)
          throw new Error("Archive exceeds feasibility bound.");
        chunks.push(Buffer.from(chunk));
      }
      const archive = Buffer.concat(chunks, bytes);
      await verifyNativeArchive(
        [archive],
        { bytes: input.bytes ?? bytes, integrity: input.integrity },
        () => {},
      );
      const members = await preflightNativeTar([archive]);
      if (platform === "win32") {
        const names = new Map();
        for (const { path: name } of members) {
          const parts = name.split("/");
          while (parts.length) {
            const value = parts.join("/"),
              key = value.toLowerCase();
            if (names.has(key) && names.get(key) !== value)
              throw new Error("Archive contains case aliases.");
            names.set(key, value);
            parts.pop();
          }
        }
      }
      const selected = feasibilityRuntimeMembers(provider, platform);
      if (
        !selected.every((name) =>
          members.some((member) => member.path === name),
        )
      )
        throw new Error("Required runtime member is absent.");
      const content = path.join(directory, provider);
      await mkdir(content, { mode: 0o700 });
      await remember(content);
      const parents = new Set([content]);
      for (const name of selected) {
        let parent = content;
        for (const part of name.split("/").slice(0, -1)) {
          parent = path.join(parent, part);
          if (!parents.has(parent)) {
            await mkdir(parent, { mode: 0o700 });
            await remember(parent);
            parents.add(parent);
          }
        }
      }
      const archiveFile = path.join(directory, `${provider}.tgz`);
      await writeFile(archiveFile, archive, { flag: "wx", mode: 0o400 });
      await remember(archiveFile);
      if (feasibilityDigest(await readFile(tar)) !== tarSha256)
        throw new Error("Extractor identity changed.");
      await execute(
        tar,
        [
          "-xzf",
          archiveFile,
          "-C",
          content,
          "--no-same-owner",
          "--",
          ...selected,
        ],
        { timeout: 30000, maxBuffer: 4096 },
      );
      for (const name of selected) {
        const file = path.join(content, ...name.split("/")),
          member = members.find((entry) => entry.path === name);
        if ((await realpath(file)) !== file)
          throw new Error("Extracted input is aliased.");
        await remember(file);
        if (feasibilityDigest(await readFile(file)) !== member.sha256)
          throw new Error("Extracted input digest mismatch.");
        await chmod(file, name.endsWith(".json") ? 0o400 : 0o500);
      }
      packages[provider] = {
        file: path.join(content, ...input.entrypoint.split("/")),
        directory: content,
        component: {
          role: "tool",
          name: provider,
          version: input.version,
          sha256: members.find(({ path: name }) => name === input.entrypoint)
            .sha256,
        },
      };
    }
    return { directory, packages, tool, cleanup };
  } catch (error) {
    // Unknown extractor output stays quarantined; no recursive deletion adopts it.
    try {
      await cleanup();
    } catch {
      error.cleanupUncertain = true;
    }
    throw error;
  }
}
