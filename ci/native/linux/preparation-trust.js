import { execFile } from "node:child_process";
import { constants } from "node:fs";
import { lstat, open, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { promisify } from "node:util";

import { assertOwnedProcessLauncherProtected } from "../../../src/agents/index.js";
import { diagnosticCommand } from "../diagnostics.js";

const execute = diagnosticCommand(
  "linux-preparation-trust",
  promisify(execFile),
);
const TARGETS = [
  "/usr/share",
  "/usr/share/keyrings",
  "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
];
const TOOLS = [
  "sudo",
  "timeout",
  "chmod",
  "apt-get",
  "apt-cache",
  "dpkg-query",
];
const FIELDS = [
  "dev",
  "ino",
  "mode",
  "uid",
  "gid",
  "nlink",
  "size",
  "mtimeNs",
  "ctimeNs",
  "birthtimeNs",
];
const MAXIMUM = 1048576;
const need = (condition) => {
  if (!condition) throw new Error("Unverified Linux preparation trust input");
};
const same = (before, after) =>
  FIELDS.every((key) => before[key] === after[key]);

/** Irreversible, fixed-path setup only for the admitted disposable hosted worker.
 * No production guard changes or insecure permission restoration are permitted. */
export async function hardenLinuxPreparationTrust(
  binding,
  persist,
  {
    fs = { lstat, open, readFile, realpath },
    run = execute,
    protect = assertOwnedProcessLauncherProtected,
    now = () => performance.now(),
    env = process.env,
    platform = process.platform,
    architecture = process.arch,
    signal,
  } = {},
) {
  need(
    platform === "linux" &&
      architecture === "x64" &&
      env.CI === "true" &&
      env.GITHUB_ACTIONS === "true" &&
      env.ImageOS === "ubuntu24" &&
      env.RUNNER_OS === "Linux" &&
      env.RUNNER_ENVIRONMENT === "github-hosted" &&
      binding?.platform === "linux" &&
      binding.workflow === "native-poc" &&
      binding.image === "ubuntu-24.04" &&
      binding.architecture === "x64" &&
      /^[a-f0-9]{40}$/u.test(binding.candidateSha) &&
      binding.checkoutSha === binding.candidateSha &&
      binding.repository === env.GITHUB_REPOSITORY &&
      binding.runId === env.GITHUB_RUN_ID &&
      String(binding.runAttempt) === env.GITHUB_RUN_ATTEMPT,
  );
  const deadline = now() + 30000;
  const active = () => need(!signal?.aborted && now() < deadline);
  const inspect = async (file, directory = false) => {
    active();
    const before = await fs.lstat(file, { bigint: true });
    need(
      !before.isSymbolicLink() &&
        (directory ? before.isDirectory() : before.isFile()) &&
        before.uid === 0n &&
        before.gid === 0n &&
        (await fs.realpath(file)) === file,
    );
    need(same(before, await fs.lstat(file, { bigint: true })));
    active();
    return before;
  };
  const readKeyring = async (file, expected) => {
    need(
      expected.nlink === 1n &&
        expected.size > 0n &&
        expected.size <= BigInt(MAXIMUM),
    );
    const held = await fs.open(
      file,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
    );
    try {
      need(same(expected, await held.stat({ bigint: true })));
      const result = Buffer.alloc(Number(expected.size));
      let offset = 0;
      for (let reads = 0; reads < 128 && offset < result.length; reads++) {
        active();
        const { bytesRead } = await held.read(
          result,
          offset,
          result.length - offset,
          offset,
        );
        need(bytesRead > 0);
        offset += bytesRead;
      }
      need(
        offset === result.length &&
          (await held.read(Buffer.alloc(1), 0, 1, offset)).bytesRead === 0 &&
          same(expected, await held.stat({ bigint: true })) &&
          same(expected, await inspect(file)),
      );
      return result;
    } finally {
      await held.close();
    }
  };
  const tools = new Map();
  const verifyTools = async () => {
    for (const [file, expected] of tools) {
      need(same(expected, await inspect(file)));
      protect(file);
      active();
    }
  };
  let record = { status: "POSSIBLE", target: null };
  try {
    active();
    const release = await fs.readFile("/etc/os-release", "utf8");
    need(
      /^ID=ubuntu$/mu.test(release) && /^VERSION_ID="24\.04"$/mu.test(release),
    );
    for (const name of TOOLS) {
      const file = "/usr/bin/" + name,
        stat = await inspect(file);
      need((stat.mode & 0o111n) !== 0n && !(stat.mode & 0o022n));
      protect(file);
      tools.set(file, stat);
    }
    const targets = [];
    for (const [index, file] of TARGETS.entries()) {
      const stat = await inspect(file, index < 2);
      targets.push({
        file,
        stat,
        contents: index === 2 ? await readKeyring(file, stat) : null,
      });
    }
    const verify = async (target, hardened = false) => {
      const actual = await inspect(target.file, target.contents === null),
        expected = hardened
          ? {
              ...target.stat,
              mode: target.stat.mode & ~0o022n,
              ctimeNs: actual.ctimeNs,
            }
          : target.stat;
      need(
        same(expected, actual) &&
          (!hardened || actual.ctimeNs >= target.stat.ctimeNs),
      );
      if (target.contents)
        need(target.contents.equals(await readKeyring(target.file, actual)));
      return actual;
    };
    for (const [index, target] of targets.entries()) {
      record = { status: "POSSIBLE", target: target.file };
      await persist({ ...record }); // Durable intent precedes even a permission-only effect.
      active();
      await verifyTools();
      for (const ancestor of targets.slice(0, index)) await verify(ancestor);
      protect(path.posix.dirname(target.file));
      await verify(target); // The now-protected parent must still name the snapshot.
      active();
      await run(
        "/usr/bin/sudo",
        [
          "--non-interactive",
          "--",
          "/usr/bin/timeout",
          "--signal=TERM",
          "--kill-after=2s",
          "5s",
          "/usr/bin/chmod",
          "go-w",
          "--",
          target.file,
        ],
        {
          env: { PATH: "/usr/bin:/bin", LANG: "C" },
          timeout: 8000,
          maxBuffer: 65536,
          killSignal: "SIGKILL",
          signal,
        },
      );
      active();
      target.stat = await verify(target, true);
      protect(target.file);
    }
    const verifyAll = async () => {
      await verifyTools();
      for (const target of targets) {
        await verify(target);
        protect(target.file); // The original strict guard gates every package effect.
      }
    };
    await verifyAll();
    active();
    record = { status: "PASS", target: null };
    await persist({ ...record });
    await verifyAll(); // Completion persistence must not hide an input substitution.
    active();
    return record;
  } catch (error) {
    try {
      await persist({ ...record, status: "FAIL" });
    } catch {
      // Retain the write-ahead intent and original refusal; never roll modes back.
    }
    throw error;
  }
}
