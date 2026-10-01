import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  rename,
  writeFile,
} from "node:fs/promises";
import { createServer, createConnection } from "node:net";
import { networkInterfaces } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { assertOwnedProcessLauncherProtected } from "../../../src/agents/index.js";
import { LINUX_ACCESS_CHECK_IDS } from "../index.js";
import { protectedLibraries } from "./confinement.js";
import { digest } from "./inspect.js";
import {
  ACCESS_PROFILES,
  ACCESS_POLICY_ID,
  FIXED_SUBJECT,
  accessGrants,
  validateAccessObservation,
  recordAccessSetupFailure,
  validateCommitRequest,
  validateCommitEffect,
  validateCommitMetadata,
} from "./profiles.js";

const execute = promisify(execFile);
const SOURCE = fileURLToPath(new URL("./", import.meta.url));
const CHECKOUT = fileURLToPath(
  new URL("../../../package.json", import.meta.url),
);
const GIT_ENV = Object.freeze({
  PATH: "/usr/bin:/bin",
  LANG: "C",
  HOME: "/nonexistent",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_ATTR_NOSYSTEM: "1",
  GIT_TERMINAL_PROMPT: "0",
  GIT_OPTIONAL_LOCKS: "0",
});

async function git(storage, args) {
  const { stdout } = await execute(
    storage.git,
    [
      "-c",
      `core.hooksPath=${storage.hooks}`,
      "-c",
      "core.fsmonitor=false",
      "-c",
      "commit.gpgsign=false",
      "-c",
      "core.attributesFile=/dev/null",
      "-c",
      "gc.auto=0",
      "-c",
      "maintenance.auto=false",
      "--git-dir",
      storage.metadata,
      "--work-tree",
      storage.workspace,
      ...args,
    ],
    { env: GIT_ENV, timeout: 3000, maxBuffer: 65536 },
  );
  return stdout;
}

async function tree(directory, prefix = "", entries = []) {
  for (const name of (await readdir(path.join(directory, prefix))).sort()) {
    const relative = path.posix.join(prefix, name);
    const file = path.join(directory, relative);
    const stat = await lstat(file);
    if (entries.length >= 4096 || stat.isSymbolicLink())
      throw new Error("Unverifiable synthetic repository");
    if (stat.isDirectory()) await tree(directory, relative, entries);
    else {
      if (!stat.isFile() || stat.size > 1048576)
        throw new Error("Unexpected synthetic repository member");
      entries.push([relative, digest(await readFile(file)), stat.mode & 0o777]);
    }
  }
  return entries;
}

async function snapshot(storage) {
  const head = (await git(storage, ["rev-parse", "HEAD"])).trim();
  const refs = (
    await git(storage, ["for-each-ref", "--format=%(refname) %(objectname)"])
  )
    .trim()
    .split("\n")
    .map((line) => line.split(" "));
  const identity = `${(await git(storage, ["config", "--local", "user.name"])).trim()} <${(await git(storage, ["config", "--local", "user.email"])).trim()}>`;
  return {
    head,
    refs,
    identity,
    branch: (await git(storage, ["symbolic-ref", "HEAD"])).trim(),
    config: await readFile(path.join(storage.metadata, "config"), "utf8"),
    status: await git(storage, ["status", "--porcelain=v1"]),
    metadata: await tree(storage.metadata),
    workspace: await tree(storage.workspace),
  };
}

async function listen(server, options) {
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(options, resolve);
  });
}

async function positiveEndpoint(options, nonce) {
  await new Promise((resolve, reject) => {
    const socket = createConnection(options);
    let bytes = "";
    const timer = setTimeout(
      () => finish(new Error("External positive-control deadline")),
      1500,
    );
    const finish = (error) => {
      clearTimeout(timer);
      socket.destroy();
      error ? reject(error) : resolve();
    };
    socket.once("error", finish);
    socket.on("data", (chunk) => {
      bytes += chunk.toString();
      if (bytes === nonce) finish();
      else if (bytes.length >= nonce.length)
        finish(new Error("Invalid external positive control"));
    });
    socket.once("end", () => {
      if (bytes !== nonce) finish(new Error("Absent external response"));
    });
  });
}

async function endpoints(directory) {
  const nonce = randomUUID();
  const host = Object.values(networkInterfaces())
    .flat()
    .find((entry) => !entry.internal && entry.family === "IPv4")?.address;
  if (!host) throw new Error("Missing live host network positive control");
  const socket = path.join(directory, "host.sock");
  const abstract = `native-proof-${nonce}`;
  const servers = [];
  const close = async () => {
    for (const server of servers)
      if (server.listening)
        await new Promise((resolve, reject) =>
          server.close((error) => (error ? reject(error) : resolve())),
        );
  };
  try {
    for (const options of [
      { port: 0, host: "0.0.0.0" },
      { path: socket },
      { path: `\0${abstract}` },
    ]) {
      const server = createServer((client) => client.end(nonce));
      servers.push(server);
      await listen(server, options);
    }
    const port = servers[0].address().port;
    const controls = [
      { host: "127.0.0.1", port },
      { host, port },
      { path: socket },
      { path: `\0${abstract}` },
    ];
    const confirm = async () => {
      for (const options of controls) await positiveEndpoint(options, nonce);
    };
    await confirm();
    return { host, port, socket, abstract, nonce, close, confirm };
  } catch (error) {
    await close();
    throw error;
  }
}

async function prepareRepository(base, profile, gitFile, hooks) {
  const directory = path.join(base.directory, "access", profile);
  await mkdir(directory, { mode: 0o700 });
  const workspace = path.join(directory, "workspace");
  const metadata = path.join(directory, "metadata");
  const pointer = path.join(directory, "pointer");
  const storage = {
    workspace,
    metadata,
    pointer,
    git: gitFile,
    hooks,
    operation: path.join(directory, "operation.json"),
    protocol: path.join(base.directory, "inputs", "access-payload.cjs"),
  };
  await execute(
    gitFile,
    ["init", "--initial-branch=proof", `--template=${hooks}`, workspace],
    { env: GIT_ENV, timeout: 3000, maxBuffer: 4096 },
  );
  await rename(path.join(workspace, ".git"), metadata);
  await writeFile(path.join(workspace, ".git"), `gitdir: ${metadata}\n`, {
    flag: "wx",
    mode: 0o400,
  });
  await writeFile(pointer, "gitdir: /metadata\n", { flag: "wx", mode: 0o400 });
  await git(storage, ["config", "--local", "user.name", "Fixture Author"]);
  await git(storage, [
    "config",
    "--local",
    "user.email",
    "fixture@example.invalid",
  ]);
  await git(storage, ["config", "--local", "core.fsmonitor", "false"]);
  await git(storage, ["config", "--local", "commit.gpgsign", "false"]);
  await writeFile(path.join(workspace, "content.txt"), "original content\n", {
    flag: "wx",
  });
  await git(storage, ["add", "--", "content.txt"]);
  await git(storage, [
    "commit",
    "-m",
    "test(fixture): initialize owned repository",
  ]);
  await git(storage, ["branch", "witness"]);
  await git(storage, ["tag", "witness"]);
  const hookDirectory = path.join(metadata, "hooks");
  await mkdir(hookDirectory, { mode: 0o700 });
  await writeFile(
    path.join(hookDirectory, "pre-commit"),
    "#!/proof/bin/node\nprocess.exit(97);\n",
    { flag: "wx", mode: 0o500 },
  );
  await git(storage, [
    "config",
    "--local",
    "core.hooksPath",
    "/metadata/hooks",
  ]);
  const before = await snapshot(storage);
  if (before.status !== "" || before.refs.length !== 3)
    throw new Error("Invalid synthetic repository positive control");
  if (profile === "commit")
    await writeFile(path.join(workspace, "content.txt"), "owned edit\n");
  return { storage, before, directory };
}

async function accessFixture(base, profile, common) {
  const { storage, before, directory } = await prepareRepository(
    base,
    profile,
    common.gitFile,
    common.hooks,
  );
  const controls = await endpoints(directory);
  try {
    const external = path.join(directory, "outside");
    await mkdir(external, { mode: 0o700 });
    const outside = path.join(external, "sentinel");
    const credential = path.join(external, "credential");
    for (const file of [outside, credential])
      await writeFile(file, controls.nonce, { flag: "wx", mode: 0o400 });
    const receipt = path.join(base.directory, "evidence", `${profile}.json`);
    const control = path.join(base.directory, "control", `${profile}.sentinel`);
    const checkoutDigest = digest(await readFile(CHECKOUT));
    const operation = {
      profile,
      nonce: controls.nonce,
      head: before.head,
      positiveControls: true,
      subject: FIXED_SUBJECT,
      outside,
      credential,
      checkout: CHECKOUT,
      receipt,
      control,
      host: controls.host,
      port: controls.port,
      socket: controls.socket,
      abstract: controls.abstract,
    };
    await writeFile(storage.operation, JSON.stringify(operation) + "\n", {
      flag: "wx",
      mode: 0o400,
    });
    const payload = path.join(
      base.directory,
      "inputs",
      profile === "commit" ? "fixed-executor.cjs" : "access-payload.cjs",
    );
    const grants = accessGrants(profile, storage);
    const policy = {
      ...base.policy,
      id: ACCESS_POLICY_ID,
      profile,
      grants,
      payloadDigest: digest(await readFile(payload)),
      libraries: common.libraries,
      gitDigest: digest(await readFile(common.gitFile)),
      protocolDigest: digest(await readFile(storage.protocol)),
      operationDigest: digest(await readFile(storage.operation)),
      pointerDigest: digest(await readFile(storage.pointer)),
      commitRequest:
        profile === "commit"
          ? validateCommitRequest({
              operation: "commit",
              subject: FIXED_SUBJECT,
            })
          : null,
    };
    const fixture = {
      ...base,
      profile,
      payload,
      policy,
      policyDigest: digest(JSON.stringify(policy)),
      arguments:
        profile === "commit" ? ["commit", FIXED_SUBJECT] : ["profile", profile],
    };
    await writeFile(
      path.join(base.directory, "evidence", `${profile}-policy.json`),
      JSON.stringify(policy) + "\n",
      { flag: "wx", mode: 0o400 },
    );
    const sentinel = async () => {
      for (const file of [outside, credential])
        if ((await readFile(file, "utf8")) !== controls.nonce)
          throw new Error("External sentinel mutated");
      if (
        digest(await readFile(CHECKOUT)) !== checkoutDigest ||
        digest(await readFile(storage.operation)) !== policy.operationDigest ||
        digest(await readFile(storage.protocol)) !== policy.protocolDigest ||
        digest(await readFile(storage.pointer)) !== policy.pointerDigest ||
        (await readdir(common.hooks)).length !== 0 ||
        digest(await readFile(common.gitFile)) !== policy.gitDigest
      )
        throw new Error("Protected authority mutated");
      const after = await snapshot(storage);
      if (
        profile !== "commit" &&
        (JSON.stringify(after.metadata) !== JSON.stringify(before.metadata) ||
          after.head !== before.head ||
          after.config !== before.config)
      )
        throw new Error("Ordinary Git authority escaped");
      const expectedWorkspace = before.workspace.map(([file, sha, mode]) => [
        file,
        file === "content.txt" && profile !== "read-only"
          ? digest("owned edit\n")
          : sha,
        mode,
      ]);
      // Before release, a writable profile has not yet performed its permitted edit.
      if (
        JSON.stringify(after.workspace) !== JSON.stringify(before.workspace) &&
        JSON.stringify(after.workspace) !== JSON.stringify(expectedWorkspace)
      )
        throw new Error("Unexpected workspace mutation");
      return after;
    };
    const effects = {
      nonce: controls.nonce,
      async ready(message) {
        if (message.profile !== profile || message.inspection !== true)
          throw new Error("Missing permitted inspection readiness");
        await controls.confirm();
        const initial = await sentinel();
        if (
          initial.head !== before.head ||
          JSON.stringify(initial.metadata) !== JSON.stringify(before.metadata)
        )
          throw new Error("Git authority preceded release");
      },
      sentinel,
      async observe(message) {
        const after = await sentinel();
        await controls.confirm();
        if (profile === "commit") {
          validateCommitRequest({
            operation: message.operation,
            subject: message.subject,
          });
          if (message.type !== "access-result" || message.profile !== "commit")
            throw new Error("Invalid executor result");
          const details = {
            ...after,
            parent: (await git(storage, ["rev-parse", "HEAD^"])).trim(),
            message: await git(storage, ["log", "-1", "--format=format:%B"]),
            changed: await git(storage, [
              "diff-tree",
              "--no-commit-id",
              "--name-only",
              "-r",
              "HEAD",
            ]),
            content: await readFile(
              path.join(storage.workspace, "content.txt"),
              "utf8",
            ),
            author: (
              await git(storage, ["log", "-1", "--format=%an <%ae>"])
            ).trim(),
            committer: (
              await git(storage, ["log", "-1", "--format=%cn <%ce>"])
            ).trim(),
          };
          const parents = (
            await git(storage, [
              "rev-list",
              "--parents",
              "--max-count=1",
              "HEAD",
            ])
          )
            .trim()
            .split(" ");
          if (
            parents.length !== 2 ||
            parents[0] !== after.head ||
            parents[1] !== before.head
          )
            throw new Error("Unexpected commit parent authority");
          validateCommitEffect(before, details);
          const objectIds = [
            after.head,
            (await git(storage, ["rev-parse", "HEAD^{tree}"])).trim(),
            (await git(storage, ["rev-parse", "HEAD:content.txt"])).trim(),
          ];
          validateCommitMetadata(before.metadata, after.metadata, objectIds);
          await writeFile(
            path.join(base.directory, "evidence", "commit-observation.json"),
            JSON.stringify({
              before,
              after: details,
              sentinelsUnchanged: true,
            }) + "\n",
            { flag: "wx", mode: 0o400 },
          );
        } else {
          if (
            profile !== "read-only" &&
            (await readFile(
              path.join(storage.workspace, "content.txt"),
              "utf8",
            )) !== "owned edit\n"
          )
            throw new Error("Permitted edit not observed");
          const denials = validateAccessObservation(profile, message, true);
          await writeFile(
            path.join(
              base.directory,
              "evidence",
              `${profile}-observation.json`,
            ),
            JSON.stringify({
              profile,
              policyDigest: fixture.policyDigest,
              denials,
              isolatedLoopback: true,
              hostPositiveControls: true,
              sentinelsUnchanged: true,
            }) + "\n",
            { flag: "wx", mode: 0o400 },
          );
        }
        return [
          {
            expected:
              profile === "commit"
                ? "Fixed operation changes only the expected HEAD/current branch and exact subject"
                : "Permitted inspection/edit and every declared content/Git/host denial",
            observed:
              profile === "commit"
                ? "Independent refs, configuration, identity, message, tree and sentinel comparison matched"
                : "Each live attempt matched; ready host controls survived; isolated loopback worked; external state was unchanged",
            matched: true,
            positiveControl: true,
            attempted: true,
            sentinelsUnchanged: true,
          },
        ];
      },
      async cleanup() {
        await sentinel();
        await controls.confirm();
        await controls.close();
      },
    };
    return { fixture, effects, close: controls.close };
  } catch (error) {
    await controls.close();
    throw error;
  }
}

/** Reuse the admitted ownership protocol once per profile; loss/recovery cases
 * remain in the ownership suite. Only Linux system CI reaches these effects. */
export async function runLinuxAccessProofs(
  job,
  base,
  runCase,
  record,
  blocked,
) {
  let common;
  try {
    await mkdir(path.join(base.directory, "access"), { mode: 0o700 });
    const gitFile = path.join(base.directory, "executables", "git");
    const source = await realpath("/usr/bin/git");
    assertOwnedProcessLauncherProtected(source);
    await copyFile(source, gitFile);
    await chmod(gitFile, 0o500);
    const libraries = new Map(
      base.policy.libraries.map((entry) => [entry.target, entry]),
    );
    for (const entry of await protectedLibraries(gitFile)) {
      if (
        libraries.has(entry.target) &&
        libraries.get(entry.target).sha256 !== entry.sha256
      )
        throw new Error("Incompatible Git ABI");
      libraries.set(entry.target, entry);
    }
    const hooks = path.join(base.directory, "control", "empty-hooks");
    await mkdir(hooks, { mode: 0o500 });
    for (const name of ["access-payload.cjs", "fixed-executor.cjs"]) {
      const target = path.join(base.directory, "inputs", name);
      await copyFile(path.join(SOURCE, name), target);
      await chmod(target, 0o400);
    }
    const { stdout: version } = await execute(gitFile, ["--version"], {
      env: GIT_ENV,
      timeout: 3000,
      maxBuffer: 1024,
    });
    if (!/^git version [0-9]+\.[0-9]+\.[0-9]+(?:[^\r\n]*)\n$/u.test(version))
      throw new Error("Unknown protected Git version");
    common = {
      gitFile,
      hooks,
      libraries: [...libraries.values()].sort((a, b) =>
        a.target.localeCompare(b.target),
      ),
      version: {
        name: "git",
        version: version.trim(),
        sha256: digest(await readFile(gitFile)),
      },
    };
  } catch (error) {
    await writeFile(
      path.join(base.directory, "evidence", "access-missing-inputs.json"),
      JSON.stringify({
        status: "BLOCKED",
        missingInputs: [
          "Protected Git executable/ABI and fresh confined synthetic repository storage",
        ],
        observation: error.code ?? "UNVERIFIED",
      }) + "\n",
      { flag: "wx", mode: 0o400 },
    );
    return blocked(LINUX_ACCESS_CHECK_IDS);
  }
  const cases = {};
  const fixtures = {};
  let setupFailure;
  for (const profile of ACCESS_PROFILES) {
    let prepared;
    const setupStarted = performance.now();
    try {
      prepared = await accessFixture(base, profile, common);
    } catch (error) {
      setupFailure = {
        profile,
        elapsedMs: Math.ceil(performance.now() - setupStarted),
      };
      const code =
        Number.isSafeInteger(error.code) && error.code > 0 && error.code <= 255
          ? `EXIT_${error.code}`
          : /^[A-Z][A-Z0-9_]{0,79}$/u.test(error.code ?? "")
            ? error.code
            : "UNVERIFIED";
      await writeFile(
        path.join(base.directory, "evidence", `${profile}-setup-failure.json`),
        JSON.stringify({
          status: "FAIL",
          candidateSha: job.candidateSha,
          profile,
          failedStage: "setup",
          observation: code,
          next: "Inspect the synthetic repository or live host-control setup failure. No denial or independent retirement was proved.",
        }) + "\n",
        { flag: "wx", mode: 0o400 },
      );
      break;
    }
    fixtures[profile] = prepared.fixture;
    try {
      cases[profile] = await runCase(
        profile,
        prepared.fixture,
        prepared.effects,
      );
    } finally {
      await prepared.close().catch(() => {});
    }
    await writeFile(
      path.join(base.directory, "evidence", `${profile}-result.json`),
      JSON.stringify(cases[profile]) + "\n",
      { flag: "wx", mode: 0o400 },
    );
    if (
      cases[profile].settlement.status !== "RETIRED" ||
      !cases[profile].settlement.independent
    )
      break;
  }
  const ordinary = ACCESS_PROFILES.filter((profile) => profile !== "commit");
  const mapping = {
    "profile.read-only": ["read-only"],
    "profile.workspace-write": ["workspace-write"],
    "profile.trusted-command": ["trusted-command"],
    "network.deny": ordinary,
    "network.loopback": ordinary,
    "ipc.deny": ordinary,
    "git.ordinary-denial": ordinary,
    "git.fixed-commit": ["commit"],
  };
  const results = [];
  for (const id of LINUX_ACCESS_CHECK_IDS) {
    const profiles = mapping[id];
    if (setupFailure && profiles.includes(setupFailure.profile)) {
      const pending = blocked([id])[0];
      results.push(
        recordAccessSetupFailure(
          {
            ...pending,
            versions: [...pending.versions, base.version, common.version],
          },
          setupFailure.elapsedMs,
        ),
      );
      continue;
    }
    if (
      !profiles.every((name) => cases[name]) &&
      !profiles.some((name) => cases[name]?.status === "FAIL")
    ) {
      results.push(blocked([id])[0]);
      continue;
    }
    const present = profiles.filter((name) => cases[name]);
    const fixture = fixtures[present[0]];
    const policy = {
      ...fixture.policy,
      profiles: present.map((name) => ({
        profile: name,
        sha256: fixtures[name].policyDigest,
      })),
    };
    await writeFile(
      path.join(base.directory, "evidence", `${id}-policy.json`),
      JSON.stringify(policy) + "\n",
      { flag: "wx", mode: 0o400 },
    );
    results.push(
      record(
        job,
        id,
        {
          ...fixture,
          policy,
          policyDigest: digest(JSON.stringify(policy)),
          versions: [common.version],
        },
        present.map((name) => cases[name]),
      ),
    );
  }
  return results;
}
