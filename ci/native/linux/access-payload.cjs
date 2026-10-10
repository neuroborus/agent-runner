const { spawnSync } = require("node:child_process");
const { readFileSync, readlinkSync, writeFileSync } = require("node:fs");
const { createConnection, createServer } = require("node:net");

// Fixed fixture protocol and probes. No downloaded executable or provider runs.
function git(args, expected = true) {
  const result = spawnSync(
    "/proof/bin/git",
    [
      "-c",
      "core.hooksPath=/proof/hooks",
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
      ...args,
    ],
    {
      encoding: "utf8",
      timeout: 3000,
      maxBuffer: 16384,
      env: {
        PATH: "/proof/bin",
        LANG: "C",
        HOME: "/output",
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_CONFIG_GLOBAL: "/dev/null",
        GIT_ATTR_NOSYSTEM: "1",
        GIT_TERMINAL_PROMPT: "0",
        GIT_PAGER: "",
      },
    },
  );
  if (result.error || result.signal || !Number.isInteger(result.status))
    throw new Error("Git executable failed");
  if (
    expected
      ? result.status !== 0
      : result.status === 0 ||
        !/(?:Permission denied|Read-only file system)/u.test(result.stderr)
  )
    throw new Error("Git authority mismatch");
  return expected ? result.stdout : `EXIT_${result.status}`;
}

function channel(operation, probe, ready) {
  const send = (message) =>
    process.stdout.write(
      JSON.stringify({ ...message, nonce: operation.nonce }) + "\n",
    );
  let buffer = "";
  let state = "ready";
  let pending = Promise.resolve();
  process.stdout.on("error", () => process.exit(125));
  process.stdin.on("data", (bytes) => {
    buffer += bytes.toString("utf8");
    if (Buffer.byteLength(buffer) > 16384) process.exit(126);
    let end;
    while ((end = buffer.indexOf("\n")) >= 0) {
      const message = JSON.parse(buffer.slice(0, end));
      buffer = buffer.slice(end + 1);
      pending = pending.then(async () => {
        if (message.nonce !== operation.nonce)
          throw new Error("Invalid probe nonce");
        if (message.type === "release" && state === "ready") {
          state = "probing";
          send(await probe());
          state = "observed";
        } else if (
          message.type === "arm" &&
          state === "observed" &&
          message.caseId === operation.profile
        ) {
          state = "armed";
          send({ type: "armed", caseId: operation.profile, armed: true });
        } else if (message.type === "finish" && state === "armed")
          process.exit(0);
        else throw new Error("Invalid probe boundary");
      });
      pending.catch(() => process.exit(125));
    }
  });
  writeFileSync("/output/positive", operation.nonce, { flag: "wx" });
  send({
    type: "ready",
    positive: true,
    profile: operation.profile,
    pid: process.pid,
    namespaceId: readlinkSync("/proc/self/ns/pid"),
    stat: readFileSync("/proc/self/stat", "utf8"),
    ...ready,
  });
}

function connect(options, nonce, denied = false) {
  return new Promise((resolve, reject) => {
    const socket = createConnection(options);
    let bytes = "";
    const finish = (error, code) => {
      clearTimeout(timer);
      socket.destroy();
      error ? reject(error) : resolve(code);
    };
    const timer = setTimeout(
      () => finish(new Error("Endpoint deadline")),
      1500,
    );
    socket.on("data", (chunk) => {
      bytes += chunk.toString();
      if (denied || bytes.length > 128)
        finish(new Error("Host endpoint accessible"));
      else if (bytes === nonce) finish();
    });
    socket.once("connect", () => {
      if (denied) finish(new Error("Host endpoint accessible"));
    });
    socket.once("error", (error) => {
      finish(
        denied &&
          [
            "ENOENT",
            "EACCES",
            "EPERM",
            "ECONNREFUSED",
            "ENETUNREACH",
            "EHOSTUNREACH",
          ].includes(error.code)
          ? null
          : error,
        error.code,
      );
    });
    socket.once("end", () => {
      if (!denied && bytes !== nonce)
        finish(new Error("Missing endpoint response"));
    });
  });
}

async function loopback(nonce) {
  const server = createServer((socket) => socket.end(nonce));
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    await connect({ host: "127.0.0.1", port: server.address().port }, nonce);
  } finally {
    await new Promise((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
}

function main() {
  const operation = JSON.parse(readFileSync("/proof/operation.json", "utf8"));
  const profile = operation.profile;
  if (
    process.argv.slice(2).join(",") !== `profile,${profile}` ||
    !["read-only", "workspace-write", "trusted-command"].includes(profile)
  )
    process.exit(126);
  if (
    git(["rev-parse", "HEAD"]).trim() !== operation.head ||
    git(["log", "-1", "--format=%H"]).trim() !== operation.head ||
    git(["cat-file", "-e", "HEAD^{commit}"]) !== "" ||
    git(["status", "--porcelain=v1"]) !== "" ||
    readFileSync("/workspace/content.txt", "utf8") !== "original content\n"
  )
    process.exit(125);
  channel(
    operation,
    async () => {
      const denials = [];
      function deny(id, effect) {
        const code = effect();
        denials.push({
          id,
          code,
          attempted: true,
          denied: true,
          positiveControl: operation.positiveControls === true,
        });
      }
      function inaccessible(effect) {
        try {
          effect();
        } catch (error) {
          if (
            ["ENOENT", "EACCES", "EROFS", "EPERM", "EBUSY"].includes(error.code)
          )
            return error.code;
          throw error;
        }
        throw new Error("Prohibited file authority available");
      }
      const write = (file) =>
        inaccessible(() => writeFileSync(file, "substitution\n"));
      const read = (file) => inaccessible(() => readFileSync(file));
      let edit;
      if (profile === "read-only") {
        deny("content-write", () => write("/workspace/content.txt"));
        edit = "denied";
      } else {
        writeFileSync("/workspace/content.txt", "owned edit\n");
        edit = "permitted";
      }
      deny("git-add", () => git(["add", "--", "content.txt"], false));
      deny("git-commit", () =>
        git(
          ["commit", "--allow-empty", "-m", "test(fixture): denied commit"],
          false,
        ),
      );
      for (const [id, file] of [
        ["git-config", "/metadata/config"],
        ["git-index", "/metadata/index"],
        ["git-ref", "/metadata/refs/heads/proof"],
        ["git-pointer", "/workspace/.git"],
        ["outside-write", operation.outside],
        ["receipt-write", operation.receipt],
        ["control-write", operation.control],
      ])
        deny(id, () => write(file));
      for (const [id, file] of [
        ["credential-read", operation.credential],
        ["checkout-read", operation.checkout],
        ["receipt-read", operation.receipt],
      ])
        deny(id, () => read(file));
      await loopback(operation.nonce);
      for (const [id, options] of [
        ["host-loopback", { host: "127.0.0.1", port: operation.port }],
        ["host-network", { host: operation.host, port: operation.port }],
        ["host-socket", { path: operation.socket }],
        ["abstract-socket", { path: `\0${operation.abstract}` }],
      ]) {
        const code = await connect(options, operation.nonce, true);
        deny(id, () => code);
      }
      return {
        type: "access-result",
        profile,
        inspection: true,
        edit,
        loopback: true,
        denials,
      };
    },
    { inspection: true },
  );
}

module.exports = { git, channel };
if (require.main === module) {
  try {
    main();
  } catch {
    process.exitCode = 125;
  }
}
