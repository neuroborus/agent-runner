const { spawn } = require("node:child_process");
const { readFileSync, readlinkSync, writeFileSync } = require("node:fs");
const { createServer } = require("node:net");

// This fixed synthetic payload is never imported by ordinary discovery.
function main() {
  const [role, nonce, ...literal] = process.argv.slice(2);
  let buffer = "";
  const send = (message) =>
    process.stdout.write(JSON.stringify({ ...message, nonce }) + "\n");
  const receive = (callback) =>
    process.stdin.on("data", (bytes) => {
      buffer += bytes.toString("utf8");
      if (buffer.length > 16384) process.exit(126);
      let end;
      while ((end = buffer.indexOf("\n")) !== -1) {
        const message = JSON.parse(buffer.slice(0, end));
        buffer = buffer.slice(end + 1);
        if (message.nonce !== nonce) process.exit(126);
        callback(message);
      }
    });
  const own = () => ({
    pid: process.pid,
    namespaceId: readlinkSync("/proc/self/ns/pid"),
    stat: readFileSync("/proc/self/stat", "utf8"),
  });
  process.stdout.on("error", () => process.exit(125));
  if (role === "leaf") {
    createServer().listen("/output/leaf.sock", () =>
      send({ type: "leaf-ready", ...own() }),
    );
    return;
  }
  if (role === "worker") {
    const leaf = spawn(
      process.execPath,
      ["/proof/payload.cjs", "leaf", nonce],
      { detached: true, stdio: ["ignore", 1, 2] },
    );
    leaf.once("error", () => process.exit(125));
    leaf.unref();
    // The leaf's ready message proves creation before the worker's exit.
    process.on("message", (message) => {
      if (message.type === "reparent" && message.nonce === nonce)
        process.exit(0);
    });
    send({ type: "worker-ready", ...own() });
    return;
  }
  if (role !== "root") process.exit(126);
  writeFileSync("/output/positive", nonce, { flag: "wx" });
  let controlDenied = false;
  try {
    writeFileSync("/control/receipt.json", "substitution", { flag: "w" });
  } catch (error) {
    controlDenied = ["ENOENT", "EACCES", "EROFS"].includes(error.code);
  }
  send({ type: "ready", ...own(), literal, positive: true, controlDenied });
  let worker;
  receive((message) => {
    if (message.type === "release" && worker === undefined) {
      worker = spawn(
        process.execPath,
        ["/proof/payload.cjs", "worker", nonce],
        { stdio: ["ignore", 1, 2, "ipc"] },
      );
      worker.once("error", () => process.exit(125));
      worker.once("exit", (code) => {
        if (code !== 0) process.exit(125);
        send({ type: "reparented" });
      });
    } else if (message.type === "reparent") worker.send(message);
    else if (message.type === "arm")
      send({ type: "armed", caseId: message.caseId, armed: true });
    else if (message.type === "finish") process.exit(0);
  });
}

if (require.main === module) main();
