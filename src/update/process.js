import { createHash } from "node:crypto";
import { lstat } from "node:fs/promises";
import { hostname } from "node:os";

import {
  inspectOwnedSessionProcesses,
  readProcessIdentity,
  readProcessNamespace,
  spawnOwnedProcess,
} from "../platform/index.js";

// Only previously registered identities are eligible for retirement inspection.
export async function preparationProcessRetired(
  record,
  {
    identity = readProcessIdentity,
    namespace: readNamespace = readProcessNamespace,
    stat = lstat,
    session = inspectOwnedSessionProcesses,
  } = {},
) {
  if (record === null) return true;
  if (record.hostname !== hostname()) return false;
  const observer = await identity(process.pid);
  const namespace = await readNamespace(process.pid);
  if (!observer || !namespace) return false;
  if (observer.bootId !== record.processIdentity.bootId) return true;
  if (namespace !== record.observerNamespace) return false;
  const current = await identity(record.pid);
  if (current !== null) {
    if (
      current.bootId === record.processIdentity.bootId &&
      current.startTicks === record.processIdentity.startTicks
    )
      return false;
  } else {
    try {
      await stat(`/proc/${record.pid}`);
      return false;
    } catch (error) {
      if (error.code !== "ENOENT") return false;
    }
  }
  // A retired private namespace's PID 1 cannot leave its children alive.
  if (record.namespaceId !== namespace) return true;
  const token = createHash("sha256")
    .update(
      `${record.pid}\0${record.processIdentity.bootId}\0${record.processIdentity.startTicks}`,
    )
    .digest("hex");
  // After owner retirement, a bare session number can belong to a new session
  // whose leader also exited. Require the owned token or verified ancestry.
  const members = session(record.pid, token, {
    includeSession: false,
  });
  return members !== null && members.length === 0;
}

export async function runCandidateCommand(
  command,
  args,
  {
    directory,
    env,
    onProcess,
    readOnly = [],
    network = false,
    spawn = spawnOwnedProcess,
  },
) {
  await directory.verify();
  const deadline = process.hrtime.bigint() + 120_000_000_000n;
  const mounts = readOnly.flatMap(({ path }, index) => [
    "--ro-bind",
    `/proc/self/fd/${index + 4}`,
    path,
  ]);
  const vector = [
    "--die-with-parent",
    "--unshare-user",
    "--unshare-pid",
    "--new-session",
    "--cap-drop",
    "ALL",
    ...(!network ? ["--unshare-net"] : []),
    "--ro-bind",
    "/",
    "/",
    "--bind",
    "/proc/self/fd/3",
    directory.path,
    ...mounts,
    "--proc",
    "/proc",
    "--dev",
    "/dev",
    "--chdir",
    directory.path,
    "--",
    command,
    ...args,
  ];
  const child = spawn("/usr/bin/bwrap", vector, {
    cwd: "/",
    env,
    onProcess,
    deadlineNs: String(deadline),
    stdio: [
      "pipe",
      "pipe",
      "pipe",
      directory.handle.fd,
      ...readOnly.map(({ handle }) => handle.fd),
    ],
  });
  const output = { stdout: [], stderr: [] };
  let bytes = 0;
  let expired = false;
  const timer = setTimeout(
    () => {
      expired = true;
      child.kill("SIGKILL");
    },
    Math.max(
      0,
      Math.ceil(Number(deadline - process.hrtime.bigint()) / 1_000_000),
    ),
  );
  let result;
  try {
    child.stdin.on("error", () => child.kill("SIGKILL"));
    for (const [name, stream] of [
      ["stdout", child.stdout],
      ["stderr", child.stderr],
    ])
      stream.on("data", (chunk) => {
        bytes += chunk.length;
        if (bytes > 2 * 1024 * 1024) child.kill("SIGKILL");
        else output[name].push(chunk);
      });
    child.stdin.end();
    result = await child.ownedCompletion;
    expired ||= process.hrtime.bigint() >= deadline;
  } finally {
    clearTimeout(timer);
  }
  await directory.verify();
  if (
    expired ||
    bytes > 2 * 1024 * 1024 ||
    result.outcome?.type !== "close" ||
    result.outcome.exitCode !== 0
  )
    throw new Error("Candidate command failed.");
  return Object.fromEntries(
    Object.entries(output).map(([key, chunks]) => [
      key,
      Buffer.concat(chunks).toString("utf8"),
    ]),
  );
}

// The probe is contained with its child and has no provider, project or client settings.
export const MCP_PROBE = String.raw`
const {spawn}=require("node:child_process");
const {createInterface}=require("node:readline");
const child=spawn(process.execPath,[process.argv[1],"mcp"],{stdio:["pipe","pipe","pipe"],env:process.env});
let complete=false, failed=false, bytes=0;
const fail=()=>{failed=true; child.kill("SIGKILL");};
const send=(value)=>child.stdin.write(JSON.stringify(value)+"\n",error=>{if(error)fail();});
child.on("error",fail); child.stdin.on("error",fail);
child.stderr.on("data",fail);
child.stdout.on("data",chunk=>{bytes+=chunk.length;if(bytes>2*1024*1024)fail();});
const lines=createInterface({input:child.stdout,crlfDelay:Infinity});
lines.on("line",line=>{
  try {
    const value=JSON.parse(line);
    if(value.jsonrpc!=="2.0"||value.error)throw Error();
    if(value.id===1){
      if(!value.result?.protocolVersion||!value.result?.serverInfo)throw Error();
      send({jsonrpc:"2.0",method:"notifications/initialized"});
      send({jsonrpc:"2.0",id:2,method:"tools/list",params:{}});
    }else if(value.id===2){
      if(!Array.isArray(value.result?.tools)||!value.result.tools.length||value.result.tools.some(tool=>typeof tool.name!=="string"))throw Error();
      complete=true;child.stdin.end();
    }else if(Object.hasOwn(value,"id"))throw Error();
  }catch{fail();}
});
child.on("close",(code,signal)=>{lines.close();if(failed||!complete||code!==0||signal)process.exitCode=1;else process.stdout.write("MCP smoke passed\n");});
send({jsonrpc:"2.0",id:1,method:"initialize",params:{protocolVersion:"2025-11-25",capabilities:{},clientInfo:{name:"candidate-smoke",version:"1.0.0"}}});
`;
