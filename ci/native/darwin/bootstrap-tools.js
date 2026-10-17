import { randomBytes } from "node:crypto";
import * as filesystem from "node:fs/promises";
import path from "node:path";
import { nativeException } from "../diagnostics.js";
import { observationDigest, observationObject } from "../index.js";
import { darwinCustodyTransport } from "./custody.js";
import { normalizeDarwinFileIdentity } from "./files-protocol.js";
import { protectedBytes, verifyDarwinBootstrapSeed } from "./private-files.js";
import {
  normalizeDarwinIdentity,
  sameDarwinIdentity,
  requireDarwin,
} from "./protocol.js";

const paths = ["/usr/bin/sudo", "/usr/bin/env"];
function transport(prepared, mode, nonce) {
  return darwinCustodyTransport(prepared.bootstrap, [
    mode,
    prepared.sourceDirectory,
    prepared.bootstrapSeed.sha256,
    prepared.job.candidateSha,
    ...(nonce ? [nonce] : []),
  ]);
}
function root(value) {
  const identity = normalizeDarwinIdentity(value);
  requireDarwin(
    ["uid", "gid", "ruid", "rgid", "svuid", "svgid"].every(
      (key) => identity[key] === 0,
    ),
  );
  return identity;
}
function tools(values) {
  requireDarwin(Array.isArray(values) && values.length === 2);
  return values.map((value, index) => {
    const file = value.file,
      signature = value.signature;
    observationObject(value, ["path", "sha256", "file", "signature"]);
    observationObject(file, [
      "identity",
      "bytes",
      "uid",
      "gid",
      "mode",
      "directory",
    ]);
    observationObject(signature, ["cdhash", "entitlementsSha256", "valid"]);
    normalizeDarwinFileIdentity(file.identity);
    requireDarwin(
      value.path === paths[index] &&
        /^[a-f0-9]{64}$/u.test(value.sha256) &&
        Number.isSafeInteger(file.bytes) &&
        file.bytes > 0 &&
        file.bytes <= 134217728 &&
        file.uid === 0 &&
        file.gid === 0 &&
        file.directory === false &&
        Number.isSafeInteger(file.mode) &&
        file.mode >= 0 &&
        file.mode <= 0o7777 &&
        !(file.mode & 0o22) &&
        signature.valid === true &&
        /^[a-f0-9]{40}$/u.test(signature.cdhash) &&
        /^[a-f0-9]{64}$/u.test(signature.entitlementsSha256),
    );
    return { path: value.path, sha256: value.sha256 };
  });
}

/** Rejoin the original protected result and independently absent birth. This
 * operation never releases the acquisition again or adopts a fresh tool read. */
export async function readDarwinBootstrapTools(prepared, options = {}) {
  const fs = options.fs ?? filesystem;
  await verifyDarwinBootstrapSeed(prepared, fs);
  const nonce = (
    options.bootstrapNonce ?? (() => randomBytes(16).toString("hex"))
  )();
  requireDarwin(/^[a-f0-9]{32}$/u.test(nonce));
  await fs.writeFile(
    path.join(prepared.directory, `darwin-tool-verifier-${nonce}.intent`),
    `${prepared.job.candidateSha} ${prepared.bootstrapSeed.sha256} ${nonce}\n`,
    { flag: "wx", mode: 0o400 },
  );
  const channel = await (options.bootstrapTransport ?? transport)(
    prepared,
    "--bootstrap-tools-read",
    nonce,
  );
  try {
    const checked = await channel.receive();
    observationObject(checked, [
      "owner",
      "verifier",
      "retired",
      "tools",
      "receiptSha256",
    ]);
    const owner = root(checked.owner),
      verifier = root(checked.verifier);
    requireDarwin(checked.retired === true && verifier.pid !== owner.pid);
    const exit = await channel.completion;
    requireDarwin(exit.code === 0 && exit.signal === null);
    let absent = false;
    try {
      (options.kill ?? process.kill)(verifier.pid, 0);
    } catch (cause) {
      absent = cause.code === "ESRCH";
    }
    requireDarwin(absent);
    const settlement = {
      status: "RETIRED",
      independent: true,
      emergencyCleanup: false,
    };
    if (checked.receiptSha256 === null) {
      requireDarwin(options.allowIncomplete === true);
      return { tools: null, owner, receipt: null, settlement };
    }
    requireDarwin(/^[a-f0-9]{64}$/u.test(checked.receiptSha256));
    const pin = {
        path: path.join(prepared.sourceDirectory, "bootstrap-tools.json"),
        sha256: checked.receiptSha256,
      },
      bytes = await protectedBytes(pin, 0, 0o444, 65536, fs);
    const original = JSON.parse(bytes);
    observationObject(original, [
      "purpose",
      "candidateSha",
      "seedSha256",
      "owner",
      "tools",
    ]);
    requireDarwin(
      original.purpose === "experiment" &&
        original.candidateSha === prepared.job.candidateSha &&
        original.seedSha256 === prepared.bootstrapSeed.sha256 &&
        sameDarwinIdentity(root(original.owner), owner) &&
        observationDigest(original.tools) === observationDigest(checked.tools),
    );
    const [elevation, environment] = tools(original.tools);
    return {
      tools: { elevation, environment },
      owner,
      receipt: pin,
      settlement,
    };
  } finally {
    channel.close();
  }
}

export async function acquireDarwinBootstrapTools(
  prepared,
  persist,
  options = {},
) {
  const fs = options.fs ?? filesystem,
    save = (phase, details) =>
      persist({
        purpose: "experiment",
        phase: "tool-acquisition-" + phase,
        ...details,
      }),
    admit = async () =>
      requireDarwin(
        !options.signal?.aborted &&
          !(await fs.readdir(prepared.directory)).some((name) =>
            name.startsWith("darwin-recovery-"),
          ),
      );
  await verifyDarwinBootstrapSeed(prepared, fs);
  await admit();
  await save("possible", { seed: prepared.bootstrapSeed });
  await admit();
  const channel = await (options.bootstrapTransport ?? transport)(
    prepared,
    "--bootstrap-tools",
  );
  let owner, primary;
  try {
    const announced = await channel.receive();
    observationObject(announced, ["owner"]);
    owner = root(announced.owner);
    await save("owner", { owner, seed: prepared.bootstrapSeed });
    await admit();
    await channel.send("P\n");
    const result = await channel.receive();
    observationObject(result, ["published"]);
    requireDarwin(result.published === true);
    await admit();
    const exit = await channel.completion;
    requireDarwin(exit.code === 0 && exit.signal === null);
    const original = await readDarwinBootstrapTools(prepared, options);
    requireDarwin(sameDarwinIdentity(original.owner, owner));
    await save("retired", original);
    return original;
  } catch (cause) {
    primary = cause;
    throw cause;
  } finally {
    channel.close();
    if (primary) {
      try {
        await channel.completion.catch(() => {});
        const original = await readDarwinBootstrapTools(prepared, {
          ...options,
          signal: undefined,
          allowIncomplete: true,
        });
        if (owner) requireDarwin(sameDarwinIdentity(original.owner, owner));
        await save("retired", original);
      } catch (cause) {
        nativeException("darwin-bootstrap-tools-cleanup", cause);
      }
    }
  }
}
