import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { deflateSync } from "node:zlib";
import { win32 as path } from "node:path";
import { observationDigest, nativePolicyTemplateDigest } from "../index.js";
import { digest, inspectWindowsPe } from "./protocol.js";
import { encode, decode } from "./custody-protocol.js";

const sha1 = (bytes) => createHash("sha1").update(bytes).digest("hex");

/** Synthetic bytes and native IPC only: no owner callbacks or real native proof. */
export function operationAssets(f, input, entries, id, binding) {
  const assets = [],
    add = (kind, file, bytes) => {
      const index = entries.length;
      entries.push({
        kind,
        path: file,
        sha256: bytes ? digest(bytes) : null,
        signatureSha256: ["helper", "image"].includes(kind)
          ? inspectWindowsPe(bytes).signatureSha256
          : null,
      });
      let source = null;
      if (bytes) {
        source = entries.length;
        const name = path.join(
          "C:\\Fixture\\sealed",
          "operation-" +
            source +
            (kind === "helper" || kind === "image" ? ".exe" : ".data"),
        );
        const sourceKind = ["helper", "image"].includes(kind) ? kind : "data";
        entries.push({ ...entries[index], kind: sourceKind, path: name });
        f.files.set(name, bytes);
      }
      assets.push({ index, source });
      return index;
    };
  const root = path.dirname(input.request.custody);
  const outside = add("directory", root + "\\outside");
  add("data", root + "\\outside\\sentinel", Buffer.from("unchanged sentinel"));
  if (id.startsWith("files.")) {
    const files = add("directory", input.request.custody + "\\files");
    const alias = entries.findIndex(
      ({ path }) =>
        path === f.manifest.windowsPreparation.bootstrap.reader.path,
    );
    assert.ok(alias >= 0);
    const foreign = entries.length;
    entries.push({
      kind: "directory",
      path: "D:\\Fixture\\foreign",
      sha256: null,
      signatureSha256: null,
    });
    f.files.set("D:\\Fixture\\foreign", Buffer.from("directory"));
    f.files.set(
      "D:\\Fixture\\foreign\\sentinel",
      Buffer.from("foreign sentinel"),
    );
    return {
      assets,
      slots: {
        base: 2,
        root: files,
        outside,
        alias,
        foreign,
        loader: [5, 6, alias].map((index) => ({ index, imports: [] })),
      },
    };
  }
  if (id.startsWith("git.")) {
    const git = add("image", input.request.storage + "\\git.exe", f.signed);
    const metadata = add("directory", input.request.storage + "\\metadata");
    const hooks = add("directory", input.request.storage + "\\hooks"),
      policyObjects = [metadata, hooks];
    const directory = (name) => {
      const index = add(
        "directory",
        input.request.storage + "\\metadata\\" + name,
      );
      policyObjects.push(index);
      return index;
    };
    directory("objects");
    directory("refs");
    directory("refs\\heads");
    const known = new Set();
    const object = (kind, bytes) => {
      const full = Buffer.concat([
          Buffer.from(kind + " " + bytes.length + "\0"),
          bytes,
        ]),
        hash = sha1(full),
        prefix = hash.slice(0, 2);
      if (!known.has(prefix)) {
        directory("objects\\" + prefix);
        known.add(prefix);
      }
      const index = add(
        "data",
        input.request.storage +
          "\\metadata\\objects\\" +
          prefix +
          "\\" +
          hash.slice(2),
        deflateSync(full),
      );
      policyObjects.push(index);
      return hash;
    };
    const make = (content, parent) => {
      const blob = object("blob", Buffer.from(content));
      const tree = object(
        "tree",
        Buffer.concat([
          Buffer.from("100644 content.txt\0"),
          Buffer.from(blob, "hex"),
        ]),
      );
      const commit = object(
        "commit",
        Buffer.from(
          "tree " +
            tree +
            "\n" +
            (parent ? "parent " + parent + "\n" : "") +
            "author Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\n" +
            (parent
              ? "test(fixture): record owned edit\n"
              : "test(fixture): initialize fixture\n"),
        ),
      );
      return { blob, tree, commit };
    };
    const before = make("initial\n", null),
      after = make("owned edit\n", before.commit);
    // Future commit objects are produced by the fixed Git child, not setup.
    const future = new Map();
    for (const hash of [after.blob, after.tree, after.commit]) {
      const name =
        input.request.storage +
        "\\metadata\\objects\\" +
        hash.slice(0, 2) +
        "\\" +
        hash.slice(2);
      const asset = assets.find(({ index }) => entries[index].path === name);
      future.set(name, f.files.get(entries[asset.source].path));
      assets.splice(assets.indexOf(asset), 1);
      policyObjects.splice(policyObjects.indexOf(asset.index), 1);
      entries[asset.index].path = path.join(
        "C:\\Fixture\\sealed",
        "future-" + asset.index + ".data",
      );
      f.files.set(entries[asset.index].path, future.get(name));
    }
    const indexBytes = (blob) => {
      const bytes = Buffer.alloc(108);
      bytes.write("DIRC");
      bytes.writeUInt32BE(2, 4);
      bytes.writeUInt32BE(1, 8);
      bytes.writeUInt32BE(0o100644, 36);
      Buffer.from(blob, "hex").copy(bytes, 52);
      bytes.writeUInt16BE(11, 72);
      bytes.write("content.txt", 74);
      Buffer.from(sha1(bytes.subarray(0, -20)), "hex").copy(
        bytes,
        bytes.length - 20,
      );
      return bytes;
    };
    for (const [name, data, kind] of [
      [
        "config",
        Buffer.from(
          "[user]\n\tname = Fixture\n\temail = fixture@example.invalid\n",
        ),
        "data",
      ],
      ["HEAD", Buffer.from("ref: refs/heads/proof\n"), "data"],
      ["index", indexBytes(before.blob), "mutable"],
      ["refs\\heads\\proof", Buffer.from(before.commit + "\n"), "mutable"],
    ])
      policyObjects.push(
        add(kind, input.request.storage + "\\metadata\\" + name, data),
      );
    const content = add(
      "mutable",
      input.request.workspace + "\\content.txt",
      Buffer.from("owned edit\n"),
    );
    policyObjects.push(content);
    add(
      "mutable",
      input.request.workspace + "\\.git",
      Buffer.from(
        "gitdir: " +
          input.request.storage.replaceAll("\\", "/") +
          "/metadata\n",
      ),
    );
    const policyHelper = entries.length;
    entries.push({
      kind: "helper",
      path: "C:\\Fixture\\sealed\\git-policy.exe",
      sha256: digest(f.signed),
      signatureSha256: inspectWindowsPe(f.signed).signatureSha256,
    });
    input.git = {
      path: entries[git].path,
      sha256: entries[git].sha256,
      signatureSha256: entries[git].signatureSha256,
    };
    input.metadata = entries[metadata].path;
    input.hooks = entries[hooks].path;
    input.parent = before.commit;
    f.gitCommit = () => {
      for (const [name, bytes] of future) f.files.set(name, bytes);
      f.files.set(input.metadata + "\\index", indexBytes(after.blob));
      f.files.set(
        input.metadata + "\\refs\\heads\\proof",
        Buffer.from(after.commit + "\n"),
      );
    };
    return {
      assets,
      slots: {
        git,
        metadata,
        hooks,
        outside,
        policyHelper,
        policyObjects,
        loader: [5, 6, git, policyHelper].map((index) => ({
          index,
          imports: [],
        })),
      },
    };
  }
  assert.equal(id, "release");
  const json = (file, value) =>
    add(
      "data",
      input.request.storage + "\\" + file + ".json",
      Buffer.from(JSON.stringify(value) + "\n"),
    );
  const sdk = entries.flatMap((entry, index) =>
    entry.kind === "sdk" ? [index] : [],
  );
  const sdkSha256 = observationDigest(
    sdk.map((index) => ({
      path: entries[index].path,
      sha256: entries[index].sha256,
    })),
  );
  const template = json("template", binding.template),
    components = [],
    expected = [];
  for (const name of ["helper", "codex", "claude"]) {
    const index = add(
        "image",
        input.request.storage + "\\" + name + ".exe",
        f.signed,
      ),
      bindings = {};
    for (const key of ["publication", "source", "build", "license", "abi"])
      bindings[key] = json(
        name + "-" + key,
        key === "build"
          ? {
              componentSha256: entries[index].sha256,
              contextSha256: observationDigest(binding.context),
              osBuild: "10.0.26100",
              sdkBuild: "1.0",
              sdkSha256,
              linkerMajor: 0,
              linkerMinor: 0,
              timestamp: 0,
            }
          : { componentSha256: entries[index].sha256, purpose: key },
      );
    components.push({ id: name, index, loader: [], bindings });
    expected.push({
      id: name,
      role: name === "helper" ? "helper" : "executable",
      sha256: entries[index].sha256,
      format: "pe-x64",
      loader: [],
      bindings: Object.fromEntries(
        Object.entries(bindings).map(([key, slot]) => [
          key,
          entries[slot].sha256,
        ]),
      ),
    });
  }
  const providers = {},
    packages = {};
  for (const name of ["codex", "claude"]) {
    packages[name] = {
      reviewSha256: digest(Buffer.from(name + " review")),
      closureSha256: digest(Buffer.from(name + " closure")),
      members: [name],
    };
    providers[name] = json(name + "-package", packages[name]);
  }
  const authority = json("authority", {
    schemaVersion: 1,
    contextSha256: observationDigest(binding.context),
    image: "windows-2025",
    sdkBuild: "1.0",
    sdkSha256,
    policyTemplates: [template],
    privileges: ["system"],
  });
  f.releaseManifest = {
    schemaVersion: 2,
    candidateSha: binding.context.candidateSha,
    platform: "win32",
    image: "windows-2025",
    osBuild: "10.0.26100",
    sdkBuild: "1.0",
    policyTemplates: [nativePolicyTemplateDigest(binding.template)],
    privileges: ["system"],
    components: expected,
    providers: packages,
  };
  return { assets, slots: { components, providers, authority, sdk } };
}

export function installOperationNativeFixture(f, input, specification) {
  const model = {
    frames: [],
    subjects: [],
    receipts: new Map(),
    helpers: new Map(),
    workers: [],
    reads: [],
    objects: {},
    sequence: 0,
    closed: [],
    control: null,
    exitCode: 0,
  };
  const hash = digest(Buffer.from("reviewed fixture bytes")),
    slots = specification.slots;
  const member = (image, sid = "S-1-5-18") => {
    const identity = { ...f.rawActor(), userSid: sid },
      state = f.actors.get(identity.pid);
    Object.assign(state, { identity, retired: false });
    f.rawImages.set(identity.pid, image);
    return identity;
  };
  const retire = (identity) => {
    f.actors.get(identity.pid).retired = true;
  };
  const frame = (value) => ({
    hex: Buffer.from(JSON.stringify(value) + "\n").toString("hex"),
  });
  const state = () => ({
    base: input.base,
    root: input.root,
    allocation: model.objects.allocation?.identity ?? null,
    leaf: model.objects.leaf?.identity ?? null,
    temporary: model.objects.temporary?.identity ?? null,
    alias: Boolean(
      model.objects.leaf &&
      model.objects.leaf.identity === model.objects.temporary?.identity,
    ),
  });
  const object = (name, bytes = null, identity) => {
    const file =
      input.request.custody + "\\files\\" + name + "-" + model.sequence++;
    return {
      identity: identity ?? f.rawFileId(file),
      namedIdentity: identity ?? f.rawFileId(file),
      ownerSid: "S-1-5-18",
      systemOnlyDacl: true,
      protectedDacl: true,
      noReparse: true,
      canonicalName: true,
      noShortAlias: true,
      defaultStreamsOnly: true,
      kind: bytes === null ? "directory" : "file",
      caseSensitive: false,
      links: 1,
      bytes,
    };
  };
  const reply = (phase) => {
    model.frames.push({ nonce: input.request.nonce, phase, ...state() });
  };
  const fileCommand = (text) => {
    const [command, allocation, leaf, temporary, bytes] = text
      .trim()
      .split(" ");
    if (command === "start") return;
    if (command === "continue") {
      if (model.control) {
        model.exitCode = 126;
        retire(model.helper);
        return;
      }
      if (model.stage === "prepared") {
        if (model.command === "publish" && model.objects.leaf) {
          model.objects.temporary = null;
          reply("exists");
          model.stage = null;
          return;
        }
        model.objects.leaf = { ...model.objects.temporary };
        if (model.command === "publish") {
          model.objects.leaf.links = model.objects.temporary.links = 2;
          model.stage = "linked";
          reply("linked");
        } else {
          model.objects.temporary = null;
          model.stage = "published";
          reply("published");
        }
      } else if (model.stage === "linked") {
        model.objects.temporary = null;
        model.objects.leaf.links = 1;
        model.stage = "published";
        reply("published");
      } else if (model.stage === "published") {
        model.stage = null;
        reply("complete");
      } else if (model.stage === "removing") {
        model.objects = {};
        model.stage = null;
        reply("removed");
      }
      return;
    }
    if (command === "allocate") {
      model.objects.allocation = object("allocation");
      reply("allocated");
    } else if (command === "publish" || command === "replace") {
      model.command = command;
      model.objects.temporary = object("temporary", bytes === "-" ? "" : bytes);
      model.stage = "prepared";
      reply("prepared");
    } else if (command === "recover") {
      assert.equal(allocation, state().allocation);
      assert.equal(leaf, state().leaf ?? "-");
      assert.equal(temporary, state().temporary ?? "-");
      reply("recovered");
    } else if (command === "cleanup") {
      model.stage = "removing";
      reply("removing");
    } else if (command === "inspect") reply("inspected");
    else if (command === "finish") {
      reply("finished");
      retire(model.helper);
    } else assert.fail("Unexpected file command: " + command);
  };
  const read = (file, contents = false) => {
    const bytes = f.files.get(file);
    assert.ok(bytes, file);
    return {
      identity: f.rawFileId(file),
      bytes: bytes.length,
      sha256: digest(bytes),
      daclSha256: hash,
      ...(contents ? { hex: bytes.toString("hex") } : {}),
    };
  };
  f.accessNative = async (command, args, scope, declaration) => {
    if (declaration?.context.executionId === "build") return;
    const entries = scope.entries,
      account = f.accounts.get(input.request.custody);
    if (command === "verifier") return f.actors.get(Number(args[0])).identity;
    const retainedHelper = model.helpers.get(
      scope.retained[Number(args[0])]?.identity.pid,
    );
    if (command === "verify-transfer" && retainedHelper) {
      const { identity, transfers, kind } = retainedHelper;
      const members = (f.rawJobs.get(identity.pid) ?? []).filter(
        (identity) => !f.actors.get(identity.pid).retired,
      );
      return {
        threadDaclSha256: hash,
        creatorDefaultDaclSha256: hash,
        pipeDaclSha256: [hash, hash],
        job: {
          daclSha256: hash,
          limitFlags: 0x2008,
          processLimit: kind === "git" ? 32 : 1,
          uiRestrictions: 255,
          members,
        },
        objects: [
          null,
          null,
          ...transfers.map((index) => f.rawFileId(model.entries[index].path)),
        ],
        inheritedHandleCount: transfers.length + 2,
      };
    }
    if (command === "verify-sharing")
      return { identity: f.rawFileId(decode(args[0])) };
    if (command === "verify-job" && retainedHelper) {
      const members = (f.rawJobs.get(retainedHelper.identity.pid) ?? []).filter(
        (identity) => !f.actors.get(identity.pid).retired,
      );
      return {
        daclSha256: hash,
        limitFlags: 0x2008,
        processLimit: retainedHelper.kind === "git" ? 32 : 1,
        uiRestrictions: 255,
        members,
      };
    }
    if (command === "case-file") {
      const entry = entries[Number(args[0])];
      assert.ok(!f.files.has(entry.path));
      f.files.set(entry.path, Buffer.from(args[3], "hex"));
      return f.objectRead(entry);
    }
    if (command === "operation-bind") {
      model.entries = entries;
      model.scope = scope;
      input.base = f.rawFileId(input.request.custody);
      if (slots.root !== undefined)
        input.root = f.rawFileId(entries[slots.root].path);
      return { bound: true };
    }
    if (command === "ownership-receipt") {
      if (args[2]) {
        const bytes = Buffer.from(args[2], "hex");
        assert.equal(digest(bytes), args[1]);
        assert.ok(!model.receipts.has(args[0]));
        model.receipts.set(args[0], bytes);
      }
      return { hex: model.receipts.get(args[0]).toString("hex") };
    }
    if (command === "signature") {
      if (f.operationDamage === "signature") return { sha256: hash };
      return {
        sha256: inspectWindowsPe(f.files.get(entries[Number(args[0])].path))
          .signatureSha256,
      };
    }
    if (command === "read")
      return {
        hex: f.files
          .get(entries[Number(args[0])].path)
          .subarray(Number(args[1]), Number(args[1]) + Number(args[2]))
          .toString("hex"),
      };
    if (command === "parents")
      return [f.rawFileId(path.dirname(entries[Number(args[0])].path))];
    if (command === "tree") {
      const root = entries[Number(args[0])].path;
      return [...f.files]
        .filter(
          ([name]) =>
            name.startsWith(root + "\\") &&
            !entries.some(
              (entry) => entry.path === name && entry.kind === "directory",
            ),
        )
        .map(([name]) => ({
          nameHex: encode(name.slice(root.length + 1)),
          file: read(name),
        }))
        .sort((a, b) => a.nameHex.localeCompare(b.nameHex));
    }
    if (command === "barrier")
      return read(
        path.join(entries[Number(args[0])].path, decode(args[1])),
        true,
      );
    if (command === "release-build")
      return { bytes: f.files.get(entries[Number(args[0])].path).length };
    if (command === "release-pe")
      return {
        complete: true,
        dll: false,
        imports:
          f.operationDamage === "dependency"
            ? [{ name: "extra.dll", host: "extra.dll", delay: false }]
            : [],
        linkerMajor: 0,
        linkerMinor: 0,
        timestamp: 0,
      };
    if (command === "release-close") {
      model.closed.push(Number(args[0]));
      return { index: Number(args[0]), closed: true };
    }
    if (command === "operation-closed") return model.closed;
    if (command === "operation-authority")
      return {
        systemOnly: true,
        soleParentAuthority: true,
        noLiveMembers: true,
        sdkAndLoaderVerified: true,
        ntfsSemanticsVerified: true,
      };
    if (command === "operation-fence") {
      model.fenced = true;
      return { fenced: true };
    }
    if (command === "operation-helper-retire") {
      if (model.helper) {
        retire(model.helper);
        model.child && retire(model.child.identity);
      }
      return { helpersSettled: true };
    }
    if (command === "file-workers-retire") {
      model.workers.forEach(retire);
      return { noLiveMembers: true, helpersSettled: true };
    }
    if (command === "operation-retirement") {
      assert.ok(!model.helper || f.actors.get(model.helper.pid).retired);
      return {
        noLiveMembers: true,
        helpersSettled: true,
        admissionsClosed: true,
      };
    }
    if (command === "file-recovery-retirement") {
      const active = [...model.helpers.values()].filter(
        ({ identity }) => !f.actors.get(identity.pid).retired,
      );
      assert.ok(
        active.length <= 1 &&
          active.every(
            ({ identity, kind }) =>
              kind === "file" && identity.userSid === "S-1-5-18",
          ),
      );
      assert.ok(model.workers.every(({ pid }) => f.actors.get(pid).retired));
      return {
        noLiveMembers: true,
        helpersSettled: true,
        admissionsClosed: true,
      };
    }
    if (command === "file-view") {
      return {
        base: object("base", null, input.base),
        root: object("root", null, input.root),
        allocation: model.objects.allocation ?? null,
        leaf: model.objects.leaf ?? null,
        temporary: model.objects.temporary ?? null,
      };
    }
    if (command === "helper-start") {
      if (!["file", "git", "git-policy"].includes(args[0])) return;
      model.kind = args[0];
      model.exitCode = 0;
      model.helper = member(entries[Number(args[1])].path);
      model.frames = [];
      const offset = 3 + Number(args[2]);
      model.transfers = args.slice(offset + 1).map(Number);
      model.helpers.set(model.helper.pid, {
        identity: model.helper,
        kind: model.kind,
        transfers: model.transfers,
      });
      f.rawJobs.set(model.helper.pid, [model.helper]);
      if (model.kind === "file")
        model.frames.push({
          nonce: input.request.nonce,
          phase: "ready",
          base: input.base,
          root: input.root,
          allocation: null,
          leaf: null,
          temporary: null,
          alias: false,
        });
      else if (model.kind === "git-policy")
        model.frames.push({
          nonce: input.request.nonce,
          phase: "before-write",
          objects: slots.policyObjects.length,
        });
      else {
        model.frames.push({ nonce: input.request.nonce, phase: "ready" });
        model.children = ["parent", "branch", "status", "add", "commit"];
      }
      return {
        helper: model.helper,
        processDaclSha256: hash,
        threadDaclSha256: hash,
        inheritedHandleCount:
          model.kind === "file"
            ? 4
            : model.kind === "git-policy"
              ? slots.policyObjects.length + 4
              : 2,
        job: {
          daclSha256: hash,
          limitFlags: 0x2008,
          processLimit: model.kind === "git" ? 32 : 1,
          uiRestrictions: 255,
          members: [model.helper],
        },
        ...(model.kind === "git" ? { creatorDefaultDaclSha256: hash } : {}),
        ...(model.kind === "file" ? { fileRootDeleteSharing: true } : {}),
      };
    }
    if (command === "helper-send" && model.helper) {
      const text = Buffer.from(args[1], "hex").toString();
      if (model.kind === "file") fileCommand(text);
      else if (model.kind === "git-policy") {
        model.frames.push({ nonce: input.request.nonce, phase: "complete" });
        retire(model.helper);
      } else {
        if (model.child) retire(model.child.identity);
        const operation = model.children.shift();
        model.child = operation
          ? {
              nonce: input.request.nonce,
              phase: "child",
              operation,
              suspended: true,
              identity: member(input.git.path),
            }
          : null;
        if (model.child) {
          model.frames.push(model.child);
          f.rawJobs.get(model.helper.pid).push(model.child.identity);
        } else {
          f.gitCommit();
          model.frames.push({ nonce: input.request.nonce, phase: "finished" });
          retire(model.helper);
        }
      }
      return { sent: true };
    }
    if (command === "helper-read" && model.helper) {
      const value = model.frames.shift();
      if (
        f.operationDamage === "git-policy-interruption" &&
        model.kind === "git-policy"
      )
        value.objects++;
      if (
        f.operationDamage === "publisher-interruption" &&
        value.phase === "prepared"
      )
        value.nonce = "f".repeat(32);
      if (f.operationDamage === "finish-nonce" && value.phase === "finished") {
        value.nonce = "f".repeat(32);
        f.operationDamage = null;
      }
      return frame(value);
    }
    if (command === "helper-close-input" && model.helper) {
      if (!f.actors.get(model.helper.pid).retired) {
        retire(model.helper);
        model.exitCode = 126;
      }
      return { closed: true };
    }
    if (command === "helper-finish" && model.helper) {
      if (!f.actors.get(model.helper.pid).retired) retire(model.helper);
      return {
        retired: true,
        members: 0,
        drained: true,
        exitCode: model.exitCode,
      };
    }
    if (command === "process-image") {
      const actor = scope.processSlots[Number(args[0])].identity,
        entry = entries[Number(args[1])];
      return {
        identity: actor,
        sha256: entry.sha256,
        signatureSha256: entry.signatureSha256,
      };
    }
    if (command === "loader") {
      const entry = entries[Number(args[1])];
      return {
        loaded: [
          {
            pathHex: encode(
              f.operationDamage === "loaded-substitution"
                ? "C:\\Fixture\\unapproved.exe"
                : entry.path,
            ),
            identity: f.rawFileId(entry.path),
            sha256: entry.sha256,
            signatureSha256: entry.signatureSha256,
            daclSha256: hash,
            links: 1,
          },
        ],
        imports: [],
        linkerMajor: 0,
        linkerMinor: 0,
        timestamp: 0,
        complete: true,
      };
    }
    if (command === "file-private") {
      const identity = member(entries[slots.alias].path, account.accountSid);
      retire(identity);
      return {
        identity,
        ready: true,
        reachable: true,
        attempted: true,
        allowed: false,
        nativeCode: 5,
        exitCode: 0,
        signal: null,
        settled: true,
        tokenVerified: true,
        jobVerified: true,
      };
    }
    if (command === "file-publishers-start") {
      model.workers = [0, 1, 2].map(() => member(entries[slots.alias].path));
      return {
        ready: true,
        overlapped: true,
        requestsAcknowledged: 3,
        callers: model.workers,
      };
    }
    if (command === "file-publishers-finish") {
      model.workers.forEach(retire);
      return {
        complete: f.operationDamage !== "publisher-interruption",
        settled: true,
        overlapped: true,
        requests: (f.operationDamage === "publisher-interruption"
          ? []
          : model.workers
        ).map((identity, i) => ({
          identity,
          bytesSha256: digest(
            Buffer.from(
              ["006f6c64ff", "006e657700ff", "7365636f6e64"][i],
              "hex",
            ),
          ),
          leaf: model.objects.leaf.identity,
          outcome: i ? "exists" : "complete",
          nativeEventSha256: hash,
        })),
      };
    }
    if (command === "file-reader-start") {
      model.workers = [member(entries[slots.alias].path)];
      model.old = { ...model.objects.leaf };
      return { ready: true, reader: model.workers[0] };
    }
    if (command === "file-reader-read")
      return {
        identity: model.objects.leaf.identity,
        bytes: model.objects.leaf.bytes,
        links: 1,
        code: 0,
      };
    if (command === "file-reader-finish") {
      retire(model.workers[0]);
      return {
        ready: true,
        reader: model.workers[0],
        oldHeld: {
          identity: model.old.identity,
          bytes: model.old.bytes,
          links: 0,
        },
        overlapped: true,
        complete: true,
        settled: true,
        dropped: false,
      };
    }
    if (command === "file-control") {
      const kind = decode(args[0]),
        target =
          kind === "root"
            ? "root"
            : ["parent", "junction", "cross-volume"].includes(kind)
              ? "allocation"
              : "leaf";
      const original =
          target === "root"
            ? object("root", null, input.root)
            : model.objects[target],
        before = {
          identity: original.identity,
          bytesSha256:
            target === "leaf"
              ? digest(Buffer.from(original.bytes, "hex"))
              : hash,
          links: 1,
        };
      const changed = {
        ...before,
        kind: target === "leaf" ? "file" : "directory",
      };
      if (
        ["root", "parent", "junction", "symlink", "cross-volume"].includes(kind)
      )
        changed.identity = f.rawFileId(
          input.request.custody + "\\changed-" + model.sequence++,
        );
      if (["junction", "symlink", "cross-volume"].includes(kind))
        changed.reparse = kind === "cross-volume" ? "junction" : kind;
      if (kind === "case") changed.name = "Value";
      if (kind === "stream") changed.streams = 2;
      if (kind === "hardlink") changed.links = 2;
      if (kind === "short-name") changed.alternateName = "VALUE~1";
      const foreign = {
        identity: "2".repeat(16) + ":" + "3".repeat(32),
        kind: "directory",
        stateSha256: hash,
      };
      if (kind === "cross-volume") changed.targetIdentity = foreign.identity;
      model.control = { kind, before, changed, foreign };
      return { ready: true, applied: changed };
    }
    if (command === "file-control-read") {
      const { kind, before, changed, foreign } = model.control;
      return {
        continued: true,
        exitCode: 126,
        rejected: true,
        attempted: true,
        ready: true,
        reachable: true,
        signal: null,
        nativeDecision:
          "reject-" +
          (["root", "parent"].includes(kind)
            ? "identity"
            : ["junction", "symlink", "cross-volume"].includes(kind)
              ? "reparse"
              : kind),
        before,
        saved: { ...before, links: changed.links },
        applied: changed,
        after: changed,
        othersBeforeSha256: hash,
        othersAfterSha256: hash,
        ...(kind === "cross-volume"
          ? { foreignTarget: { before: foreign, after: { ...foreign } } }
          : {}),
      };
    }
    if (command === "file-control-restore") {
      if (f.operationDamage === "changed-control")
        return {
          ownedOnly: false,
          foreignPreserved: true,
          priorRetirementVerified: true,
        };
      model.control = null;
      return {
        ownedOnly: true,
        foreignPreserved: true,
        priorRetirementVerified: true,
      };
    }
    if (command === "git-policy-read")
      return {
        complete: true,
        privateParents: true,
        hooksEmpty: true,
        noForeignCreators: true,
        noPrincipalFlows: true,
        gitClosureVerified: true,
        soleMetadataAuthority: true,
        privateCreatorDaclVerified: true,
        jobIdentitySha256: hash,
      };
    if (command === "git-policy-install" || command === "git-audit-install")
      return { installed: true };
    if (command === "git-policy-restore")
      return { unchangedInstalled: true, restored: true };
    if (command === "git-child")
      return {
        suspended: true,
        bornInJob: true,
        noForeignHandles: true,
        privateCreatorDaclVerified: true,
        parentsVerified: true,
        jobIdentitySha256: hash,
      };
    if (command === "git-child-retired") return { settled: true };
    if (command === "git-ordinary") {
      const operation = decode(args[1]),
        identity = member(input.git.path, account.accountSid);
      retire(identity);
      const targetIdentitySha256 = observationDigest(input.metadata);
      return {
        identity,
        tokenVerified: true,
        bornInJob: true,
        noBreakaway: true,
        settled: true,
        basePolicyVerified: true,
        closureVerified: true,
        decisionVerified: true,
        auditComplete: f.operationDamage !== "audit-loss",
        auditSha256: hash,
        lossCount: f.operationDamage === "audit-loss" ? 1 : 0,
        jobIdentitySha256: hash,
        code: 0,
        head: input.parent,
        attempted: true,
        allowed: false,
        exitCode: operation.startsWith("git-") ? 1 : 0,
        signal: null,
        nativeCode: 5,
        nativeDecision: "deny-metadata-write",
        beforeSha256: hash,
        afterSha256: hash,
        targetIdentitySha256,
        control: {
          identity: scope.serving,
          ready: true,
          reachable: true,
          readyBeforeAttempt: true,
          settled: true,
          operation,
          nativeCode: 0,
          targetIdentitySha256,
        },
      };
    }
  };
  return model;
}
