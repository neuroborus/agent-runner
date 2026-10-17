import assert from "node:assert/strict";
import { win32 as path } from "node:path";
import { observationDigest } from "../index.js";
import { buildWindowsPolicy } from "./policy.js";
import { effectiveFixture } from "./effective.fixture.js";
import { expectedAces } from "./effective-protocol.js";
import { encode, decode } from "./custody-protocol.js";
import { digest } from "./protocol.js";

/** Raw filesystem/process/pipe model. It supplies native reads, not owner
 * callbacks, approval decisions or real Windows evidence. */
export function installAccessNativeFixture(f, input) {
  const model = {
      members: [],
      frames: [],
      output: [],
      fileRoots: [],
      lanes: new Map(),
      helpers: new Map(),
      events: [],
      xml: new Map(),
      barrier: 0,
      streamed: 0,
      streamBytes: 0,
      bytes: Buffer.alloc(0),
      policy: false,
      registry: false,
      audit: false,
      retired: false,
    },
    hash = "a".repeat(64),
    system = "S-1-5-18",
    time = 134116992000000000n,
    account = () => f.accounts.get(input.request.custody),
    plan = () =>
      buildWindowsPolicy({
        ...input,
        accountSid: account().accountSid,
        request: { ...input.request, restrictingSid: account().restrictingSid },
      }),
    job = (members, limit = 32) => ({
      daclSha256: hash,
      limitFlags: 0x2008,
      processLimit: limit,
      uiRestrictions: 255,
      members: members.filter((member) => !f.actors.get(member.pid).retired),
    }),
    frame = (value) => ({
      hex: Buffer.from(JSON.stringify(value) + "\n").toString("hex"),
    }),
    security = (descriptor) => ({
      ownerSid: system,
      protectedDacl: true,
      daclSha256: hash,
      descriptorSha256: hash,
      aces: model.policy
        ? expectedAces(descriptor)
        : [{ type: 0, flags: 0, mask: 0x1f01ff, sid: system }],
      sacl: [
        ...(model.policy &&
        ["edit", "workspace", "private-tree"].includes(descriptor.grant)
          ? [{ type: 17, flags: 3, mask: 1, sid: "S-1-16-4096" }]
          : []),
        ...(model.audit
          ? [{ type: 2, flags: 192, mask: 0x1f01ff, sid: account().accountSid }]
          : []),
      ],
    }),
    data = (slot) => model.entries[slot],
    descriptors = () =>
      plan().manifest.objects.filter(({ name }) => name !== "registry"),
    index = (name) =>
      model.slots[descriptors().findIndex((entry) => entry.name === name)],
    readFile = (slot, contents = false) => {
      const entry = data(slot),
        bytes = f.files.get(entry.path);
      return {
        identity: f.rawFileId(entry.path),
        bytes: bytes.length,
        sha256: digest(bytes),
        daclSha256: hash,
        ...(contents ? { hex: bytes.toString("hex") } : {}),
      };
    },
    token = () => account().token,
    member = (sid = account().accountSid) => {
      const identity = { ...f.rawActor(), userSid: sid },
        state = f.actors.get(identity.pid);
      Object.assign(state, {
        identity,
        tokenId: token().tokenId,
        authenticationId: token().authenticationId,
        integritySid: "S-1-16-4096",
        restricting: sid === account().accountSid ? token().restrictedSids : [],
        privileges: [],
      });
      return identity;
    },
    masks = {
      system: 0,
      traverse: 0x120020,
      "read-tree": 0x1200a9,
      workspace: 0x1200af,
      read: 0x120089,
      edit: 0x13019f,
      execute: 0x1200a9,
    },
    access = (descriptor) => ({
      granted: model.policy ? masks[descriptor.grant] : 0,
      micDenied: 0,
      subjectLevel: 4096,
      objectLevel: ["edit", "workspace", "private-tree"].includes(
        descriptor.grant,
      )
        ? 4096
        : 8192,
      label: 1,
      tokenId: token().tokenId,
    });
  const filters = () => {
    const fixture = effectiveFixture(),
      approved = plan();
    return fixture.filters.map((filter, i) => ({
      ...filter,
      key: approved.manifest.filters[i].key,
      providerKey: approved.manifest.providerKey,
      sublayerKey: approved.manifest.sublayerKey,
      conditions: filter.conditions.map((condition) => ({
        ...condition,
        ...(condition.field === "principal"
          ? {
              value: [
                { type: 0, flags: 0, mask: 1, sid: account().accountSid },
                { type: 0, flags: 0, mask: 1, sid: account().restrictingSid },
              ],
            }
          : {}),
      })),
    }));
  };
  const wfp = (kind, key) => {
    const fixture = effectiveFixture(),
      approved = plan();
    if (kind === "filter") return filters().find((entry) => entry.key === key);
    return {
      ...(kind === "provider"
        ? { flags: 1, providerData: "", serviceNameHex: null }
        : {
            providerKey: approved.manifest.providerKey,
            flags: 1,
            providerData: "",
            weight: 65535,
          }),
      key,
      security: structuredClone(fixture.registry.security),
    };
  };
  const registry = () => ({
    nameHex: encode(
      "\\REGISTRY\\MACHINE\\SOFTWARE\\NativeProof\\" + input.request.nonce,
    ),
    children: 0,
    values: 0,
    written: "0000000000000001",
    security: wfp("provider", plan().manifest.providerKey).security,
    access: {
      granted: 0,
      micDenied: 0,
      subjectLevel: 4096,
      objectLevel: 8192,
      label: 1,
      tokenId: token().tokenId,
    },
  });
  const socket = (identity, family, protocol, port, pin, remote = null) => ({
    identity,
    family,
    protocol,
    localAddress: family === "v4" ? "127.0.0.1" : "::1",
    localPort: port,
    socketIdentitySha256: digest(pin),
    remote,
  });
  const sockets = new Map();
  const holdSocket = (actual) => {
    const id = String(sockets.size + 1);
    sockets.set(id, actual);
    return {
      identity: actual.identity,
      handle: id,
      hex: Buffer.from(id).toString("hex"),
    };
  };
  const nativeFields = (kind, fields) => ({
    kind,
    fields: Object.entries(fields).map(([name, value]) => ({
      nameHex: encode(name),
      hex: encode(String(value)),
    })),
  });
  const event = (fields) => {
    const id = model.events.length + 1,
      milliseconds = model.barrier + 0.5,
      bytes = Buffer.from("event-" + id + "\0", "utf16le"),
      actual = nativeFields("event", {
        Provider: "Microsoft-Windows-Security-Auditing",
        EventID: fields.EventID,
        Version: 1,
        Keywords:
          fields.EventID === 4656 || fields.EventID === 5157
            ? "0x8010000000000000"
            : "0x8020000000000000",
        Channel: "Security",
        EventRecordID: id,
        TimeCreated:
          "2026-01-01T00:00:00." +
          String(Math.round(milliseconds * 1000)).padStart(6, "0") +
          "Z",
        ...fields,
      });
    model.events.push(bytes);
    model.xml.set(bytes.toString("hex"), actual);
  };
  const networkEvent = (actual, remote, action, connect) => {
    const approved = plan(),
      tuple = {
        protocol: actual.protocol,
        localAddress: actual.localAddress,
        localPort: actual.localPort,
        remoteAddress: remote.localAddress,
        remotePort: remote.localPort,
      },
      filter = approved.manifest.filters.find(
        (entry) =>
          entry.action === action &&
          entry.layer.endsWith(actual.family.toUpperCase()) &&
          entry.layer.includes("CONNECT") === connect &&
          (entry.principal === null ||
            entry.principal === actual.identity.userSid) &&
          Object.entries(entry.conditions).every(
            ([key, value]) => tuple[key] === value,
          ),
      );
    assert.ok(filter);
    event({
      EventID: action === "BLOCK" ? 5157 : 5156,
      ProcessID:
        actual.identity.pid +
        (action === "BLOCK" && f.accessDamage === "unjoined-drop" ? 1 : 0),
      FilterRTID: approved.manifest.filters.indexOf(filter) + 1,
      Protocol: actual.protocol === "tcp" ? 6 : 17,
      SourceAddress: connect ? actual.localAddress : remote.localAddress,
      DestAddress: connect ? remote.localAddress : actual.localAddress,
      SourcePort: connect ? actual.localPort : remote.localPort,
      DestPort: connect ? remote.localPort : actual.localPort,
      Direction: connect ? "%%14593" : "%%14592",
    });
  };
  const append = (bytes) => {
    model.bytes = Buffer.concat([model.bytes, bytes]);
  };
  const word = (value) => {
    const bytes = Buffer.alloc(4);
    bytes.writeUInt32LE(value);
    return bytes;
  };
  const streamEvents = () => {
    while (model.streamed < model.events.length) {
      const bytes = model.events[model.streamed++];
      model.streamBytes += bytes.length;
      append(Buffer.concat([word(bytes.length), bytes]));
    }
  };
  const attempt = () => {
    const { operation, args } = model.pending,
      payload = model.members[0],
      nonce = input.request.nonce;
    if (operation === "pair") {
      const i = Number(args[0]),
        endpoint = input.endpoints[i],
        client = socket(
          payload,
          endpoint.family,
          endpoint.protocol,
          endpoint.clientPort,
          "reservation-" + i * 2,
        ),
        server = socket(
          model.peers.privatePeer,
          endpoint.family,
          endpoint.protocol,
          endpoint.serverPort,
          "server-" + i,
        );
      model.pair = { client, server };
      networkEvent(client, server, "PERMIT", true);
      networkEvent(server, client, "PERMIT", false);
      if (endpoint.protocol === "udp") {
        networkEvent(server, client, "PERMIT", true);
        networkEvent(client, server, "PERMIT", false);
      }
      model.output.push({
        nonce,
        operation,
        phase: "attempted",
        index: i,
        allowed: true,
        nativeCode: 0,
        bytes: nonce,
        echo: nonce,
      });
      return;
    }
    if (operation === "network") {
      const endpoint = model.control.endpoint,
        actor = sockets.get(model.pending.socket.handle);
      networkEvent(
        actor,
        {
          identity: endpoint.identity,
          localAddress: endpoint.address,
          localPort: endpoint.port,
        },
        "BLOCK",
        true,
      );
      model.output.push({
        nonce,
        operation,
        phase: "initiated",
        nativeCode: actor.protocol === "tcp" ? 10035 : 0,
      });
      return;
    }
    const owned = args[0] === input.request.workspace + "\\owned.txt",
      allowed =
        operation === "read" || (owned && input.profile !== "read-only"),
      code = operation === "com" || operation === "wmi" ? 0x80070005 : 5;
    if (["read", "write", "delete", "replace", "rename"].includes(operation)) {
      assert.equal(
        model.fileRoots.length,
        2,
        "File attempts need both held reduced traversal roots",
      );
      event({
        EventID: allowed ? 4663 : 4656,
        ProcessId: payload.pid,
        SubjectUserSid: account().accountSid,
        ObjectType: "File",
        ObjectName: args[0],
        AccessMask:
          !allowed && f.accessDamage === "unrelated-file-denial"
            ? 0x20000
            : operation === "read"
              ? 1
              : operation === "delete" || operation === "rename"
                ? 0x10000
                : operation === "replace"
                  ? 0x10002
                  : 2,
      });
      if (owned && operation === "write" && allowed)
        f.files.set(args[0], Buffer.from(nonce + "-owned-edit"));
    }
    model.output.push({
      nonce,
      operation,
      phase: "attempted",
      allowed,
      nativeCode: allowed ? 0 : code,
    });
  };
  f.accessNative = async (operation, args, scope, declaration) => {
    if (operation === "case-file") {
      const entry = scope.entries[Number(args[0])];
      f.files.set(entry.path, Buffer.from(args[3], "hex"));
      return f.objectRead(entry);
    }
    if (!account()) return;
    if (operation === "access-inventory") {
      model.source = scope.serving;
      model.entries = scope.entries;
      model.slots = args.map(Number);
      return { bound: true };
    }
    if (!model.entries) return;
    if (operation === "ownership-launch") {
      assert.deepEqual(args.slice(1).map(decode), [
        "suite",
        input.request.nonce,
      ]);
      model.launcher = f.rawActor();
      model.owner = f.rawActor();
      model.frames.push({
        nonce: input.request.nonce,
        phase: "helper",
        helper: model.launcher,
        payload: null,
        accountSid: null,
      });
      return { helper: model.launcher, owner: model.owner };
    }
    if (operation === "ownership-control") return frame(model.frames.shift());
    if (operation === "ownership-output") return frame(model.output.shift());
    if (operation === "ownership-send") {
      const command = Buffer.from(args[0], "hex").toString();
      if (command === "P")
        model.frames.push({
          nonce: input.request.nonce,
          phase: "setup",
          helper: model.launcher,
          payload: null,
          accountSid: account().accountSid,
        });
      else if (command.startsWith("C")) {
        model.members.push(member());
        model.frames.push({
          nonce: input.request.nonce,
          phase: "ready",
          helper: model.launcher,
          payload: model.members[0],
          accountSid: account().accountSid,
        });
      } else if (command === "R" || command === "D") {
      } else if (command === "A") attempt();
      else {
        const [operation, ...args] = command.trim().split(" ").map(decode);
        model.pending = { operation, args };
        if (operation === "file-root") {
          const index = Number(args[0]);
          assert.equal(args[1], model.fileRoots[index]);
          assert.equal(args[2], data(index + 1).path);
          model.output.push({
            nonce: input.request.nonce,
            operation,
            phase: "retained",
            index,
            handle:
              index === 1 && f.accessDamage === "root-interruption"
                ? "9999"
                : model.fileRoots[index],
          });
        } else if (operation === "socket")
          model.output.push({
            nonce: input.request.nonce,
            operation,
            phase: "retained",
            index: Number(args[0]),
            handle: String(Number(args[0]) + 1),
          });
        else if (operation === "network") {
          const actual = socket(
            model.members[0],
            args[1],
            args[2],
            43000,
            "attempt-" + model.control.id,
          );
          actual.localAddress = args[6];
          model.pending.socket = holdSocket(actual);
          model.output.push({
            nonce: input.request.nonce,
            operation,
            phase: "ready",
            ...model.pending.socket,
          });
        } else
          model.output.push({
            nonce: input.request.nonce,
            operation,
            phase: "ready",
          });
      }
      return { sent: true };
    }
    if (operation === "access-policy-begin") return { possible: true };
    if (operation === "access-policy-installed") {
      model.registry = true;
      f.files.set(
        input.request.custody + "\\policy",
        Buffer.from(args[0], "hex"),
      );
      return { installed: true };
    }
    if (operation === "ownership-receipt") {
      const file = input.request.custody + "\\ownership-" + args[0] + ".json";
      if (args[2]) {
        assert.ok(!f.files.has(file));
        f.files.set(file, Buffer.from(args[2], "hex"));
      }
      return { hex: f.files.get(file).toString("hex") };
    }
    if (operation === "verify-receipt")
      return {
        hex: f.files
          .get(input.request.custody + "\\ownership-" + args[1] + ".json")
          .toString("hex"),
      };
    if (operation === "ownership-retain") return { retained: true };
    if (operation === "ownership-witness")
      return {
        settled: true,
        sourceVerified: true,
        sdkExportsVerified: true,
        creatorAccessDenied: true,
        noForeignHandles: true,
        accountSid: account().accountSid,
        restrictingSid: account().restrictingSid,
        contextSha256: account().contextSha256,
        jobObjectSha256: hash,
        payloadSuspended: true,
        explicitHandles: true,
        creationTimeJob: true,
        payloadImageSha256: input.request.executable.sha256,
        launcherSignaled: model.retired,
        ownerSignaled: model.retired,
        ownerJobEmpty: model.retired,
        enumeration: {
          processes: model.members.map((identity) => ({
            identity,
            signaled: f.actors.get(identity.pid).retired,
          })),
        },
      };
    if (operation === "process-open") {
      const value = f.actors.get(Number(args[0]));
      const slot = scope.retained.push(value) - 1;
      return { slot, observation: value };
    }
    if (operation === "process") return scope.retained[Number(args[0])];
    if (operation === "effective-token") return token();
    if (operation === "verifier") return f.actors.get(Number(args[0])).identity;
    if (operation === "job-open")
      return { slot: 0, observation: job(model.members) };
    if (operation === "job") return job(model.members);
    if (operation === "access-state" || operation === "access-peer-state")
      return { hex: "01" };
    if (operation === "verify-access")
      return {
        accountSid: account().accountSid,
        restrictingSid: account().restrictingSid,
        contextSha256: account().contextSha256,
        bfeRunning: true,
        token: token(),
        creator: model.source,
        creationSealed: model.retired,
        observerAbsent: !model.lanes.has(1),
        fileRoots: model.retired
          ? []
          : model.fileRoots.map((_, i) => ({
              index: i + 1,
              identity: f.rawFileId(
                data(f.accessDamage === "substituted-root" ? 3 : i + 1).path,
              ),
              accessMask:
                f.accessDamage === "overpowered-root" ? 0x1000a1 : 0x1000a0,
            })),
        members: model.members.map((identity) => ({
          identity,
          signaled: f.actors.get(identity.pid).retired,
          inJob: true,
          token: token(),
        })),
        job: job(model.members),
        objects: descriptors().map((descriptor, i) => ({
          index: model.slots[i],
          identity: f.rawFileId(descriptor.path),
          foreignWritableHandles: 0,
          parents: [f.rawFileId(path.dirname(descriptor.path))],
          security: security(descriptor),
        })),
        endpoints: account().endpoints,
        reservations: Array.from({ length: 8 }, (_, i) => ({
          identitySha256: digest("reservation-" + i),
          payloadVerified: model.members.length > 0,
        })),
        registryPresent: model.registry,
        registry: model.registry
          ? (({ access: _, ...value }) => value)(registry())
          : null,
        flows:
          model.retired && f.accessDamage === "surviving-flow"
            ? [
                {
                  pid: model.source.pid,
                  family: "v4",
                  protocol: "tcp",
                  state: 5,
                  localPort: 41000,
                  remotePort: 41001,
                },
              ]
            : [],
        ownedWfp: {
          provider: model.policy,
          sublayer: model.policy,
          filters: Array(52).fill(model.policy),
          observations: {
            provider: model.policy
              ? wfp("provider", plan().manifest.providerKey)
              : null,
            sublayer: model.policy
              ? wfp("sublayer", plan().manifest.sublayerKey)
              : null,
            filters: model.policy
              ? filters().slice(
                  0,
                  f.accessDamage === "incomplete-policy" ? 51 : 52,
                )
              : Array(52).fill(null),
          },
        },
      };
    if (operation === "acl") {
      const descriptor = descriptors()[model.slots.indexOf(Number(args[1]))];
      return {
        object: f.objectRead(data(Number(args[1]))),
        security: security(descriptor),
        access: access(descriptor),
      };
    }
    if (operation === "registry") return registry();
    if (operation === "file") return readFile(Number(args[0]));
    if (operation === "tree") return [];
    if (operation === "wfp-inventory")
      return model.policy ? plan().manifest.filters.map(({ key }) => key) : [];
    if (operation === "wfp")
      return wfp(["provider", "sublayer", "filter"][Number(args[0])], args[1]);
    if (operation === "wfp-global") {
      const fixture = effectiveFixture(),
        i = plan().manifest.filters.findIndex(({ key }) => key === args[0]),
        actual = await fixture.reader.wfpGlobal(fixture.filters[i].key);
      Object.assign(actual, {
        key: args[0],
        providerKey: plan().manifest.providerKey,
        sublayer: plan().manifest.sublayerKey,
        sublayerProviderKey: plan().manifest.providerKey,
      });
      return actual;
    }
    if (operation === "helper-start") {
      const kind = args[0],
        nativeArgs = args
          .slice(3, 3 + Number(args[2]))
          .map((arg) => Buffer.from(arg, "hex").toString("utf16le")),
        lane = kind === "observer" ? 1 : 0,
        helper = f.rawActor(),
        helperJob = job([helper], 1),
        count = Number(args[3 + Number(args[2])]);
      const slots = args
        .slice(4 + Number(args[2]), 4 + Number(args[2]) + count)
        .map(Number);
      const value = {
        kind,
        helper,
        operation: nativeArgs[4],
        job: helperJob,
        slots,
        frames:
          kind === "policy"
            ? [
                {
                  nonce: input.request.nonce,
                  phase: "before-write",
                  pid: helper.pid,
                  filters: 0,
                },
              ]
            : [],
      };
      model.lanes.set(lane, value);
      model.helpers.set(helper.pid, value);
      f.rawJobs.set(helper.pid, [helper]);
      f.rawImages.set(helper.pid, data(Number(args[1])).path);
      return {
        helper,
        processDaclSha256: f.actors.get(helper.pid).processDaclSha256,
        threadDaclSha256: hash,
        inheritedHandleCount: count + 2,
        job: helperJob,
      };
    }
    const helperByPid = (pid) => model.helpers.get(pid);
    if (operation === "verify-transfer" || operation === "verify-job") {
      const identity = scope.retained[Number(args[0])].identity,
        helper = helperByPid(identity.pid);
      if (helper)
        return operation === "verify-job"
          ? job([identity], 1)
          : {
              threadDaclSha256: hash,
              creatorDefaultDaclSha256: hash,
              pipeDaclSha256: [hash, hash],
              job: job([identity], 1),
              objects: [
                null,
                null,
                ...helper.slots.map((slot) => f.rawFileId(data(slot).path)),
              ],
              inheritedHandleCount: helper.slots.length + 2,
            };
    }
    if (operation === "helper-release") return { released: true };
    if (operation === "helper-read")
      return frame(model.lanes.get(Number(args[0])).frames.shift());
    if (operation === "helper-send") {
      const lane = model.lanes.get(Number(args[0])),
        command = Buffer.from(args[1], "hex").toString();
      if (lane.kind === "policy") {
        if (command === "I" || command === "D") {
          model.policy =
            command === "I" && f.accessDamage !== "policy-interruption";
          if (model.policy) model.registry = true;
          lane.frames.push({
            nonce: input.request.nonce,
            phase: command === "I" ? "installed" : "removed",
            pid: lane.helper.pid,
            filters: f.accessDamage === "policy-interruption" ? 0 : 52,
          });
        } else if (command === "V") {
          lane.frames.push({
            nonce: input.request.nonce,
            phase: "settled",
            pid: lane.helper.pid,
          });
          f.actors.get(lane.helper.pid).retired = true;
        }
      } else if (command === "A") append(word(0));
      else if (command === "B") {
        if (f.accessDamage === "audit-clear" && !model.events.length)
          event({ EventID: 1102 });
        streamEvents();
        const bytes = Buffer.alloc(20);
        bytes.writeUInt32LE(0xfffffffe);
        bytes.writeUInt32LE(++model.barrier, 4);
        bytes.writeBigUInt64LE(time + BigInt(model.barrier) * 10000n, 8);
        bytes.writeUInt32LE(model.streamed, 16);
        append(bytes);
      } else if (command === "S") {
        assert.ok(model.retired);
        streamEvents();
        const bookmark = Buffer.from("bookmark\0", "utf16le");
        model.xml.set(
          bookmark.toString("hex"),
          nativeFields("bookmark", {
            Channel: "Security",
            IsCurrent: "true",
            RecordId: model.streamed,
          }),
        );
        append(
          Buffer.concat([
            word(0xffffffff),
            word(model.streamBytes),
            word(model.streamed),
            word(bookmark.length),
            bookmark,
          ]),
        );
        f.actors.get(lane.helper.pid).retired = true;
      }
      return { sent: true };
    }
    if (operation === "helper-bytes") {
      const bytes = model.bytes.subarray(0, Number(args[1]));
      assert.ok(bytes.length);
      model.bytes = model.bytes.subarray(bytes.length);
      return { hex: bytes.toString("hex") };
    }
    if (operation === "helper-close-input") return { closed: true };
    if (operation === "helper-stop") {
      const lane = model.lanes.get(Number(args[0]));
      f.actors.get(lane.helper.pid).retired = true;
      lane.exitCode = 126;
      model.bytes = Buffer.alloc(0);
      return { stopped: true, drained: true };
    }
    if (operation === "helper-finish") {
      const lane = model.lanes.get(Number(args[0]));
      model.lanes.delete(Number(args[0]));
      return {
        retired: true,
        members: 0,
        drained: true,
        exitCode: lane.exitCode ?? 0,
      };
    }
    if (operation === "xml") return model.xml.get(args[0]);
    const categories = [
      "0cce921d-69ae-11d9-bed3-505054503030",
      "0cce9225-69ae-11d9-bed3-505054503030",
      "0cce9226-69ae-11d9-bed3-505054503030",
    ];
    if (operation === "audit-snapshot")
      return {
        sid: account().accountSid,
        systemSha256: hash,
        system: categories.map((key) => ({ key, flags: 0 })),
        principal: model.audit
          ? categories.map((key) => ({ key, flags: 5 }))
          : null,
      };
    if (operation === "audit-install") {
      model.audit = true;
      return {
        installed: f.accessDamage !== "audit-interruption",
        objects: model.slots.length,
      };
    }
    if (operation === "audit-restore") {
      assert.ok(model.retired && !model.lanes.has(1));
      model.audit = false;
      return { restored: true };
    }
    if (operation === "access-controls") return { ready: true };
    if (operation === "access-transfer-root") {
      const index = Number(args[0]);
      assert.equal(index, model.fileRoots.length);
      model.fileRoots.push(String(9000 + index));
      return { handle: model.fileRoots[index] };
    }
    if (operation === "access-transfer-socket") return { hex: "01" };
    if (operation === "access-register-socket") return { registered: true };
    if (operation === "access-peers-park") {
      model.peers = {
        privatePeer: member(),
        otherPeer: member("S-1-5-21-8-9-10-1001"),
      };
      model.members.push(model.peers.privatePeer);
      return model.peers;
    }
    if (operation === "verify-access-peer-policy")
      return {
        parked: true,
        imageSha256: input.request.executable.sha256,
        signatureSha256: input.request.executable.signatureSha256,
      };
    if (operation === "access-peers") return model.peers;
    if (operation === "access-reservation") {
      const i = Number(args[0]),
        endpoint = input.endpoints[Math.floor(i / 2)],
        identity = i % 2 ? model.peers.privatePeer : model.members[0],
        actual = socket(
          identity,
          endpoint.family,
          endpoint.protocol,
          i % 2 ? endpoint.serverPort : endpoint.clientPort,
          "reservation-" + i,
          model.pair &&
            i === Number(model.pending.args[0]) * 2 &&
            endpoint.protocol === "tcp"
            ? {
                address: endpoint.family === "v4" ? "127.0.0.1" : "::1",
                port: endpoint.serverPort,
              }
            : null,
        );
      return holdSocket(actual);
    }
    if (operation === "access-peer-result") {
      const actual = model.pair.server,
        client = model.pair.client;
      if (actual.protocol === "tcp")
        actual.remote = {
          address: client.localAddress,
          port: client.localPort,
        };
      return frame({
        nonce: input.request.nonce,
        operation: "serve",
        phase: "served",
        index: Number(args[0]) * 2 + 1,
        bytes: input.request.nonce,
        echo: input.request.nonce,
        ...holdSocket(actual),
      });
    }
    if (operation === "verify-socket")
      return sockets.get(Buffer.from(args[3], "hex").toString());
    if (operation === "access-control") {
      model.controlId = args[0];
      return { hex: "01" };
    }
    if (operation === "verify-access-control") {
      const id = args[2],
        descriptor = plan().manifest.objects.find(
          ({ name }) =>
            name ===
            {
              "metadata-write": "metadata",
              "pointer-write": "pointer",
              "pointer-delete": "pointer",
              "pointer-replace": "pointer",
              "parent-delete": "workspace",
              "parent-replace": "workspace",
              custody: "custody",
              checkout: "checkout",
              configuration: "configuration",
              credentials: "credentials",
              registry: "registry",
              "outside-write": "outside",
            }[id],
        );
      if (f.accessDamage === "missing-control")
        throw new Error("Missing independent native control");
      let endpoint = null;
      if (/-v[46]-(tcp|udp)$/u.test(id)) {
        const family = id.includes("-v4-") ? "v4" : "v6",
          protocol = id.endsWith("-tcp") ? "tcp" : "udp",
          i = input.endpoints.findIndex(
            (entry) => entry.family === family && entry.protocol === protocol,
          ),
          address = id.startsWith("host-network-")
            ? family === "v4"
              ? "192.0.2.8"
              : "2001:db8::8"
            : family === "v4"
              ? "127.0.0.1"
              : "::1";
        endpoint = {
          family,
          protocol,
          address,
          bindAddress: id.startsWith("wildcard-")
            ? family === "v4"
              ? "0.0.0.0"
              : "::"
            : address,
          port: id.startsWith("foreign-")
            ? input.endpoints[i].serverPort
            : 42000 + i,
          socketIdentitySha256: digest("control-" + id),
          identity: id.startsWith("foreign-")
            ? model.peers.privatePeer
            : id.startsWith("cross-")
              ? model.peers.otherPeer
              : model.source,
        };
      }
      const actual = {
        id,
        nonce: input.request.nonce,
        controller: model.source,
        kind: endpoint
          ? 9
          : descriptor
            ? descriptor.name === "registry"
              ? 2
              : 1
            : 3,
        denialCode:
          descriptor || endpoint
            ? 0
            : id === "com" || id === "wmi"
              ? 0x80070005
              : 5,
        targetHex: encode(descriptor ? descriptor.path : "private-" + id),
        targetIdentitySha256: descriptor
          ? descriptor.name === "registry"
            ? ""
            : digest(f.rawFileId(descriptor.path))
          : digest("control-" + id),
        endpoint,
      };
      model.control = actual;
      return actual;
    }
    if (operation === "access-foreign") {
      const endpoint = model.control.endpoint,
        actual = socket(
          model.source,
          endpoint.family,
          endpoint.protocol,
          43001,
          "foreign-" + args[0],
        ),
        destination = socket(
          endpoint.identity,
          endpoint.family,
          endpoint.protocol,
          endpoint.port,
          "control-" + args[0],
        );
      networkEvent(actual, destination, "BLOCK", true);
      return {
        ...holdSocket(actual),
        nativeCode: endpoint.protocol === "tcp" ? 10035 : 0,
      };
    }
    if (operation === "access-foreign-close") return { closed: true };
    if (operation === "access-fault-arm" || operation === "access-fault-fire") {
      const identity =
        decode(args[0]) === "owner-loss" ? model.owner : model.launcher;
      if (operation.endsWith("fire")) f.actors.get(identity.pid).retired = true;
      return { identity, signaled: operation.endsWith("fire") };
    }
    if (operation === "access-controls-stop") {
      if (model.peers) f.actors.get(model.peers.otherPeer.pid).retired = true;
      return { fenced: true };
    }
    if (operation === "ownership-stop") {
      model.retired = true;
      for (const identity of [...model.members, model.owner, model.launcher])
        f.actors.get(identity.pid).retired = true;
      return { creationSealed: true, helpersSettled: true };
    }
    if (operation === "verify-access-peer-retired")
      return {
        retired: true,
        accountAbsent: true,
        rightsAbsent: true,
        contextSha256: account().contextSha256,
      };
    if (operation === "access-controls-drain") return { drained: true };
    if (operation === "access-policy-restore") {
      assert.ok(!model.audit && model.retired);
      model.policy = model.registry = false;
      return { restored: true };
    }
    if (operation === "access-jobs-close") return { closed: true };
    if (operation === "ownership-account-retire") {
      assert.ok(!model.policy && !model.audit);
      account().retired = true;
      return { retired: true };
    }
  };
  return model;
}
