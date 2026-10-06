import assert from "node:assert/strict";
import test from "node:test";
import {
  createWindowsEffectiveReaders,
  normalizeWindowsBarrierRead,
  assertWindowsWfpFilterRead,
} from "./index.js";
import {
  effectiveFixture,
  hash,
  fileId,
  candidateSha,
} from "./effective.fixture.js";
import { digest } from "./protocol.js";
import { encode } from "./custody-protocol.js";
import { observationDigest } from "../index.js";

test("Windows effective composition joins independently approved bindings to actual ACL/MIC, registry and WFP reads", async () => {
  const f = effectiveFixture();
  let reads = 0;
  const acl = f.reader.acl;
  f.reader.acl = (...args) => {
    reads++;
    return acl(...args);
  };
  const owner = createWindowsEffectiveReaders(
    f.reader,
    f.context,
    f.verifier,
    f.options,
  );
  assert.equal(reads, 0);
  const snapshot = await owner.policySnapshot(f.input, {
    subject: 0,
    objects: f.objects.map((_, index) => index),
  });
  assert.equal(snapshot.objects.length, f.plan.manifest.objects.length);
  assert.equal(snapshot.wfp.filters.length, 52);
  assert.equal(
    snapshot.objects.find((item) => item.descriptor.name === "owned").rights
      .delete,
    true,
  );
  assert.equal(
    snapshot.objects.find((item) => item.descriptor.name === "workspace").rights
      .deleteChild,
    false,
  );
  assert.ok(reads > f.objects.length);
});
test("Windows expected manifests cannot manufacture native access, MIC, object identities or coverage", async () => {
  for (const change of [
    (f) => {
      delete f.options.binding;
    },
    (f) => {
      f.options.provisioning.bindings[0].value = "S-1-5-21-1-2-3-9";
    },
    (f) => {
      f.objects[3].access.granted |= 0x40000;
    },
    (f) => {
      f.objects[3].access.micDenied = 2;
    },
    (f) => {
      f.objects[3].security.sacl[0].sid = "S-1-16-8192";
    },
    (f) => {
      f.objects[3].object.pathHex = f.objects[4].object.pathHex;
    },
    (f) => {
      f.registry.values = 1;
    },
    (f) => {
      const coverage = f.options.coverage;
      f.options.coverage = async (value) => ({
        ...(await coverage(value)),
        observationsSha256: hash,
      });
    },
    (f) => {
      delete f.options.coverage;
    },
    (f) => {
      f.reader.verifier = async () => ({
        ...f.verifier,
        creationTime: "10999",
      });
    },
    (f) => {
      const coverage = f.options.coverage;
      f.options.coverage = async (value) => {
        const proof = await coverage(value);
        proof.wfp.globalConfigurationSha256 = hash;
        return proof;
      };
    },
    (f) => {
      const coverage = f.options.coverage;
      f.options.coverage = async (value) => {
        const proof = await coverage(value);
        proof.flags.creationDaclProtectionVerified = false;
        return proof;
      };
    },
  ]) {
    const f = effectiveFixture();
    change(f);
    await assert.rejects(
      createWindowsEffectiveReaders(
        f.reader,
        f.context,
        f.verifier,
        f.options,
      ).policySnapshot(f.input, {
        subject: 0,
        objects: f.objects.map((_, index) => index),
      }),
    );
  }
});
test("Windows WFP observations reject substituted principals, types, tuples, action rights and late changes", async () => {
  const f = effectiveFixture(),
    expected = f.plan.manifest.filters[6],
    native = f.filters[6];
  assert.equal(assertWindowsWfpFilterRead(native, expected, f.plan).id, "7");
  for (const change of [
    (read) => {
      read.conditions[0].value.pop();
    },
    (read) => {
      read.conditions[0].value[0].sid = "S-1-5-18";
    },
    (read) => {
      read.conditions[1].type = 2;
    },
    (read) => {
      read.conditions.push(structuredClone(read.conditions[1]));
    },
    (read) => {
      read.flags = 1;
    },
    (read) => {
      read.security.aces.push({ type: 0, flags: 0, mask: 1, sid: "S-1-1-0" });
    },
  ]) {
    const read = structuredClone(native);
    change(read);
    assert.throws(() => assertWindowsWfpFilterRead(read, expected, f.plan));
  }
  let count = 0;
  const acl = f.reader.acl;
  f.reader.acl = async (...args) => {
    const read = await acl(...args);
    if (++count > f.objects.length) read.security.aces[0].mask = 1;
    return read;
  };
  await assert.rejects(
    createWindowsEffectiveReaders(
      f.reader,
      f.context,
      f.verifier,
      f.options,
    ).policySnapshot(f.input, {
      subject: 0,
      objects: f.objects.map((_, index) => index),
    }),
  );
  for (const damage of [
    (read) => {
      read.conditions[0].value.type = 255;
    },
    (read) => {
      read.sublayerWeight--;
    },
  ]) {
    const fixture = effectiveFixture(),
      global = fixture.reader.wfpGlobal;
    let reads = 0;
    fixture.reader.wfpGlobal = async (key) => {
      const read = await global(key);
      if (++reads > fixture.filters.length) damage(read);
      return read;
    };
    await assert.rejects(
      createWindowsEffectiveReaders(
        fixture.reader,
        fixture.context,
        fixture.verifier,
        fixture.options,
      ).policySnapshot(fixture.input, {
        subject: 0,
        objects: fixture.objects.map((_, index) => index),
      }),
    );
  }
});
test("Windows held file barriers reject manufactured bytes and retirement cannot infer whole-domain absence", async () => {
  const bytes = Buffer.from("sentinel");
  const read = {
    identity: fileId(1),
    bytes: bytes.length,
    sha256: digest(bytes),
    daclSha256: hash,
    hex: bytes.toString("hex"),
  };
  assert.deepEqual(normalizeWindowsBarrierRead(read), read);
  assert.throws(() => normalizeWindowsBarrierRead({ ...read, hex: "00" }));
  const f = effectiveFixture();
  f.reader.process = async (slot) => ({
    independent: true,
    identity: slot === 31 ? f.verifier : f.subject,
    retired: slot !== 31,
  });
  f.reader.inspectJob = async () => ({ independent: true, members: [] });
  const owner = createWindowsEffectiveReaders(
    f.reader,
    f.context,
    f.verifier,
    f.options,
  );
  await assert.rejects(owner.retirement([0], [0]));
  f.options.retirement = async ({ context, processes, jobs }) => {
    const { observationDigest } = await import("../index.js");
    return {
      candidateSha,
      status: "RETIRED",
      independent: true,
      emergencyCleanup: false,
      noLiveMembers: true,
      noForeignCreators: true,
      noPrincipalFlows: true,
      observationsSha256: observationDigest({ context, processes, jobs }),
      verifier: f.verifier,
      nativeEventSha256: hash,
    };
  };
  assert.equal((await owner.retirement([0], [0])).status, "RETIRED");
  f.reader.inspectJob = async () => ({
    independent: true,
    members: [f.subject],
  });
  await assert.rejects(owner.retirement([0], [0]));
});

test("Windows protected Git snapshots join actual bytes, ancestors and complete repeated inventories", async () => {
  const f = effectiveFixture(),
    request = f.input.request;
  const input = {
    request,
    git: {
      path: request.storage + "\\git.exe",
      sha256: hash,
      signatureSha256: hash,
    },
    metadata: request.storage + "\\metadata",
    hooks: request.storage + "\\hooks",
    parent: candidateSha,
    accountSid: f.input.accountSid,
    reviewSha256: hash,
  };
  const contents = [
    {
      config: "[user]\n\tname = Fixture\n\temail = fixture@example.invalid\n",
      HEAD: "ref: refs/heads/proof\n",
      "refs/heads/proof": candidateSha + "\n",
    },
    {
      ".git": `gitdir: ${input.metadata.replaceAll("\\", "/")}\n`,
      "content.txt": "owned edit\n",
    },
  ];
  const records = contents.map((values, root) =>
    Object.entries(values).map(([name, value], index) => ({
      name,
      file: {
        identity: fileId(20 + root * 10 + index),
        bytes: Buffer.byteLength(value),
        sha256: digest(value),
        daclSha256: hash,
        hex: Buffer.from(value).toString("hex"),
      },
    })),
  );
  f.reader.inspect = async (index) => ({
    ...f.objects[0].object,
    identity: fileId(80 + index),
    pathHex: encode(index === 0 ? input.metadata : request.workspace),
  });
  f.reader.parents = async () => [fileId(70), fileId(71)];
  f.reader.tree = async (index) =>
    records[index].map(({ name, file }) => {
      const { hex, ...rest } = file;
      return { nameHex: encode(name.replaceAll("/", "\\")), file: rest };
    });
  f.reader.barrier = async (index, name) =>
    structuredClone(
      records[index].find((item) => item.name === name.replaceAll("\\", "/"))
        .file,
    );
  const owner = createWindowsEffectiveReaders(
      f.reader,
      f.context,
      f.verifier,
      f.options,
    ),
    snapshot = await owner.gitSnapshot(input, 0, 1);
  assert.equal(snapshot.identity, "Fixture <fixture@example.invalid>");
  assert.equal(snapshot.head, candidateSha);
  assert.equal(snapshot.contentSha256, digest("owned edit\n"));
  const tree = f.reader.tree;
  let calls = 0;
  f.reader.tree = async (index) => {
    const values = await tree(index);
    if (++calls > 2) values[0].file.identity = fileId(99);
    return values;
  };
  await assert.rejects(owner.gitSnapshot(input, 0, 1));
});
test("Windows outside controls require actual held nonce bytes and a distinct native System acknowledgement", async () => {
  const f = effectiveFixture(),
    nonce = f.input.request.nonce,
    helper = { ...f.verifier, pid: 902, creationTime: "10902" };
  f.reader.process = async (index) => ({
    identity: index === 31 ? f.verifier : helper,
    independent: true,
    retired: false,
  });
  const file = {
    identity: fileId(20),
    bytes: nonce.length,
    sha256: digest(nonce),
    daclSha256: hash,
    hex: Buffer.from(nonce).toString("hex"),
  };
  f.reader.barrier = async () => structuredClone(file);
  f.options.control = async ({ subject, target }) => ({
    independent: true,
    reached: true,
    discretionaryAllowed: true,
    nonce,
    targetIdentity: target.identity,
    targetSha256: target.sha256,
    subject,
    verifier: f.verifier,
    nativeEventSha256: hash,
  });
  const owner = createWindowsEffectiveReaders(
    f.reader,
    f.context,
    f.verifier,
    f.options,
  );
  assert.equal(
    (await owner.outsideControl(f.input, 0, 0, "outside-sentinel")).ready,
    true,
  );
  file.sha256 = hash;
  await assert.rejects(owner.outsideControl(f.input, 0, 0, "outside-sentinel"));
});
test("Windows retired policy snapshots require fresh whole-domain proof and observe owned filter removal", async () => {
  const f = effectiveFixture(),
    process = f.reader.process;
  f.reader.process = async (slot) => ({
    ...(await process(slot)),
    retired: true,
  });
  f.reader.inspectJob = async () => ({ independent: true, members: [] });
  const owner = createWindowsEffectiveReaders(
      f.reader,
      f.context,
      f.verifier,
      f.options,
    ),
    transfer = { subject: 0, objects: f.objects.map((_, index) => index) };
  await assert.rejects(owner.policySnapshot(f.input, transfer));
  await assert.rejects(owner.retiredPolicySnapshot(f.input, transfer, [0]));
  f.options.retirement = async ({ context, processes, jobs }) => ({
    candidateSha,
    nonce: f.input.request.nonce,
    status: "RETIRED",
    independent: true,
    emergencyCleanup: false,
    noLiveMembers: true,
    noForeignCreators: true,
    noPrincipalFlows: true,
    observationsSha256: observationDigest({ context, processes, jobs }),
    verifier: f.verifier,
    nativeEventSha256: hash,
  });
  assert.equal(
    (await owner.retiredPolicySnapshot(f.input, transfer, [0])).wfp.filters
      .length,
    52,
  );
  await assert.rejects(
    owner.retiredPolicySnapshot(f.input, transfer, [0], { installed: false }),
  );
  f.filters.splice(0);
  assert.equal(
    (
      await owner.retiredPolicySnapshot(f.input, transfer, [0], {
        installed: false,
      })
    ).wfp.filters.length,
    0,
  );
  f.options.retirement = async () => ({
    status: "RETIRED",
    independent: true,
    noLiveMembers: false,
  });
  await assert.rejects(
    owner.retiredPolicySnapshot(f.input, transfer, [0], { installed: false }),
  );
});
