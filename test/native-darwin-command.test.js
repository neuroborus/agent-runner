import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import {
  runDarwinFeasibilityCommand,
  darwinCommandEnvironment,
  darwinCommandFileObservation,
  settleDarwinCommandCustody,
  darwinCommandCleanupArguments,
} from "../ci/native/darwin/index.js";
import { feasibilityCommandParameters } from "../ci/native/providers/index.js";

const sha = (value) => createHash("sha256").update(value).digest("hex"),
  PIN = sha("fixture");
const identity = {
  pid: 123,
  pidVersion: 2,
  asid: 17,
  auid: 501,
  uid: 501,
  ruid: 501,
  svuid: 501,
  gid: 20,
  rgid: 20,
  svgid: 20,
  startSeconds: 90,
  startMicroseconds: 1,
};
function fixture(change = () => {}) {
  const calls = [],
    requests = [],
    durations = [],
    signals = [],
    inputs = {
      packages: {
        codex: {
          component: {
            role: "tool",
            name: "codex",
            version: "0.160.0",
            sha256: PIN,
          },
        },
      },
      tool: { role: "tool", name: "tar", version: "1", sha256: PIN },
    };
  let nonce,
    spec,
    clock = 100;
  const prepared = {
    admission: true,
    audit: true,
    completeRetirement: true,
    sessionEscapeDenied: true,
    uid: 501,
    gid: 20,
    home: "/fixture/home",
    workspace: "/fixture/workspace",
    helper: "/fixture/helper",
    gate: "/fixture/workspace/gate",
    helperSha256: PIN,
    sentinelSha256: PIN,
    files: {
      inspect: "/fixture/workspace/inspection",
      edit: "/fixture/workspace/edit",
      outside: "/fixture/outside",
    },
  };
  const client = {
    initialize: async () => ({ codexHome: prepared.home }),
    exec: async (request) => {
      requests.push(request);
      return {
        exitCode: 0,
        stdout:
          spec.action === "inspect"
            ? nonce
            : spec.permit
              ? "attempt:written"
              : "attempt:denied",
        stderr: "",
      };
    },
    close: async () => {
      calls.push("client-close");
    },
  };
  const effects = {
    noCustody: () => true,
    prepare: async (value) => {
      calls.push("prepare");
      nonce = value;
      return prepared;
    },
    schema: async () => {
      calls.push("schema");
      return {};
    },
    arm: async () => {
      calls.push("arm");
      return {
        identity,
        captureReady: true,
        sessionHeld: true,
        imageSha256: PIN,
        transport: {},
      };
    },
    release: async () => {
      calls.push("release");
    },
    control: async () => {
      const saved = spec;
      spec = {
        action: "control",
        permit: true,
        target: prepared.files.outside,
      };
      const observation = await effects.observe();
      spec = saved;
      return {
        permitted: true,
        observation,
        reply: { exitCode: 0, stdout: "attempt:written" },
      };
    },
    begin: async (_, value) => {
      calls.push("begin");
      spec = value;
    },
    observe: async () => {
      const first = darwinCommandFileObservation({
          identity: `1:2:3:4:90:1:501:20:100600:${"a".repeat(32)}`,
          sha256: sha(nonce),
        }),
        last = {
          ...first,
          sha256: sha(
            spec.permit && ["edit", "outside"].includes(spec.action)
              ? nonce + "-edited"
              : nonce,
          ),
        };
      const gate = { device: "1", inode: "5", uid: 501, gid: 20, mode: 0o600 };
      return {
        before: identity,
        after: identity,
        imageSha256: PIN,
        sandboxed: true,
        gate: { before: gate, after: { ...gate } },
        object: { before: first, after: last },
        barrierSha256: PIN,
        events: [
          {
            id: sha(JSON.stringify(spec)),
            pid: identity.pid,
            auid: 501,
            asid: 17,
            uid: 501,
            gid: 20,
            opcode: "AUE_OPEN",
            target: spec.target,
            kind: "path",
            error: spec.permit ? 0 : 13,
            result: spec.permit ? 3 : -1,
            time: 100002,
            window: { start: 100001, end: 100003, barrierSha256: PIN },
            nativeObject: {
              device: "1",
              inode: "4",
              mode: 0o600,
              uid: 501,
              gid: 20,
            },
          },
          {
            id: sha("acknowledgement" + JSON.stringify(spec)),
            pid: identity.pid,
            auid: 501,
            asid: 17,
            uid: 501,
            gid: 20,
            target: prepared.gate,
            opcode: "AUE_OPEN",
            kind: "path",
            error: 0,
            result: 3,
            time: 100002,
            window: { start: 100001, end: 100003, barrierSha256: PIN },
            nativeObject: gate,
          },
        ],
      };
    },
    retire: async () => {
      calls.push("retire");
      return {
        independent: true,
        completeDomain: true,
        sessionHeldUntilEmpty: true,
        admissionsClosed: true,
        serverRetired: true,
        helpersRetired: true,
        observerRetired: true,
        emergency: false,
        witnessSha256: PIN,
      };
    },
    finish: async () => {
      calls.push("finish");
      return { sentinelSha256: prepared.sentinelSha256, witnessSha256: PIN };
    },
  };
  const protocol = {
    open: () => client,
    parameters: feasibilityCommandParameters,
    supports: () => true,
  };
  change({ effects, prepared, client, protocol, calls });
  return {
    inputs,
    calls,
    requests,
    durations,
    signals,
    effects,
    advance: (ms) => {
      clock += ms;
    },
    run: () =>
      runDarwinFeasibilityCommand(
        { expectedSha: "a".repeat(40) },
        inputs,
        protocol,
        {
          effects,
          now: () => clock,
          timeout: (ms) => {
            durations.push(ms);
            const c = new AbortController();
            signals.push(c);
            return c.signal;
          },
        },
      ),
  };
}
test("Darwin command construction uses an empty-home credential-free allowlist and both explicit stock policies", async () => {
  const env = darwinCommandEnvironment("/fixture/home", "/fixture/codex");
  assert.deepEqual(Object.keys(env).sort(), [
    "CI",
    "CODEX_HOME",
    "GITHUB_ACTIONS",
    "HOME",
    "LANG",
    "PATH",
    "RUNNER_ENVIRONMENT",
    "RUNNER_OS",
  ]);
  assert.equal(env.CODEX_HOME, env.HOME);
  const f = fixture(),
    result = await f.run();
  assert.equal(result.status, "PASS");
  assert.equal(result.cleanup.status, "PASS");
  assert.equal(f.inputs.commandCleanup, result.cleanup);
  assert.deepEqual(f.durations, [120000, 30000]);
  assert.equal(f.requests.length, 6);
  assert.ok(f.calls.indexOf("arm") < f.calls.indexOf("release"));
  for (const request of f.requests) {
    assert.equal(request.sandboxPolicy.networkAccess, false);
    assert.equal(request.command[0], "/fixture/helper");
    assert.equal(request.outputBytesCap, 4096);
  }
  assert.deepEqual(
    f.requests.slice(3).map(({ sandboxPolicy }) => sandboxPolicy.writableRoots),
    Array(3).fill(["/fixture/workspace"]),
  );
  assert.ok(f.calls.indexOf("retire") < f.calls.indexOf("finish"));
});
test("Darwin command prerequisites and unsupported installed schemas stop provider release", async () => {
  for (const key of [
    "admission",
    "audit",
    "completeRetirement",
    "sessionEscapeDenied",
  ]) {
    const f = fixture(({ prepared }) => {
      prepared[key] = false;
    });
    const result = await f.run();
    assert.equal(result.status, "BLOCKED");
    assert.equal(result.cleanup.status, "NOT_RUN");
    assert.equal(f.calls.includes("schema"), false);
  }
  const f = fixture(({ protocol }) => {
    protocol.supports = () => false;
  });
  assert.equal((await f.run()).status, "BLOCKED");
  assert.equal(f.calls.includes("release"), false);
});
test("Darwin failed buffered replies retain their cause while native observation is pending", async () => {
  for (const outcome of [
    "unavailable",
    "later-unavailable",
    "failure",
    "exit",
  ]) {
    const original = {
      code: "crash",
      detail: "The buffered request lost its server.",
    };
    let requests = 0,
      rejectObservation;
    const f = fixture(({ effects, client }) => {
      const observe = effects.observe,
        retire = effects.retire,
        exec = client.exec;
      effects.observe = (...args) =>
        args.length === 0 || (outcome === "later-unavailable" && requests === 1)
          ? observe(...args)
          : new Promise((_, reject) => {
              rejectObservation = reject;
            });
      client.exec = async (params) => {
        requests++;
        if (outcome === "later-unavailable" && requests === 1)
          return exec(params);
        if (outcome === "exit") return { exitCode: 17, stdout: "", stderr: "" };
        throw Object.assign(
          new Error("Buffered request failed"),
          outcome === "failure"
            ? { feasibilityCause: original }
            : { code: "ERR_FEASIBILITY_ROUTE_UNAVAILABLE" },
        );
      };
      effects.retire = async (...args) => {
        rejectObservation(new Error("Later missing helper"));
        return retire(...args);
      };
    });
    const result = await f.run();
    assert.equal(requests, outcome === "later-unavailable" ? 2 : 1);
    assert.equal(result.cleanup.status, "PASS");
    assert.equal(result.status, outcome === "unavailable" ? "BLOCKED" : "FAIL");
    if (outcome === "failure") assert.equal(result.cause, original);
    else if (outcome === "exit")
      assert.match(
        result.cause.detail,
        /buffered-reply: exit=17, signal=unknown, timeout=unknown/u,
      );
    else
      assert.equal(
        result.cause.code,
        outcome === "unavailable" ? "prerequisite-unavailable" : "setup-failed",
      );
  }
});
test("Darwin attribution, live policy, audit controls and changed held sentinels cannot pass", async () => {
  for (const mutate of [
    (o) => {
      o.after = { ...identity, pidVersion: 3 };
    },
    (o) => {
      o.imageSha256 = sha("other");
    },
    (o) => {
      o.sandboxed = false;
    },
    (o) => {
      o.events = [];
    },
    (o) => {
      o.events.pop();
    },
    (o) => {
      o.gate.after.inode = "6";
    },
    (o) => {
      o.events[0].nativeObject.inode = "5";
    },
    (o) => {
      o.object.before.sha256 = sha("changed-before");
    },
    (o) => {
      o.object.after.sha256 = sha("changed");
    },
  ]) {
    const f = fixture(({ effects }) => {
      const read = effects.observe;
      effects.observe = async (...args) => {
        const o = await read(...args);
        mutate(o);
        return o;
      };
    });
    const result = await f.run();
    assert.equal(result.status, "FAIL");
    assert.equal(f.calls.includes("retire"), true);
  }
  const f = fixture(({ effects }) => {
    effects.control = async () => ({ permitted: false });
  });
  assert.equal((await f.run()).status, "FAIL");
  assert.equal(f.requests.length, 0);
});
test("Darwin capture loss and a changed final outside sentinel retain failure through settlement", async () => {
  for (const change of [
    ({ effects }) => {
      effects.observe = async () => {
        throw new Error("capture lost");
      };
    },
    ({ effects }) => {
      effects.finish = async () => ({
        sentinelSha256: sha("changed"),
        witnessSha256: PIN,
      });
    },
  ]) {
    const f = fixture(change),
      result = await f.run();
    assert.equal(result.status, "FAIL");
  }
});
test("Darwin retirement requires the held complete domain, server, descendants and observer", async () => {
  for (const key of [
    "completeDomain",
    "sessionHeldUntilEmpty",
    "admissionsClosed",
    "serverRetired",
    "helpersRetired",
    "observerRetired",
    "independent",
  ]) {
    const f = fixture(({ effects }) => {
      const retire = effects.retire;
      effects.retire = async () => ({ ...(await retire()), [key]: false });
    });
    const result = await f.run();
    assert.equal(result.status, "FAIL");
    assert.equal(result.cleanup.status, "UNCERTAIN");
    assert.equal(f.calls.includes("finish"), false);
  }
  const f = fixture(({ effects }) => {
    const retire = effects.retire;
    effects.retire = async () => ({ ...(await retire()), emergency: true });
  });
  const result = await f.run();
  assert.equal(result.status, "FAIL");
  assert.equal(result.cleanup.status, "UNCERTAIN");
  assert.equal(result.cleanup.emergency, true);
  assert.equal(f.calls.includes("finish"), false);
  const g = fixture(({ effects }) => {
    effects.retire = async () => {
      throw Object.assign(new Error("Independent verification lost"), {
        emergency: true,
      });
    };
  });
  const uncertain = await g.run();
  assert.equal(uncertain.cleanup.status, "UNCERTAIN");
  assert.equal(uncertain.cleanup.emergency, true);
  assert.equal(g.calls.includes("finish"), false);
});
test("Darwin native custody failures still retire and independently observe the owner without replacing the first cause", async () => {
  for (const stage of ["domain", "session", "close"]) {
    const calls = [],
      first = new Error("First custody failure"),
      later = new Error("Later observer failure");
    await assert.rejects(
      settleDarwinCommandCustody(new Set([17, 18]), {
        retireDomain: async () => {
          calls.push("domain");
          if (stage === "domain") throw first;
          return {
            empty: true,
            emergency: true,
            serverClean: true,
            sessions: [17, 18],
          };
        },
        verifySession: async (asid) => {
          calls.push(asid);
          if (stage === "session" && asid === 17) throw first;
          return { empty: true };
        },
        closeObserver: async () => {
          calls.push("close");
          if (stage === "close") throw first;
        },
        verifyObserver: async () => {
          calls.push("observer");
          throw later;
        },
      }),
      (error) => error === first && error.emergency === (stage !== "domain"),
    );
    assert.deepEqual(
      calls,
      stage === "domain"
        ? ["domain", "close", "observer"]
        : ["domain", 17, 18, "close", "observer"],
    );
  }
  const invalid = { empty: true, emergency: false, sessions: [17, 17] },
    calls = [];
  await assert.rejects(
    settleDarwinCommandCustody(new Set([17, 18]), {
      retireDomain: async () => invalid,
      verifySession: async () => {
        assert.fail("Invalid custody must not be admitted");
      },
      closeObserver: async () => {
        calls.push("close");
      },
      verifyObserver: async () => {
        calls.push("observer");
        return { status: "RETIRED" };
      },
    }),
  );
  assert.deepEqual(calls, ["close", "observer"]);
  calls.length = 0;
  await assert.rejects(
    settleDarwinCommandCustody(new Set([17, 18]), {
      retireDomain: async () => ({
        empty: true,
        emergency: false,
        serverClean: false,
        sessions: [17, 18],
      }),
      verifySession: async (asid) => {
        calls.push(asid);
        return { empty: true };
      },
      closeObserver: async () => {
        calls.push("close");
      },
      verifyObserver: async () => {
        calls.push("observer");
        return { status: "RETIRED" };
      },
    }),
  );
  assert.deepEqual(calls, [17, 18, "close", "observer"]);
});
test("Darwin fixture cleanup refuses replaced files or parents before producing removal requests", () => {
  const files = [4, 5, 6].map((inode) => ({
      identity: `1:2:3:${inode}:90:1:501:20:100600:${"a".repeat(32)}`,
      sha256: PIN,
    })),
    parents = [1, 2].map((inode) => ({
      identity: `1:2:3:${inode}:90:1:501:20:40700:${"a".repeat(32)}`,
      sha256: null,
    })),
    value = {
      files: {
        inspect: "/fixture/workspace/inspection",
        edit: "/fixture/workspace/edit",
        outside: "/fixture/outside",
      },
      fileIdentities: files.map(({ identity }) => identity),
      parentIdentities: parents.map(({ identity }) => identity),
      sentinelSha256: sha(JSON.stringify(files[2])),
    };
  const args = darwinCommandCleanupArguments(value, files, parents);
  assert.equal(args.length, 3);
  assert.equal(args[0][4], parents[1].identity);
  assert.equal(args[2][4], parents[0].identity);
  for (const index of [0, 1, 2]) {
    const changed = structuredClone(files);
    changed[index].identity = changed[index].identity.replace(":90:", ":91:");
    assert.throws(() => darwinCommandCleanupArguments(value, changed, parents));
  }
  const changedParent = structuredClone(parents);
  changedParent[1].identity = changedParent[1].identity.replace(":90:", ":91:");
  assert.throws(() =>
    darwinCommandCleanupArguments(value, files, changedParent),
  );
  const changedOutside = structuredClone(files);
  changedOutside[2].sha256 = sha("changed");
  assert.throws(() =>
    darwinCommandCleanupArguments(value, changedOutside, parents),
  );
});
test("Darwin observation and partial-failure settlement have separate enforced deadlines", async () => {
  const elapsed = fixture(),
    observe = elapsed.effects.observe,
    retire = elapsed.effects.retire;
  elapsed.effects.observe = async (...args) => {
    elapsed.advance(15000);
    return observe(...args);
  };
  elapsed.effects.retire = async (...args) => {
    elapsed.advance(20000);
    return retire(...args);
  };
  const measured = await elapsed.run();
  assert.equal(measured.status, "PASS");
  assert.equal(measured.elapsedMs, 105000);
  assert.equal(measured.cleanup.elapsedMs, 20000);
  const f = fixture(({ effects }) => {
    effects.observe = () => {
      queueMicrotask(() => f.signals[0].abort());
      return new Promise(() => {});
    };
  });
  const result = await f.run();
  assert.equal(result.status, "FAIL");
  assert.equal(result.cause.code, "deadline");
  assert.equal(result.cleanup.status, "PASS");
  assert.deepEqual(f.durations, [120000, 30000]);
  const g = fixture(({ effects }) => {
    effects.retire = () => {
      queueMicrotask(() => g.signals[1].abort());
      return new Promise(() => {});
    };
  });
  assert.equal((await g.run()).cleanup.status, "UNCERTAIN");
  assert.equal(g.calls.includes("finish"), false);
});
