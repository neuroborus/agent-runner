import { createHash } from "node:crypto";
import { deflateSync } from "node:zlib";
import path from "node:path";
import { observationDigest, requireObservation } from "../index.js";
import { digest } from "./protocol.js";
import { encodeDarwinCustodyPlan } from "./custody.js";
import { darwinSystemRecipes } from "./system.js";
import { darwinOwnershipPolicy } from "./case-effects.js";
import { darwinGitPolicies } from "./git-effects.js";
import { darwinPfAuthorityDigest } from "./pf-kernel.js";
import { buildDarwinPolicy } from "./policy.js";
import { DARWIN_ACCESS_DENIALS } from "./access.js";
import { darwinExperimentCaseDeclarations } from "./case-provisioning.js";

const lease = "/private/var/run/native-poc/pf-lease";
const sha1 = (bytes) => createHash("sha1").update(bytes).digest("hex");

// Generate only disposable repository bytes. Native Git must still execute the
// exact fixed command and independently rejoin every resulting loose object.
function repository(add, copy, metadata, workspace) {
  const folders = new Set(),
    directory = (name) => {
      if (!folders.has(name)) {
        folders.add(name);
        add("authority", metadata + "/" + name);
      }
    };
  for (const name of [
    "objects",
    "refs",
    "refs/heads",
    "logs",
    "logs/refs",
    "logs/refs/heads",
  ])
    directory(name);
  const object = (kind, bytes) => {
    const body = Buffer.concat([
        Buffer.from(kind + " " + bytes.length + "\0"),
        bytes,
      ]),
      id = sha1(body);
    directory("objects/" + id.slice(0, 2));
    copy(
      "data",
      metadata + "/objects/" + id.slice(0, 2) + "/" + id.slice(2),
      deflateSync(body),
    );
    return id;
  };
  const blob = object("blob", Buffer.from("base\n")),
    tree = object(
      "tree",
      Buffer.concat([
        Buffer.from("100644 content.txt\0"),
        Buffer.from(blob, "hex"),
      ]),
    ),
    parent = object(
      "commit",
      Buffer.from(
        `tree ${tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\ntest(fixture): seed owned base\n`,
      ),
    ),
    index = Buffer.alloc(112);
  index.write("DIRC");
  index.writeUInt32BE(2, 4);
  index.writeUInt32BE(1, 8);
  index.writeUInt32BE(0o100644, 36);
  Buffer.from(blob, "hex").copy(index, 52);
  index.writeUInt16BE(11, 72);
  index.write("content.txt", 74);
  Buffer.from(sha1(index.subarray(0, -20)), "hex").copy(
    index,
    index.length - 20,
  );
  for (const [name, bytes] of Object.entries({
    config: Buffer.from(
      "[core]\n\trepositoryformatversion = 0\n\tbare = false\n\tlogallrefupdates = true\n[user]\n\tname = Fixture\n\temail = fixture@example.invalid\n",
    ),
    HEAD: Buffer.from("ref: refs/heads/proof\n"),
    "refs/heads/proof": Buffer.from(parent + "\n"),
    index,
  }))
    copy("data", metadata + "/" + name, bytes);
  copy("data", workspace + "/.git", Buffer.from("gitdir: " + metadata + "\n"));
  copy("data", workspace + "/content.txt", Buffer.from("owned edit\n"));
  return parent;
}

/** Complete finite declarations. Uploaded data supplies expectations; native
 * owners still create resources, observe policy, execute controls and retire. */
export async function prepareDarwinExperimentCases(
  prepared,
  build,
  inputs,
  publish,
) {
  const cases = [],
    uploads = [],
    sourceSha256 = observationDigest(prepared.sources),
    asset = (bytes) => {
      const pin = {
        path: path.join(
          prepared.sourceDirectory,
          "experiment-asset-" + uploads.length,
        ),
        sha256: digest(bytes),
      };
      uploads.push({ ...pin, bytes });
      return pin;
    },
    helper = (name) => {
      const value = build.helpers.find((image) => image.name === name);
      requireObservation(value);
      return {
        path: path.join(prepared.output, name),
        sha256: value.sha256,
        cdhash: value.cdhash,
      };
    };
  for (const [ordinal, recipe] of darwinSystemRecipes()
    .filter(({ id }) => id !== "build")
    .entries()) {
    const context = { ...prepared.bootstrap.context, executionId: recipe.id },
      nonce = observationDigest(context).slice(0, 32),
      root = "/private/var/run/native-poc/cases/" + observationDigest(context),
      access = recipe.id.startsWith("access."),
      files = recipe.group === "files",
      git = recipe.id.startsWith("git."),
      payload = helper(
        access
          ? "access-fixture"
          : files
            ? "file-helper"
            : git
              ? recipe.id === "git.fixed"
                ? "git-executor"
                : "git-fixture"
              : ["ownership.literal", "ownership.storage", "release"].includes(
                    recipe.id,
                  )
                ? "argv-fixture"
                : "ownership-fixture",
      ),
      launcher = helper("launcher"),
      // These are reserved numeric credentials, not directory-service logins.
      // The native reader must census both namespaces while holding exclusion.
      uid = 90001 + ordinal * 2,
      gid = uid + 1,
      request = {
        purpose: "experiment",
        schemaVersion: 1,
        candidateSha: prepared.job.candidateSha,
        nonce,
        uid,
        gid,
        custody: root + "/custody",
        storage: root + "/storage",
        workspace: root + "/storage/work",
        launcher: { path: root + "/custody/launcher", sha256: launcher.sha256 },
        executable: { ...payload, path: root + "/storage/payload" },
        policy: { path: root + "/custody/policy", sha256: sourceSha256 },
        bindings: {
          system: observationDigest(prepared.binding),
          source: sourceSha256,
          closure: context.closureSha256,
          policy: sourceSha256,
        },
      },
      assets = [],
      entries = [
        { kind: "directory", path: root, sha256: null },
        ...[request.custody, request.storage, request.workspace].map(
          (path) => ({ kind: "authority", path, sha256: null }),
        ),
        ...[request.launcher, request.executable, request.policy].map(
          ({ path, sha256 }, i) => ({
            kind:
              i === 2
                ? "data"
                : i === 1 && (files || recipe.id === "git.fixed")
                  ? "helper"
                  : "image",
            path,
            sha256,
          }),
        ),
        { kind: "image", path: launcher.path, sha256: launcher.sha256 },
        {
          kind: files || recipe.id === "git.fixed" ? "helper" : "image",
          path: payload.path,
          sha256: payload.sha256,
        },
        { kind: "data", path: "", sha256: sourceSha256 },
        {
          kind: "data",
          path: lease,
          sha256: digest("native-poc-pf-lease-v1\n"),
        },
        { kind: "directory", path: prepared.output, sha256: null },
      ],
      add = (kind, file, pin = null, source = null) => {
        const prior = [...entries, ...assets].findIndex(
          (entry) => entry.path === file,
        );
        if (prior >= 0) {
          requireObservation([...entries, ...assets][prior].sha256 === pin);
          return prior;
        }
        const index = 12 + assets.length;
        assets.push({ kind, path: file, sha256: pin, source });
        return index;
      },
      copyPin = (kind, file, pin) =>
        add(kind, file, pin.sha256, add(kind, pin.path, pin.sha256)),
      copy = (kind, file, bytes) => copyPin(kind, file, asset(bytes));
    let input = request,
      slots,
      policyBytes = Buffer.from(darwinOwnershipPolicy(request)),
      record;
    if (access) {
      input = {
        purpose: "experiment",
        request,
        profile: recipe.profile,
        disposable: true,
        metadata: request.storage + "/metadata",
        pointer: request.workspace + "/.git",
        checkout: root + "/checkout",
        configuration: root + "/configuration",
        credentials: root + "/credentials",
        runtime: [
          {
            path: request.executable.path,
            sha256: payload.sha256,
            executable: true,
            mapped: true,
          },
          {
            path: "/usr/lib/dyld",
            sha256: inputs.loader.sha256,
            executable: false,
            mapped: true,
          },
        ],
        endpoints: ["inet", "inet6"].flatMap((family, i) =>
          ["tcp", "udp"].map((protocol, j) => ({
            family,
            protocol,
            clientPort: 40000 + ordinal * 128 + i * 4 + j * 2,
            serverPort: 40001 + ordinal * 128 + i * 4 + j * 2,
            address: family === "inet" ? "127.0.0.1" : "::1",
            owned: true,
          })),
        ),
        bindingSha256: sourceSha256,
      };
      const plan = buildDarwinPolicy(input),
        install = asset(Buffer.from('anchor "native-poc/*" all quick\n')),
        empty = asset(Buffer.from("\n")),
        tool = copyPin("helper", request.custody + "/pfctl", inputs.pfctl),
        observer = copyPin(
          "helper",
          request.custody + "/observer",
          helper("observer-helper"),
        ),
        configuration = copy(
          "data",
          request.custody + "/darwin-pf.conf",
          Buffer.from(plan.pf),
        ),
        before = copyPin(
          "data",
          request.custody + "/darwin-pf-before.conf",
          empty,
        ),
        attempts = accessAttempts(plan, root, inputs);
      const bank = Buffer.from(
        // A validated numeric IPv6 zone stays in the pinned target bytes through
        // cold reads and both native control and payload argument vectors.
        attempts
          .map(
            ({ operation, target, remote, local }) =>
              `${operation} ${Buffer.from(target).toString("hex")} ${remote} ${local}\n`,
          )
          .join(""),
      );
      copy("data", request.custody + "/access-cases", bank);
      for (const file of [
        input.metadata,
        input.checkout,
        input.configuration,
        input.credentials,
        root + "/outside",
        request.storage + "/work.replacement",
      ])
        add("authority", file);
      add("data", inputs.loader.path, inputs.loader.sha256);
      add("data", input.pointer, digest(nonce));
      const required = [
        request.custody,
        request.storage,
        request.workspace,
        input.metadata,
        input.pointer,
        input.checkout,
        input.configuration,
        input.credentials,
        ...input.runtime.map(({ path }) => path),
      ];
      record = {
        purpose: "experiment",
        schemaVersion: 2,
        contextSha256: observationDigest(context),
        assets,
        pf: {
          bindings: {
            schemaVersion: 1,
            contextSha256: observationDigest(context),
            bindingSha256: prepared.bootstrap.bindingSha256,
            baselineSha256: darwinPfAuthorityDigest(inputs.pf),
            installedRootSha256: null,
            routesSha256: inputs.pf.routesSha256,
            loopbackSkip: inputs.pf.interfaces.find(
              ({ name }) => name === "lo0",
            ).skip,
          },
          tool: { index: tool, cdhash: inputs.pfctl.cdhash },
          install: add("data", install.path, install.sha256),
          restore: add("data", empty.path, empty.sha256),
          configuration,
          before,
          anchorRulesSha256: null,
        },
        audit: {
          mapping: inputs.audit,
          classes: inputs.classes,
          helper: { index: observer, cdhash: helper("observer-helper").cdhash },
        },
        mach: {
          source: inputs.mach.source,
          tool: {
            index: add(
              "helper",
              inputs.mach.tool.path,
              inputs.mach.tool.sha256,
            ),
            cdhash: inputs.mach.tool.cdhash,
          },
        },
        objects: required.map((file) => ({
          index: [...entries, ...assets].findIndex(({ path }) => path === file),
          decisions: decisions(input, file),
          aclSha256: null,
        })),
        attempts,
      };
      input.bindingSha256 = asset(
        Buffer.from(JSON.stringify(record) + "\n"),
      ).sha256;
      const pin = uploads.at(-1);
      record = { binding: { path: pin.path, sha256: pin.sha256 } };
      const final = buildDarwinPolicy(input);
      policyBytes = Buffer.from(final.seatbelt);
      request.bindings.policy = final.compositionSha256;
    } else if (files || git || recipe.id === "release") {
      const outside = add("authority", root + "/outside");
      copy(
        "data",
        root + "/outside/sentinel",
        Buffer.from("unchanged outside\n"),
      );
      input = { purpose: "experiment", request, bindingSha256: sourceSha256 };
      if (files) {
        input.base = input.root = null;
        slots = {
          base: 1,
          root: add("authority", request.custody + "/files"),
          outside,
          alias: add("authority", request.custody + "/aliases"),
          volume: {
            tool: add("helper", inputs.hdiutil.path, inputs.hdiutil.sha256),
            image: add("data", inputs.volume.path, inputs.volume.sha256),
            cdhash: inputs.hdiutil.cdhash,
          },
        };
      } else if (git) {
        const gitImage = copyPin(
            "helper",
            request.storage + "/git",
            inputs.git,
          ),
          metadata = add("authority", request.storage + "/metadata"),
          hooks = add("authority", request.storage + "/hooks");
        input.git = {
          path: request.storage + "/git",
          sha256: inputs.git.sha256,
          cdhash: inputs.git.cdhash,
        };
        input.metadata = request.storage + "/metadata";
        input.hooks = request.storage + "/hooks";
        input.parent = repository(add, copy, input.metadata, request.workspace);
        slots = {
          git: gitImage,
          metadata,
          hooks,
          outside,
          control: null,
          profiles: [],
          audit: null,
        };
        if (recipe.id === "git.ordinary") {
          const meta = add("authority", request.storage + "/control"),
            work = add("authority", request.storage + "/control-work"),
            hook = add("authority", request.storage + "/control-hooks");
          repository(
            add,
            copy,
            request.storage + "/control",
            request.storage + "/control-work",
          );
          slots.control = {
            metadata: meta,
            workspace: work,
            hooks: hook,
            helper: copyPin(
              "helper",
              request.custody + "/git-executor",
              helper("git-executor"),
            ),
            cdhash: helper("git-executor").cdhash,
          };
          slots.profiles = darwinGitPolicies(input).map(
            ({ profile, bytes }) => ({
              profile,
              policy: copy(
                "data",
                request.custody + "/git-policy-" + profile,
                bytes,
              ),
            }),
          );
          slots.audit = {
            helper: {
              index: copyPin(
                "helper",
                request.custody + "/observer",
                helper("observer-helper"),
              ),
              cdhash: helper("observer-helper").cdhash,
            },
            classes: inputs.classes,
            mapping: inputs.audit,
          };
        }
      } else
        slots = {
          components: build.helpers.map(({ name }) => ({
            id: name,
            index: add("helper", helper(name).path, helper(name).sha256),
          })),
          loader: add("image", inputs.loader.path, inputs.loader.sha256),
        };
      record = {
        purpose: "experiment",
        schemaVersion: recipe.id === "release" ? 3 : 1,
        contextSha256: observationDigest(context),
        id: recipe.id,
        inputSha256: null,
        assets,
        slots,
      };
      policyBytes = Buffer.from("(version 1)\n(deny default)\n");
    }
    const policy = asset(policyBytes);
    request.policy.sha256 = policy.sha256;
    entries[6].sha256 = policy.sha256;
    entries[9] = { kind: "data", ...policy };
    const planBytes = encodeDarwinCustodyPlan({
        purpose: "experiment",
        candidateSha: prepared.job.candidateSha,
        uid,
        gid,
        entries: [...entries, ...assets.map(({ source, ...entry }) => entry)],
      }),
      plan = asset(planBytes);
    if (record?.slots) {
      const { bindingSha256, ...data } = input;
      record.inputSha256 = observationDigest(data);
      const pin = asset(Buffer.from(JSON.stringify(record) + "\n"));
      input.bindingSha256 = pin.sha256;
      record = { binding: { path: pin.path, sha256: pin.sha256 } };
    }
    cases.push({
      id: recipe.id,
      custody: {
        ...structuredClone(prepared.bootstrap),
        context,
        reader: structuredClone(prepared.bootstrap.reader),
        plan: { path: plan.path, sha256: plan.sha256 },
      },
      bindings: {
        schemaVersion: access ? 2 : 1,
        bindingSha256: prepared.bootstrap.bindingSha256,
        uid,
        gid,
        input,
        assets: [
          { path: launcher.path, sha256: launcher.sha256 },
          { path: payload.path, sha256: payload.sha256 },
          { path: policy.path, sha256: policy.sha256 },
        ],
        ...(access ? { access: record } : record ? { operations: record } : {}),
      },
    });
  }
  for (const upload of uploads) await publish(upload);
  return {
    purpose: "experiment",
    schemaVersion: 2,
    ...darwinExperimentCaseDeclarations(cases),
    uploads: uploads.map(({ bytes, ...pin }) => ({
      ...pin,
      hex: bytes.toString("hex"),
    })),
  };
}

function decisions(input, file) {
  const request = input.request,
    runtime = input.runtime.find(({ path }) => path === file),
    read =
      file === request.workspace ||
      file === input.pointer ||
      file === input.metadata ||
      !!runtime;
  return [read ? 0 : 1, 1, 1, 1, runtime?.executable ? 0 : 1];
}
function accessAttempts(plan, root, inputs) {
  const { request } = plan.value,
    operations = [
      "read",
      "write",
      "write",
      "write",
      "unlink",
      "replace",
      "parent",
      "read",
      "write",
      "read",
      "read",
      "read",
      "write",
      "mach",
      "unix",
      "shm",
      "sem",
      "sysv-shm",
      "sysv-sem",
    ],
    targets = [
      request.workspace + "/inspection",
      request.workspace + "/edit",
      plan.value.metadata + "/sentinel",
      ...Array(3).fill(plan.value.pointer),
      request.workspace,
      request.custody + "/sentinel",
      request.custody + "/sentinel",
      plan.value.checkout + "/sentinel",
      plan.value.configuration + "/sentinel",
      plan.value.credentials + "/sentinel",
      root + "/outside/sentinel",
      "org.native-poc." + request.nonce,
      root + "/ipc",
      "/native-poc-" + request.nonce,
      "/native-poc-" + request.nonce,
      "sysv-shm",
      "sysv-sem",
    ];
  return [
    "inspection",
    "edit",
    ...DARWIN_ACCESS_DENIALS,
    ...plan.value.endpoints.map(
      ({ family, protocol }) => `loopback-${family}-${protocol}`,
    ),
  ].map((id, i) => {
    const endpoint = i >= 35 ? plan.value.endpoints[i - 35] : null,
      operation =
        operations[i] ??
        (endpoint
          ? `${endpoint.protocol}${endpoint.family === "inet" ? 4 : 6}-pair`
          : `${(i - 19) % 2 ? "udp" : "tcp"}${(i - 19) % 4 >= 2 ? 6 : 4}`),
      event =
        operation === "mach"
          ? null
          : inputs.events[operation.replace(/-pair$/u, "")];
    requireObservation(operation === "mach" || event);
    return {
      id,
      source: operation === "mach" ? inputs.mach.source : "bsm",
      event,
      controlEvent: event,
      operation,
      target:
        targets[i] ??
        endpoint?.address ??
        (Math.floor((i - 19) / 4) === 1
          ? (i - 19) % 4 >= 2
            ? "::"
            : "0.0.0.0"
          : Math.floor((i - 19) / 4) === 2
            ? inputs.addresses[(i - 19) % 4 >= 2 ? "inet6" : "inet"]
            : (i - 19) % 4 >= 2
              ? "::1"
              : "127.0.0.1"),
      remote: endpoint?.serverPort ?? (i < 17 ? 0 : 48001 + i * 2),
      local: endpoint?.clientPort ?? (i < 19 ? 0 : 48002 + i * 2),
    };
  });
}
