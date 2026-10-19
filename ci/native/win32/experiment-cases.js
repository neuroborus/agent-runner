import { createHash } from "node:crypto";
import { deflateSync } from "node:zlib";
import { win32 as path } from "node:path";
import { lstat } from "node:fs/promises";
import {
  observationDigest,
  observationObject,
  nativePolicyLaunchData,
  requireObservation,
} from "../index.js";
import { digest, hash, WINDOWS_LITERAL_ARGUMENTS } from "./protocol.js";
import { encodeWindowsCustodyPlan, location } from "./custody-protocol.js";
import { buildWindowsPolicy } from "./policy.js";
import {
  windowsOwnershipArguments,
  windowsAccessArguments,
} from "./case-effects.js";
import { windowsSystemRecipes } from "./system.js";

const sid = "S-1-5-21-1-1-1-1001",
  restricting = "S-1-5-21-1-1-1-1002";
const identity = "0".repeat(16) + ":" + "0".repeat(32);
const sha1 = (bytes) => createHash("sha1").update(bytes).digest("hex");
const rule = (id, kind, paths) => ({
  id,
  kind,
  paths,
  minimum: null,
  maximum: null,
});

/** The ordinary selector admits only the two installed Git runtime layouts. */
export function assertWindowsExperimentGitSelection(selection) {
  observationObject(selection, [
    "executable",
    "execPath",
    "directory",
    "path",
    "sha256",
  ]);
  const installed =
    /^([A-Z]:\\Program Files\\Git)\\(mingw64|ucrt64)\\bin$/u.exec(
      selection.directory,
    );
  requireObservation(
    installed &&
      [
        selection.executable,
        selection.execPath,
        selection.directory,
        selection.path,
      ].every(location) &&
      selection.execPath ===
        path.join(installed[1], installed[2], "libexec", "git-core") &&
      selection.path === path.join(selection.directory, "git.exe") &&
      ["cmd", "bin", path.join(installed[2], "bin")].some(
        (directory) =>
          selection.executable ===
          path.join(installed[1], directory, "git.exe"),
      ) &&
      hash(selection.sha256),
  );
}

/** Discover private Git dependencies and direct system targets. Bytes/signatures are
 * independently held by the System reader, including unsigned runtime bytes. */
export async function windowsExperimentGitRuntime(
  native,
  selection,
  options = {},
) {
  assertWindowsExperimentGitSelection(selection);
  const images = await discoverRuntime(native, selection.path, {
    ...options,
    directory: selection.directory,
  });
  requireObservation(images[0].sha256 === selection.sha256);
  return images;
}

/** Only private payload copies and Git need dependency discovery. Helper
 * admission deliberately supplies no transitive installed-system evidence. */
export async function windowsExperimentDependencies(
  prepared,
  native,
  options = {},
) {
  const helper = prepared.helpers.find(({ name }) => name === "access-fixture"),
    payload = await discoverRuntime(native, helper.path, {
      ...options,
      helper: true,
    });
  requireObservation(
    payload[0].sha256 === helper.sha256 &&
      payload[0].signatureSha256 === helper.signatureSha256,
  );
  return {
    payload,
    git: await windowsExperimentGitRuntime(
      native,
      prepared.gitRuntime,
      options,
    ),
  };
}

async function discoverRuntime(
  native,
  root,
  { exists = lstat, directory, helper = false } = {},
) {
  const pending = [root],
    resolutions = new Map(),
    identities = new Map(),
    images = new Map();
  for (let i = 0; i < pending.length; i++) {
    requireObservation(pending.length <= (helper ? 128 : 64));
    const file = pending[i],
      read = await native.readImage(file, !(helper && file === root));
    requireObservation(
      read.held &&
        read.independent &&
        read.unchanged &&
        read.protectedDacl &&
        read.protectedParents &&
        hash(read.identitySha256) &&
        hash(read.signatureSha256) &&
        read.sha256 === digest(read.bytes),
    );
    identities.set(file.toLowerCase(), read.identitySha256);
    const resolved = resolutions.get(file.toLowerCase());
    requireObservation(
      !resolved ||
        (read.sha256 === resolved.sha256 &&
          digest(read.bytes) === resolved.sha256 &&
          read.identitySha256 === resolved.identitySha256),
    );
    const imports = [];
    // Both consumers trust held hosted-system targets. Retain direct access
    // copies and the complete private Git graph without expanding stock imports.
    const system = /^[A-Z]:\\Windows\\System32\\[^\\]+\.dll$/iu.test(file);
    for (const imported of system ? [] : read.pe.imports) {
      const name = imported.name;
      requireObservation(
        typeof name === "string" &&
          /^[A-Za-z0-9_.-]{1,124}\.dll$/iu.test(name) &&
          typeof imported.delay === "boolean",
      );
      const local = directory ? path.join(directory, name) : null;
      let target;
      if (local) {
        try {
          await exists(local);
          target = local;
        } catch (error) {
          requireObservation(error.code === "ENOENT");
        }
      }
      if (!target) {
        let resolved;
        try {
          resolved = await native.resolveImport(name, file);
        } catch (cause) {
          try {
            Object.assign(cause, {
              image: file,
              importName: name,
              delay: imported.delay,
            });
          } catch {
            /* Preserve the original failure. */
          }
          throw cause;
        }
        const previous = resolutions.get(resolved.file.toLowerCase());
        requireObservation(
          !previous ||
            observationDigest(previous) === observationDigest(resolved),
        );
        target = resolved.file;
        resolutions.set(target.toLowerCase(), resolved);
        const held =
          images.get(target.toLowerCase()) ??
          (target.toLowerCase() === file.toLowerCase() ? read : null);
        requireObservation(
          !held ||
            (held.sha256 === resolved.sha256 &&
              identities.get(target.toLowerCase()) === resolved.identitySha256),
        );
      }
      imports.push({ name, path: target, delay: imported.delay });
      if (!pending.some((file) => file.toLowerCase() === target.toLowerCase()))
        pending.push(target);
    }
    images.set(file.toLowerCase(), {
      path: file,
      sha256: read.sha256,
      signatureSha256: read.signatureSha256,
      identitySha256: read.identitySha256,
      imports: system ? null : imports,
    });
  }
  return [...images.values()];
}

// Neutral repository data is deliberately generated here; every command and
// denial still executes against a real copied Git runtime in native CI.
function gitRepository(add, request) {
  const objects = [],
    folders = new Set(),
    metadata = request.storage + "\\metadata";
  const directory = (leaf) => {
    if (!folders.has(leaf)) {
      folders.add(leaf);
      objects.push(add("directory", metadata + "\\" + leaf));
    }
  };
  for (const leaf of ["objects", "refs", "refs\\heads"]) directory(leaf);
  const object = (kind, bytes) => {
    const full = Buffer.concat([
        Buffer.from(kind + " " + bytes.length + "\0"),
        bytes,
      ]),
      sha = sha1(full);
    directory("objects\\" + sha.slice(0, 2));
    objects.push(
      add(
        "data",
        metadata + "\\objects\\" + sha.slice(0, 2) + "\\" + sha.slice(2),
        deflateSync(full),
      ),
    );
    return sha;
  };
  const blob = object("blob", Buffer.from("initial\n")),
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
        "tree " +
          tree +
          "\nauthor Fixture <fixture@example.invalid> 1 +0000\ncommitter Fixture <fixture@example.invalid> 1 +0000\n\ntest(fixture): initialize fixture\n",
      ),
    );
  // Version 2 pads each entry (including its NUL pathname) to eight bytes.
  const index = Buffer.alloc(12 + 80 + 20);
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
  for (const [leaf, bytes, kind] of [
    [
      "config",
      Buffer.from(
        "[user]\n\tname = Fixture\n\temail = fixture@example.invalid\n",
      ),
      "data",
    ],
    ["HEAD", Buffer.from("ref: refs/heads/proof\n"), "data"],
    ["index", index, "mutable"],
    ["refs\\heads\\proof", Buffer.from(parent + "\n"), "mutable"],
  ])
    objects.push(add(kind, metadata + "\\" + leaf, bytes));
  objects.push(
    add(
      "mutable",
      request.workspace + "\\content.txt",
      Buffer.from("owned edit\n"),
    ),
  );
  add(
    "mutable",
    request.workspace + "\\.git",
    Buffer.from("gitdir: " + metadata.replaceAll("\\", "/") + "\n"),
  );
  return { parent, objects };
}

/** Fixed selectors only. No account identity, native ACL, policy installation,
 * launch, audit control or settlement is asserted by this generated data. */
export async function prepareWindowsExperimentCases(
  prepared,
  observation,
  native,
  options = {},
) {
  const cases = [],
    bindings = [],
    recipes = windowsSystemRecipes(),
    sourceSha256 = observationDigest(prepared.sources),
    provisionSha256 = prepared.bootstrap.bindingSha256,
    dependencies = await windowsExperimentDependencies(
      prepared,
      native,
      options,
    ),
    gitRuntime = dependencies.git,
    foreignVolume = await native.prepareVolume(),
    helper = (name) => prepared.helpers.find((image) => image.name === name),
    pins = (name) => {
      const value = helper(name);
      requireObservation(value);
      return {
        path: value.path,
        sha256: value.sha256,
        signatureSha256: value.signatureSha256,
      };
    },
    sdk = observation.sdkInputs.find(({ file }) =>
      /\\Windows Kits\\10\\Include\\/u.test(file),
    );
  requireObservation(sdk);
  let assetSequence = 0;
  for (const recipe of recipes.filter(({ id }) => id !== "build")) {
    const context = { ...prepared.bootstrap.context, executionId: recipe.id },
      nonce = observationDigest(context).slice(0, 32),
      root = path.join(
        prepared.directory,
        "case-" + observationDigest(context),
      ),
      access = recipe.id.startsWith("access."),
      files = recipe.group === "files",
      git = recipe.id.startsWith("git."),
      release = recipe.group === "release",
      payload = access
        ? "access-fixture"
        : files
          ? "file-helper"
          : git
            ? "git-fixture"
            : ["ownership.literal", "ownership.storage"].includes(recipe.id)
              ? "argv-fixture"
              : "ownership-fixture",
      assets = [pins("launcher"), pins(payload)],
      request = {
        schemaVersion: 3,
        candidateSha: prepared.job.candidateSha,
        nonce,
        restrictingSid: restricting,
        custody: root + "\\custody",
        storage: root + "\\storage",
        workspace: root + "\\storage\\work",
        launcher: { ...assets[0], path: root + "\\custody\\launcher.exe" },
        executable: {
          ...assets[1],
          path:
            root +
            "\\storage\\" +
            (files
              ? "file-helper.exe"
              : git
                ? "git-fixture.exe"
                : "payload.exe"),
          parser: "msvc-ucrt-wmain-v1",
        },
        policy: { path: root + "\\custody\\policy", sha256: null },
        bindings: {
          source: sourceSha256,
          system: provisionSha256,
          closure: context.closureSha256,
          policy: null,
        },
      },
      entries = [
        prepared.directory,
        root,
        request.custody,
        request.storage,
        request.workspace,
      ].map((file) => ({
        kind: "directory",
        path: file,
        sha256: null,
        signatureSha256: null,
      }));
    entries.push(
      ...[request.launcher, request.executable].map(
        ({ parser: _parser, ...image }) => ({ kind: "helper", ...image }),
      ),
      ...assets.map((image) => ({ kind: "helper", ...image })),
    );
    const uploads = [],
      operationAssets = [],
      addPin = (kind, file, pin) => {
        let index = entries.findIndex(
          (entry) => entry.path.toLowerCase() === file.toLowerCase(),
        );
        if (index < 0) {
          index = entries.length;
          entries.push({
            kind,
            path: file,
            sha256: pin?.sha256 ?? null,
            signatureSha256: pin?.signatureSha256 ?? null,
          });
        }
        return index;
      },
      add = (kind, file, bytes) => {
        const index = addPin(
          kind,
          file,
          bytes ? { sha256: digest(bytes) } : null,
        );
        let source = null;
        if (bytes) {
          const pin = {
            path: path.join(
              prepared.directory,
              `windows-experiment-asset-${assetSequence++}.json`,
            ),
            sha256: digest(bytes),
          };
          source = addPin(kind, pin.path, pin);
          uploads.push({ ...pin, bytes });
        }
        operationAssets.push({ index, source });
        return index;
      },
      imageAsset = (file, image) => {
        const index = addPin("image", file, image),
          source = addPin("image", image.path, image);
        operationAssets.push({ index, source });
        return index;
      };
    const common = [
      "custody-reader",
      "custody-bridge",
      "policy-helper",
      "observer-helper",
      "git-policy",
    ].map((name) => addPin("helper", pins(name).path, pins(name)));
    for (const source of prepared.bootstrap.sources)
      addPin("data", source.path, source);
    addPin("sdk", sdk.file, sdk);
    addPin("directory", prepared.output);
    let input = request,
      parameters,
      slots,
      accessData;
    const identities = [
      rule("account", "sid", [["policy", "accountSid"]]),
      rule("restricting", "sid", [
        ["launch", "request", "restrictingSid"],
        ["policy", "restrictingSid"],
      ]),
    ];
    if (access) {
      const runtime = [
          {
            path: request.executable.path,
            sha256: request.executable.sha256,
            bindingSha256: provisionSha256,
          },
        ],
        runtimeAssets = [];
      // Preserve direct stock targets for access isolation and every private
      // dependency; omitted stock import admission does not remove these copies.
      for (const image of dependencies.payload.slice(1)) {
        const target = imageAsset(
            request.storage + "\\" + path.basename(image.path),
            image,
          ),
          source = operationAssets.at(-1).source;
        runtimeAssets.push({ target, source });
        runtime.push({
          path: entries[target].path,
          sha256: image.sha256,
          bindingSha256: provisionSha256,
        });
      }
      runtime.sort((a, b) =>
        a.path < b.path ? -1 : a.path === b.path ? 0 : 1,
      );
      const endpoints = ["v4", "v6"].flatMap((family, i) =>
          ["tcp", "udp"].map((protocol, j) => ({
            family,
            protocol,
            clientPort: 49152 + i * 4 + j * 2,
            serverPort: 49153 + i * 4 + j * 2,
          })),
        ),
        versions = [
          { id: 4656, versions: [1] },
          { id: 4663, versions: [1] },
          { id: 5152, versions: [0, 1] },
          { id: 5156, versions: [1] },
          { id: 5157, versions: [1] },
        ],
        expectation = {
          purpose: "experiment",
          schemaVersion: 1,
          candidateSha: prepared.job.candidateSha,
          contextSha256: observationDigest(context),
          sourceSha256,
          profile: recipe.profile,
          disposable: true,
          runtimeSha256: observationDigest(runtime),
          audit: {
            pins: {
              manifestSha256: observationDigest({
                context,
                sourceSha256,
                versions,
              }),
              imageSha256: helper("observer-helper").sha256,
              sourceSha256: helper("observer-helper").sourceSha256,
              abiSha256: observation.observation.expected.sdk.sha256,
            },
            mapping: {
              sdkSha256: observation.observation.expected.sdk.sha256,
              abiSha256: observation.observation.expected.sdk.sha256,
              versions,
              mappingSha256: observationDigest(versions),
            },
          },
        },
        pin = {
          path: path.join(
            prepared.directory,
            `windows-experiment-access-${nonce}.json`,
          ),
          sha256: digest(Buffer.from(JSON.stringify(expectation) + "\n")),
        };
      await native.write(path.basename(pin.path), expectation);
      input = {
        purpose: "experiment",
        request,
        accountSid: sid,
        profile: recipe.profile,
        disposable: true,
        runtime,
        endpoints,
        bindingSha256: pin.sha256,
      };
      for (const object of buildWindowsPolicy(input).manifest.objects.filter(
        ({ name }) => name !== "registry",
      ))
        if (!entries.some((entry) => entry.path === object.path))
          addPin(
            ["metadata", "checkout", "configuration", "credentials"].includes(
              object.name,
            )
              ? "directory"
              : object.name === "owned"
                ? "mutable"
                : "data",
            object.path,
            ["metadata", "checkout", "configuration", "credentials"].includes(
              object.name,
            )
              ? null
              : {
                  sha256: digest(
                    Buffer.from(
                      object.name === "pointer"
                        ? "gitdir: " +
                            request.storage.replaceAll("\\", "/") +
                            "/metadata\n"
                        : nonce,
                    ),
                  ),
                },
          );
      accessData = { expectation: pin, runtimeAssets };
      const { request: _request, ...rest } = input;
      parameters = rest;
      parameters.accountSid = { binding: "account" };
      identities[1].paths = [["launch", "request", "restrictingSid"]];
    } else if (files || git || release) {
      const outside = add("directory", root + "\\outside");
      add(
        "data",
        root + "\\outside\\sentinel",
        Buffer.from("unchanged sentinel"),
      );
      parameters = {
        kind: files
          ? "windows-files"
          : release
            ? "windows-release"
            : "windows-git",
        ...(files || release
          ? { authority: "system-only" }
          : { grant: recipe.id === "git.fixed" ? "commit" : "ordinary" }),
        accountSid: { binding: "account" },
        restrictingSid: { binding: "restricting" },
        inventorySha256: null,
      };
      if (files) {
        const fileRoot = add("directory", request.custody + "\\files"),
          alias = common[0];
        // The preparation observer exclusively created this System-private
        // directory and observed its distinct volume; no pre-existing root is adopted.
        const foreignPath = foreignVolume.file;
        const foreign = addPin("directory", foreignPath);
        input = {
          purpose: "experiment",
          request,
          base: identity,
          root: identity,
          bindingSha256: provisionSha256,
        };
        parameters.base = { identitySha256: { binding: "base" } };
        parameters.root = { identitySha256: { binding: "root" } };
        for (const key of ["base", "root"])
          identities.push(
            rule(key, "custody", [["policy", key, "identitySha256"]]),
          );
        slots = {
          base: 2,
          root: fileRoot,
          outside,
          alias,
          foreign,
          loader: [],
        };
      } else if (release) {
        input = {
          purpose: "experiment",
          request,
          bindingSha256: provisionSha256,
        };
        slots = {
          components: prepared.helpers.map((image) => ({
            id: image.name,
            index: addPin("helper", image.path, image),
          })),
          loader: [],
        };
      } else {
        const gitImage = imageAsset(
            request.storage + "\\git.exe",
            gitRuntime[0],
          ),
          metadata = add("directory", request.storage + "\\metadata"),
          hooks = add("directory", request.storage + "\\hooks"),
          repository = gitRepository(add, request);
        input = {
          purpose: "experiment",
          request,
          git: {
            path: entries[gitImage].path,
            sha256: entries[gitImage].sha256,
            signatureSha256: entries[gitImage].signatureSha256,
          },
          metadata: entries[metadata].path,
          hooks: entries[hooks].path,
          parent: repository.parent,
          accountSid: sid,
          bindingSha256: provisionSha256,
        };
        for (const image of gitRuntime
          .slice(1)
          .filter(
            (image) => !/^[A-Z]:\\Windows\\System32\\/iu.test(image.path),
          ))
          imageAsset(request.storage + "\\" + path.basename(image.path), image);
        slots = {
          git: gitImage,
          metadata,
          hooks,
          outside,
          policyHelper: common[4],
          policyObjects: [metadata, hooks, ...repository.objects],
          loader: [],
        };
      }
    } else {
      parameters = {
        kind: "windows-ownership",
        processLimit: 32,
        network: "deny-all",
        accountSid: { binding: "account" },
        restrictingSid: { binding: "restricting" },
        objects: Array.from({ length: 6 }, (_, i) => ({
          identitySha256: { binding: "object." + i },
          mask: [0, 0, 0x120020, 0x12019f, 0, 0x1200a9][i],
        })),
      };
      for (let i = 0; i < 6; i++)
        identities.push(
          rule("object." + i, "custody", [
            ["policy", "objects", i, "identitySha256"],
          ]),
        );
    }
    // Case image/import inventories use actual native resolution captured above.
    if (slots) {
      const roots = files
          ? [5, 6, slots.alias]
          : release
            ? slots.components.map(({ index }) => index)
            : [5, 6, slots.git, slots.policyHelper],
        byPath = new Map();
      for (const index of roots)
        byPath.set(entries[index].path.toLowerCase(), index);
      if (git)
        for (const image of gitRuntime)
          if (!/^[A-Z]:\\Windows\\System32\\/iu.test(image.path)) {
            const index = entries.findIndex(
              (entry) =>
                entry.path ===
                request.storage + "\\" + path.basename(image.path),
            );
            requireObservation(index >= 0);
            byPath.set(image.path.toLowerCase(), index);
          }
      const loader = roots.map((index) => ({
        index,
        imports: git && index === slots.git ? [] : null,
      }));
      for (let i = 0; i < loader.length; i++) {
        if (loader[i].imports === null) continue;
        const entry = entries[loader[i].index],
          original =
            loader[i].index === slots.git
              ? gitRuntime[0].path
              : entry.path.startsWith(request.storage + "\\")
                ? gitRuntime.find(
                    (image) =>
                      path.basename(image.path) === path.basename(entry.path),
                  )?.path
                : entry.path,
          image = gitRuntime.find(
            (image) => image.path.toLowerCase() === original.toLowerCase(),
          );
        requireObservation(image && Array.isArray(image.imports));
        for (const imported of image.imports) {
          const dependency = gitRuntime.find(
            (image) => image.path.toLowerCase() === imported.path.toLowerCase(),
          );
          requireObservation(dependency);
          let index = byPath.get(imported.path.toLowerCase());
          if (index === undefined) {
            index = addPin("image", imported.path, dependency);
            byPath.set(imported.path.toLowerCase(), index);
          }
          if (!loader.some((component) => component.index === index))
            loader.push({
              index,
              imports: dependency.imports === null ? null : [],
            });
          loader[i].imports.push({
            name: imported.name,
            index,
            delay: imported.delay,
          });
        }
      }
      slots.loader = loader;
    }
    for (const upload of uploads)
      await native.writeBytes(path.basename(upload.path), upload.bytes);
    const planBytes = encodeWindowsCustodyPlan({
        purpose: "experiment",
        candidateSha: prepared.job.candidateSha,
        nonce,
        entries,
      }),
      plan = {
        path: path.join(
          prepared.directory,
          `windows-experiment-plan-${nonce}.json`,
        ),
        sha256: digest(planBytes),
      };
    await native.writeBytes(path.basename(plan.path), planBytes);
    if (slots) parameters.inventorySha256 = plan.sha256;
    const args = access
        ? windowsAccessArguments(request)
        : recipe.group === "ownership"
          ? windowsOwnershipArguments(recipe.id, request)
          : WINDOWS_LITERAL_ARGUMENTS,
      template = {
        purpose: "experiment",
        schemaVersion: 1,
        candidateSha: prepared.job.candidateSha,
        platform: "win32",
        sourceSha256,
        provisioningSha256: provisionSha256,
        policy: {
          launch: nativePolicyLaunchData(request, args),
          policy: parameters,
        },
        bindings: identities,
      };
    template.policy.launch.request.restrictingSid = { binding: "restricting" };
    const setup = {
      schemaVersion: 1,
      bindingSha256: provisionSha256,
      input,
      assets,
      endpoints: access
        ? input.endpoints.flatMap(
            ({ family, protocol, clientPort, serverPort }) =>
              [clientPort, serverPort].map((port) => ({
                family,
                protocol,
                port,
              })),
          )
        : [],
    };
    if (access) setup.access = accessData;
    if (slots) {
      const bound = structuredClone(input);
      delete bound.bindingSha256;
      if (files) bound.base = bound.root = null;
      const expectation = {
          schemaVersion: 2,
          contextSha256: observationDigest(context),
          id: recipe.id,
          inputSha256: observationDigest(bound),
          assets: operationAssets,
          slots,
          sourceSha256: helper(release ? "custody-reader" : payload)
            .sourceSha256,
        },
        bytes = Buffer.from(JSON.stringify(expectation) + "\n"),
        pin = {
          path: path.join(
            prepared.directory,
            `windows-experiment-operation-${nonce}.json`,
          ),
          sha256: digest(bytes),
        };
      await native.writeBytes(path.basename(pin.path), bytes);
      input.bindingSha256 = pin.sha256;
      setup.operations = { expectation: pin };
    }
    cases.push({
      id: recipe.id,
      custody: { ...prepared.bootstrap, context, nonce, plan },
      bindings: setup,
    });
    bindings.push({
      id: recipe.id,
      policyBinding: { purpose: "experiment", template, context },
    });
  }
  return { purpose: "experiment", dependencies, cases, bindings, recipes };
}
