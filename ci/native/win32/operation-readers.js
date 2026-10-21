import {
  observationDigest,
  observationObject,
  requireObservation,
} from "../index.js";
import { digest } from "./protocol.js";
import { decode } from "./custody-protocol.js";

/** Held image, private-import and SDK inventories. Approved paths identify
 * inputs; fresh native reads supply their bytes and actual dependency edges. */
export function createWindowsOperationReaders(
  reader,
  specification,
  purpose = "reviewed",
) {
  requireObservation(["reviewed", "experiment"].includes(purpose));
  const experiment = purpose === "experiment",
    importKey = ({ name, delay }) =>
      name.toLowerCase() + (experiment ? `:${delay}` : "");
  const hosted = (file) =>
    /^[A-Z]:\\Windows\\System32\\[^\\]+\.dll$/iu.test(file);
  const omitted = ({ index, imports }) =>
    experiment &&
    imports === null &&
    (specification.entries[index]?.kind === "helper" ||
      hosted(specification.entries[index]?.path));
  const read = async (index, maximum = 536870912) => {
    const entry = specification.entries[index],
      before = await reader.inspect(index),
      size = await reader.operation("release-build", index);
    requireObservation(
      entry &&
        Number.isSafeInteger(size.bytes) &&
        size.bytes > 0 &&
        size.bytes <= maximum,
    );
    const chunks = [];
    for (let offset = 0; offset < size.bytes; offset += 65536)
      chunks.push(
        await reader.read(index, offset, Math.min(65536, size.bytes - offset)),
      );
    const bytes = Buffer.concat(chunks);
    requireObservation(
      digest(bytes) === entry.sha256 &&
        observationDigest(before) ===
          observationDigest(await reader.inspect(index)),
    );
    return bytes;
  };
  const loader = async (components, roots) => {
    requireObservation(
      Array.isArray(components) &&
        components.length > 0 &&
        components.length <= 128 &&
        new Set(components.map(({ index }) => index)).size ===
          components.length &&
        roots.every((root) => components.some(({ index }) => index === root)),
    );
    const observations = [],
      reached = new Set(roots),
      dlls = new Set(
        components.flatMap(({ imports }) =>
          (imports ?? []).map(({ index }) => index),
        ),
      );
    for (const component of components) {
      observationObject(component, ["index", "imports"]);
      requireObservation(
        ["image", "helper"].includes(
          specification.entries[component.index]?.kind,
        ) &&
          (Array.isArray(component.imports)
            ? component.imports.length <= 256
            : omitted(component)),
      );
      for (const target of component.imports ?? []) {
        observationObject(
          target,
          experiment ? ["name", "index", "delay"] : ["name", "index"],
        );
        requireObservation(
          typeof target.name === "string" &&
            /^[A-Za-z0-9_.-]+\.dll$/iu.test(target.name) &&
            (!experiment || typeof target.delay === "boolean") &&
            components.some(({ index }) => index === target.index),
        );
      }
      requireObservation(
        new Set((component.imports ?? []).map(importKey)).size ===
          (component.imports ?? []).length,
      );
      await read(component.index);
      await reader.signature(component.index);
      const pe = await reader.operation("release-pe", component.index);
      requireObservation(
        pe.complete &&
          (!dlls.has(component.index) || pe.dll) &&
          Array.isArray(pe.imports) &&
          (component.imports === null ||
            pe.imports.length === component.imports.length),
      );
      requireObservation(
        new Set(pe.imports.map(importKey)).size === pe.imports.length,
      );
      for (const imported of pe.imports) {
        observationObject(
          imported,
          experiment ? ["name", "delay"] : ["name", "host", "delay"],
        );
        requireObservation(
          typeof imported.name === "string" &&
            /^[A-Za-z0-9_.-]+\.dll$/iu.test(imported.name) &&
            typeof imported.delay === "boolean",
        );
        if (component.imports === null) continue;
        const target = component.imports.find(
          (value) => importKey(value) === importKey(imported),
        );
        requireObservation(target);
        const entry = specification.entries[target.index],
          basename = entry.path.split("\\").at(-1).toLowerCase();
        // Direct edges name held physical modules, including copied Git DLLs.
        // Aliases must rejoin an independently observed System32 target.
        if (experiment && imported.name.toLowerCase() !== basename) {
          const resolved = await reader.operation(
            "release-import",
            imported.name,
            component.index,
          );
          observationObject(resolved, ["pathHex", "identity", "sha256"]);
          requireObservation(
            decode(resolved.pathHex).toLowerCase() ===
              entry.path.toLowerCase() &&
              resolved.sha256 === entry.sha256 &&
              resolved.identity ===
                (await reader.inspect(target.index)).identity,
          );
        } else
          requireObservation(
            (experiment ? imported.name : imported.host).toLowerCase() ===
              basename,
          );
      }
      observations.push({
        index: component.index,
        identity: (await reader.inspect(component.index)).identity,
        pe,
      });
    }
    for (let size = -1; size !== reached.size;) {
      size = reached.size;
      for (const component of components)
        if (reached.has(component.index))
          for (const target of component.imports ?? [])
            reached.add(target.index);
    }
    requireObservation(reached.size === components.length);
    const build = await reader.buildBindings(),
      sdk = [];
    requireObservation(
      `${build.major}.${build.minor}.${build.build}` === "10.0.26100",
    );
    for (let index = 0; index < specification.entries.length; index++)
      if (specification.entries[index].kind === "sdk") {
        requireObservation(
          specification.entries[index].path.startsWith(
            decode(build.sdkRootHex),
          ),
        );
        sdk.push({ index, sha256: digest(await read(index)) });
      }
    requireObservation(sdk.length > 0);
    return { images: observations, build, sdk };
  };
  const runtime = async (
    observe,
    image,
    components = specification.slots.loader,
  ) => {
    requireObservation(
      Array.isArray(components) &&
        components.some(({ index }) => index === image) &&
        components.every(
          (component) => Array.isArray(component.imports) || omitted(component),
        ),
    );
    const actual = await observe(),
      reached = new Set([image]);
    requireObservation(!experiment || actual.importScope === "private-runtime");
    for (let size = -1; size !== reached.size;) {
      size = reached.size;
      for (const component of components)
        if (reached.has(component.index))
          for (const target of component.imports ?? [])
            reached.add(target.index);
    }
    const indices = [],
      paths = new Set();
    for (const file of actual.loaded) {
      const path = decode(file.pathHex).toLowerCase();
      requireObservation(!paths.has(path));
      paths.add(path);
      const index = specification.entries.findIndex(
        (entry) =>
          entry.path.toLowerCase() === decode(file.pathHex).toLowerCase(),
      );
      if (experiment && !reached.has(index) && hosted(path)) {
        indices.push(-1);
        continue;
      }
      requireObservation(reached.has(index) && !indices.includes(index));
      const entry = specification.entries[index],
        held = await reader.inspect(index);
      requireObservation(
        file.identity === held.identity &&
          file.sha256 === entry.sha256 &&
          file.signatureSha256 === entry.signatureSha256 &&
          file.daclSha256 === held.daclSha256 &&
          file.links === held.links,
      );
      indices.push(index);
    }
    requireObservation(
      [...reached].every((index) => indices.includes(index)) &&
        (experiment || indices.length === reached.size),
    );
    requireObservation(
      actual.imports.length ===
        components
          .filter(({ index }) => reached.has(index))
          .reduce(
            (sum, component) => sum + (component.imports ?? []).length,
            0,
          ),
    );
    const edges = new Set();
    for (const edge of actual.imports) {
      const name = Buffer.from(edge.importHex, "hex").toString("ascii");
      const key = `${edge.source}:${importKey({ name, delay: edge.delay })}`;
      requireObservation(!edges.has(key));
      edges.add(key);
      const component = components.find(
        ({ index }) => index === indices[edge.source],
      );
      const target = component?.imports?.find(
        (value) => importKey(value) === importKey({ name, delay: edge.delay }),
      );
      requireObservation(target?.index === indices[edge.resolved]);
    }
    return actual;
  };
  return {
    read,
    loader,
    runtime: (subject, image, components) =>
      runtime(() => reader.loader(subject, image), image, components),
    async helperRuntime(identity, image) {
      requireObservation(experiment);
      let actual;
      const loaded = await runtime(async () => {
        actual = await reader.observeHelper(identity, image);
        return actual.runtime;
      }, image);
      return { processImage: actual.processImage, runtime: loaded };
    },
  };
}
