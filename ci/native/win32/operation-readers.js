import {
  observationDigest,
  observationObject,
  requireObservation,
} from "../index.js";
import { digest } from "./protocol.js";
import { decode } from "./custody-protocol.js";

/** Complete held image/API-set and SDK inventories. Approved paths identify
 * inputs; fresh native reads supply their bytes and actual dependency edges. */
export function createWindowsOperationReaders(reader, specification) {
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
        components.flatMap(({ imports }) => imports.map(({ index }) => index)),
      );
    for (const component of components) {
      observationObject(component, ["index", "imports"]);
      requireObservation(
        ["image", "helper"].includes(
          specification.entries[component.index]?.kind,
        ) &&
          Array.isArray(component.imports) &&
          component.imports.length <= 256,
      );
      for (const target of component.imports) {
        observationObject(target, ["name", "index"]);
        requireObservation(
          typeof target.name === "string" &&
            /^[A-Za-z0-9_.-]+\.dll$/iu.test(target.name) &&
            components.some(({ index }) => index === target.index),
        );
      }
      requireObservation(
        new Set(component.imports.map(({ name }) => name.toLowerCase()))
          .size === component.imports.length,
      );
      await read(component.index);
      await reader.signature(component.index);
      const pe = await reader.operation("release-pe", component.index);
      requireObservation(
        pe.complete &&
          (!dlls.has(component.index) || pe.dll) &&
          Array.isArray(pe.imports) &&
          pe.imports.length === component.imports.length,
      );
      requireObservation(
        new Set(pe.imports.map(({ name }) => name.toLowerCase())).size ===
          pe.imports.length,
      );
      for (const imported of pe.imports) {
        observationObject(imported, ["name", "host", "delay"]);
        const target = component.imports.find(
          ({ name }) => name.toLowerCase() === imported.name.toLowerCase(),
        );
        requireObservation(
          target &&
            typeof imported.delay === "boolean" &&
            imported.host.toLowerCase() ===
              specification.entries[target.index].path
                .split("\\")
                .at(-1)
                .toLowerCase(),
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
          for (const target of component.imports) reached.add(target.index);
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
  const runtime = async (subject, image, components) => {
    const actual = await reader.loader(subject, image),
      reached = new Set([image]);
    for (let size = -1; size !== reached.size;) {
      size = reached.size;
      for (const component of components)
        if (reached.has(component.index))
          for (const target of component.imports) reached.add(target.index);
    }
    const indices = [];
    for (const file of actual.loaded) {
      const index = specification.entries.findIndex(
        (entry) =>
          entry.path.toLowerCase() === decode(file.pathHex).toLowerCase(),
      );
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
    requireObservation(indices.length === reached.size);
    requireObservation(
      actual.imports.length ===
        components
          .filter(({ index }) => reached.has(index))
          .reduce((sum, component) => sum + component.imports.length, 0),
    );
    const edges = new Set();
    for (const edge of actual.imports) {
      const name = Buffer.from(edge.importHex, "hex").toString("ascii");
      const key = `${edge.source}:${name.toLowerCase()}`;
      requireObservation(!edges.has(key));
      edges.add(key);
      const component = components.find(
        ({ index }) => index === indices[edge.source],
      );
      const target = component?.imports.find(
        (value) => value.name.toLowerCase() === name.toLowerCase(),
      );
      requireObservation(target?.index === indices[edge.resolved]);
    }
    return actual;
  };
  return { read, loader, runtime };
}
