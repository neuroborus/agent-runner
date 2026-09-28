import { resolve } from "node:path";

// Fixed mount root from STORAGE_PATHS in src/trusted-validation/resources.js.
const TRUSTED_MOUNT_ROOT = "/run/agent-runner";

function isReservedRoot(root) {
  const path = resolve(root);
  return (
    path === TRUSTED_MOUNT_ROOT || path.startsWith(`${TRUSTED_MOUNT_ROOT}/`)
  );
}

export function temporaryRoots({ override, runtimeRoot, systemRoot }) {
  if (override) return [resolve(override)];

  const roots =
    runtimeRoot && !isReservedRoot(runtimeRoot) ? [runtimeRoot] : [];
  roots.push(isReservedRoot(systemRoot) ? "/tmp" : systemRoot);
  return roots;
}
