import {
  normalizeProviderSpec,
  providerInvocation,
} from "../providers/index.js";
import { admitWindowsLaunch } from "./launch.js";
import {
  normalizeWindowsLaunch,
  windowsLaunchDigest,
  windowsPrivatePath,
  requireWindows,
} from "./protocol.js";

export function windowsProviderLaunch(specification, input) {
  const spec = normalizeProviderSpec(specification),
    invocation = providerInvocation(specification);
  requireWindows(
    spec.platform === "win32" &&
      input.candidateSha === spec.candidateSha &&
      input.nonce === spec.nonce &&
      input.executable.sha256 === spec.entry.sha256,
  );
  const execution = {
    ...invocation.execution,
    environment: {
      ...invocation.execution.environment,
      USERPROFILE: spec.home,
      APPDATA: spec.cache,
      LOCALAPPDATA: spec.cache,
    },
  };
  const request = normalizeWindowsLaunch({
    ...input,
    schemaVersion: 2,
    execution,
  });
  for (const name of [spec.home, spec.cache]) {
    windowsPrivatePath(name);
    requireWindows(
      name.toLowerCase().startsWith(request.storage.toLowerCase() + "\\") &&
        !name
          .toLowerCase()
          .startsWith(request.workspace.toLowerCase() + "\\") &&
        name.toLowerCase() !== request.workspace.toLowerCase(),
    );
  }
  return {
    request,
    arguments: invocation.arguments,
    approvedSha256: windowsLaunchDigest(request, invocation.arguments),
  };
}

export function windowsProviderOwner(input, approvedSha256, effects, options) {
  return {
    assertTransport(value) {
      requireWindows(value.brokerSid === "S-1-5-18");
    },
    async launch(spec, invocation, prepare, signal) {
      requireWindows(!signal.aborted);
      const launch = windowsProviderLaunch(spec, input);
      requireWindows(approvedSha256 === launch.approvedSha256);
      let preparation;
      return admitWindowsLaunch(
        launch.request,
        launch.arguments,
        approvedSha256,
        {
          ...effects,
          async verifyAuthority(request, record) {
            requireWindows(!signal.aborted);
            preparation ??= prepare(structuredClone(record));
            await preparation;
            const authority = await effects.verifyAuthority(request, record);
            requireWindows(!signal.aborted);
            return authority;
          },
        },
        options,
      );
    },
  };
}
