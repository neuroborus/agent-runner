import {
  normalizeProviderSpec,
  providerInvocation,
} from "../providers/index.js";
import { admitDarwinLaunch } from "./launch.js";
import {
  darwinLaunchDigest,
  normalizeDarwinLaunch,
  requireDarwin,
} from "./protocol.js";

export function darwinProviderLaunch(specification, input) {
  const spec = normalizeProviderSpec(specification),
    invocation = providerInvocation(specification);
  requireDarwin(
    spec.platform === "darwin" &&
      input.candidateSha === spec.candidateSha &&
      input.nonce === spec.nonce &&
      input.executable.sha256 === spec.entry.sha256,
  );
  const request = normalizeDarwinLaunch({
    ...input,
    schemaVersion: 2,
    execution: invocation.execution,
  });
  requireDarwin(
    [spec.home, spec.cache].every(
      (p) =>
        p.startsWith(request.storage + "/") &&
        !p.startsWith(request.workspace + "/") &&
        p !== request.workspace,
    ),
  );
  return {
    request,
    arguments: invocation.arguments,
    approvedSha256: darwinLaunchDigest(request, invocation.arguments),
  };
}

export function darwinProviderOwner(input, approvedSha256, effects, options) {
  return {
    assertTransport(value) {
      requireDarwin(value.brokerUid === 0);
    },
    async launch(spec, invocation, prepare, signal) {
      requireDarwin(!signal.aborted);
      const launch = darwinProviderLaunch(spec, input);
      requireDarwin(approvedSha256 === launch.approvedSha256);
      let preparation;
      return admitDarwinLaunch(
        launch.request,
        launch.arguments,
        approvedSha256,
        {
          ...effects,
          async verifyAuthority(request, record) {
            requireDarwin(!signal.aborted);
            preparation ??= prepare(structuredClone(record));
            await preparation;
            const authority = await effects.verifyAuthority(request, record);
            requireDarwin(!signal.aborted);
            return authority;
          },
        },
        options,
      );
    },
  };
}

export function darwinProviderInputArguments(input) {
  const request = normalizeDarwinLaunch(input);
  requireDarwin(request.execution);
  return [
    "--verify-provider-inputs",
    String(request.uid),
    String(request.gid),
    request.workspace,
    request.executable.path,
    request.executable.sha256,
    request.executable.cdhash,
    String(request.execution.imageBytes),
  ];
}
