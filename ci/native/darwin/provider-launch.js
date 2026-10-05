import { normalizeNativePolicyBinding, verifyNativePolicy } from "../index.js";
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
    requestSha256: darwinLaunchDigest(request, invocation.arguments),
  };
}

export function darwinProviderOwner(input, approvedSha256, effects, options) {
  if (typeof approvedSha256 === "object" && approvedSha256 !== null)
    approvedSha256 = normalizeNativePolicyBinding(approvedSha256);
  return {
    async interrupt(mode, domain, signal) {
      requireDarwin(
        ["cancel", "helper-loss"].includes(mode) &&
          !signal.aborted &&
          typeof effects.interruptProvider === "function",
      );
      return effects.interruptProvider(mode, structuredClone(domain), {
        signal,
      });
    },
    assertTransport(value) {
      requireDarwin(value.brokerUid === 0);
    },
    async launch(spec, invocation, prepare, signal) {
      requireDarwin(!signal.aborted);
      const launch = darwinProviderLaunch(spec, input);
      requireDarwin(
        typeof approvedSha256 === "object" ||
          approvedSha256 === launch.requestSha256,
      );
      let preparation;
      return admitDarwinLaunch(
        launch.request,
        launch.arguments,
        approvedSha256,
        {
          ...effects,
          async verifyAuthority(request, record) {
            requireDarwin(!signal.aborted);
            if (typeof approvedSha256 === "object") {
              requireDarwin(typeof effects.recordPolicy === "function");
              const proof = verifyNativePolicy(
                approvedSha256.template,
                approvedSha256.approval,
                record.provisioning,
                approvedSha256.context,
                record.requestSha256,
                await effects.readPolicy(
                  structuredClone(request),
                  structuredClone(record),
                ),
              );
              await effects.recordPolicy(proof, request.bindings.policy);
            }
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
