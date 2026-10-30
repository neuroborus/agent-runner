import * as policies from "../index.js";

export const purposeData = (value) =>
  value?.purpose === "experiment" ? { purpose: "experiment" } : {};
export const bindingKey = (value) =>
  value?.purpose === "experiment" ? "bindingSha256" : "reviewSha256";
export const policyPin = (binding) =>
  binding.purpose === "experiment"
    ? policies.observationDigest(binding.template)
    : binding.approval.manifestSha256;
export const normalizePolicyTemplate = (template) =>
  (template.purpose === "experiment"
    ? policies.normalizeExperimentPolicyTemplate
    : policies.normalizeNativePolicyTemplate)(template);
export const materializePolicy = (binding, provisioning) =>
  (binding.purpose === "experiment"
    ? policies.materializeExperimentPolicy
    : policies.materializeNativePolicy)(
    binding.template,
    ...(binding.purpose === "experiment" ? [] : [binding.approval]),
    provisioning,
    binding.context,
  );

// The policy consumers share only purpose selection. Approval and
// observed provisioning remain separate contracts in the shared policy owner.
export function normalizePolicyBinding(value) {
  const binding =
    value?.purpose === "experiment"
      ? policies.normalizeExperimentPolicyBinding(value)
      : policies.normalizeNativePolicyBinding(value);
  if (binding.purpose === "experiment")
    policies.requireObservation(
      binding.context.platform === "darwin" &&
        binding.context.tier === "system",
    );
  return binding;
}
export function assertPolicyLaunchBinding(value, request, args) {
  const binding = normalizePolicyBinding(value);
  return (
    binding.purpose === "experiment"
      ? policies.assertExperimentPolicyLaunchBinding
      : policies.assertNativePolicyLaunchBinding
  )(binding, request, args);
}
export const materializePolicyBinding = (binding, ...args) =>
  (binding.purpose === "experiment"
    ? policies.materializeExperimentPolicyBinding
    : policies.materializeNativePolicyBinding)(binding, ...args);
export const assertPolicyParameters = (binding, ...args) =>
  (binding.purpose === "experiment"
    ? policies.assertExperimentPolicyParameters
    : policies.assertNativePolicyParameters)(binding, ...args);
export const verifyPolicyBinding = (
  binding,
  provisioning,
  requestSha256,
  observed,
) =>
  (binding.purpose === "experiment"
    ? policies.verifyExperimentPolicy
    : policies.verifyNativePolicy)(
    binding.template,
    ...(binding.purpose === "experiment" ? [] : [binding.approval]),
    provisioning,
    binding.context,
    requestSha256,
    observed,
  );
