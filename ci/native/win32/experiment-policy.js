import * as policies from "../index.js";

const experiment = (value) => value?.purpose === "experiment";
export const policyPin = (binding) =>
  experiment(binding)
    ? policies.observationDigest(binding.template)
    : binding.approval.manifestSha256;
export const sourcePin = (binding) =>
  experiment(binding)
    ? binding.template.sourceSha256
    : binding.template.sourceReviewSha256;
export const provisioningPin = (binding) =>
  experiment(binding)
    ? binding.template.provisioningSha256
    : binding.template.provisioningReviewSha256;
export const normalizeNativePolicyTemplate = (value) =>
  experiment(value)
    ? policies.normalizeExperimentPolicyTemplate(value)
    : policies.normalizeNativePolicyTemplate(value);
export const normalizeNativePolicyBinding = (value) => {
  const binding = experiment(value)
    ? policies.normalizeExperimentPolicyBinding(value)
    : policies.normalizeNativePolicyBinding(value);
  if (experiment(value))
    policies.requireObservation(
      binding.context.platform === "win32" && binding.context.tier === "system",
    );
  return binding;
};
export const materializeNativePolicy = (
  template,
  approval,
  provisioning,
  context,
) =>
  experiment(template)
    ? policies.materializeExperimentPolicy(template, provisioning, context)
    : policies.materializeNativePolicy(
        template,
        approval,
        provisioning,
        context,
      );
export const verifyNativePolicy = (
  template,
  approval,
  provisioning,
  context,
  request,
  observed,
) =>
  experiment(template)
    ? policies.verifyExperimentPolicy(
        template,
        provisioning,
        context,
        request,
        observed,
      )
    : policies.verifyNativePolicy(
        template,
        approval,
        provisioning,
        context,
        request,
        observed,
      );
export const assertNativePolicyLaunchBinding = (binding, request, args) =>
  experiment(binding)
    ? policies.assertExperimentPolicyLaunchBinding(
        normalizeNativePolicyBinding(binding),
        request,
        args,
      )
    : policies.assertNativePolicyLaunchBinding(binding, request, args);
export const materializeNativePolicyBinding = (
  binding,
  provisioning,
  request,
  args,
) =>
  experiment(binding)
    ? policies.materializeExperimentPolicyBinding(
        normalizeNativePolicyBinding(binding),
        provisioning,
        request,
        args,
      )
    : policies.materializeNativePolicyBinding(
        binding,
        provisioning,
        request,
        args,
      );
export const assertNativePolicyParameters = (
  binding,
  provisioning,
  value,
  args,
) =>
  experiment(binding)
    ? policies.assertExperimentPolicyParameters(
        normalizeNativePolicyBinding(binding),
        provisioning,
        value,
        args,
      )
    : policies.assertNativePolicyParameters(binding, provisioning, value, args);
