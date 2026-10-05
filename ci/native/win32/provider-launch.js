import {
  normalizeProviderSpec,
  providerInvocation,
} from "../providers/index.js";
import { admitWindowsLaunch } from "./launch.js";
import {
  normalizeNativePackageReview,
  nativePackageReviewDigest,
} from "../index.js";
import { normalizeWindowsFileIdentity } from "./files-protocol.js";
import {
  closed,
  hash,
  normalizeWindowsLaunch,
  windowsLaunchDigest,
  windowsPrivatePath,
  requireWindows,
} from "./protocol.js";

/** Native Git for Windows only. Complete member/source/build/ABI/extraction
 * review remains an independent prerequisite; no WSL or PATH fallback grant. */
export function windowsClaudeBash(specification, input, value) {
  const spec = normalizeProviderSpec(specification);
  closed(value, ["root", "review"]);
  const root = windowsPrivatePath(value.root),
    review = normalizeNativePackageReview(value.review, spec.candidateSha);
  const bash = review.files.find((file) => file.path === "usr/bin/bash.exe");
  requireWindows(
    spec.provider === "claude" &&
      spec.platform === "win32" &&
      review.packageId === "git-for-windows" &&
      review.archiveBytes !== null &&
      bash?.executable &&
      Object.values(review.bindings).every((binding) => binding !== null) &&
      nativePackageReviewDigest(review) ===
        spec.review.bindings.dependencies.sha256 &&
      root.toLowerCase().startsWith(input.storage.toLowerCase() + "\\") &&
      [input.workspace, spec.home, spec.cache].every(
        (writable) =>
          !root.toLowerCase().startsWith(writable.toLowerCase() + "\\") &&
          root.toLowerCase() !== writable.toLowerCase() &&
          !writable.toLowerCase().startsWith(root.toLowerCase() + "\\"),
      ),
  );
  return {
    path: root + "\\usr\\bin\\bash.exe",
    sha256: bash.sha256,
    reviewSha256: nativePackageReviewDigest(review),
  };
}

export function assertWindowsClaudeBash(expected, value, request, record) {
  requireWindows(
    value?.independent === true &&
      value.path === expected.path &&
      value.sha256 === expected.sha256 &&
      value.reviewSha256 === expected.reviewSha256 &&
      value.requestSha256 === record.requestSha256 &&
      value.candidateSha === request.candidateSha &&
      value.nonce === request.nonce &&
      hash(value.nativeSha256) &&
      value.held === true &&
      value.revalidated === true &&
      value.noReparse === true &&
      value.links === 1 &&
      value.privateDacl === true &&
      value.readExecuteOnly === true &&
      value.untrustedWritable === false &&
      value.sameTokenJob === true &&
      value.jobSha256 === record.setup.job.heldObjectSha256 &&
      value.noWsl === true &&
      value.noPathFallback === true &&
      value.loaderClosureVerified === true &&
      value.dataOnlyExtractionVerified === true,
  );
  normalizeWindowsFileIdentity(value.identity);
}

export function windowsProviderLaunch(specification, input) {
  const spec = normalizeProviderSpec(specification),
    invocation = providerInvocation(specification);
  const { bash: bashInput, ...launchInput } = input;
  const bash =
    spec.provider === "claude"
      ? windowsClaudeBash(spec, launchInput, bashInput)
      : null;
  requireWindows(spec.provider === "claude" || bashInput === undefined);
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
      ...(bash ? { CLAUDE_CODE_GIT_BASH_PATH: bash.path } : {}),
    },
  };
  const request = normalizeWindowsLaunch({
    ...launchInput,
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
    bash,
    approvedSha256: windowsLaunchDigest(request, invocation.arguments),
  };
}

export function windowsProviderOwner(input, approvedSha256, effects, options) {
  return {
    async interrupt(mode, domain, signal) {
      requireWindows(
        ["cancel", "helper-loss"].includes(mode) &&
          !signal.aborted &&
          typeof effects.interruptProvider === "function",
      );
      return effects.interruptProvider(mode, structuredClone(domain), {
        signal,
      });
    },
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
            if (launch.bash)
              assertWindowsClaudeBash(
                launch.bash,
                authority.gitBash,
                request,
                record,
              );
            requireWindows(!signal.aborted);
            return authority;
          },
        },
        options,
      );
    },
  };
}
