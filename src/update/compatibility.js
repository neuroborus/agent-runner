function version(value) {
  if (typeof value !== "string" || value.length > 128) return null;
  const match =
    /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u.exec(
      value,
    );
  if (!match) return null;
  const prerelease = match[4]?.split(".") ?? [];
  if (
    prerelease.some(
      (part) => /^[0-9]+$/u.test(part) && !/^(0|[1-9][0-9]*)$/u.test(part),
    )
  )
    return null;
  return { numbers: match.slice(1, 4).map(BigInt), prerelease };
}

export const isVersion = (value) => version(value) !== null;
export const isStableVersion = (value) =>
  version(value)?.prerelease.length === 0;

export function compareVersions(left, right) {
  const a = version(left);
  const b = version(right);
  if (!a || !b) throw new Error("Invalid release version.");
  for (let index = 0; index < 3; index++)
    if (a.numbers[index] !== b.numbers[index])
      return a.numbers[index] > b.numbers[index] ? 1 : -1;
  if (!a.prerelease.length || !b.prerelease.length)
    return a.prerelease.length === b.prerelease.length
      ? 0
      : a.prerelease.length
        ? -1
        : 1;
  for (
    let index = 0;
    index < Math.max(a.prerelease.length, b.prerelease.length);
    index++
  ) {
    const x = a.prerelease[index];
    const y = b.prerelease[index];
    if (x === y) continue;
    if (x === undefined || y === undefined) return x === undefined ? -1 : 1;
    const numericX = /^[0-9]+$/u.test(x);
    const numericY = /^[0-9]+$/u.test(y);
    if (numericX !== numericY) return numericX ? -1 : 1;
    return (numericX ? BigInt(x) > BigInt(y) : x > y) ? 1 : -1;
  }
  return 0;
}

function contract(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join() !==
      "configurationVersion,pipelines,runStateVersion,runnerVersion,schemaVersion" ||
    value.schemaVersion !== 1 ||
    ![
      value.configurationVersion,
      value.runnerVersion,
      value.runStateVersion,
    ].every((number) => Number.isSafeInteger(number) && number > 0) ||
    !value.pipelines ||
    typeof value.pipelines !== "object" ||
    Array.isArray(value.pipelines) ||
    Object.keys(value.pipelines).length > 32 ||
    Object.entries(value.pipelines).some(
      ([id, number]) =>
        !/^[a-z][a-z0-9-]{0,63}$/u.test(id) ||
        !Number.isSafeInteger(number) ||
        number < 1,
    )
  )
    throw new Error("Release compatibility metadata is unavailable.");
  return value;
}

export function releaseCompatibility(
  current,
  available,
  nodeVersion,
  configurationVersion,
  runtime,
) {
  const from = contract(current.agentRunnerCompatibility);
  const to = contract(available.agentRunnerCompatibility);
  const range = /^>=([1-9][0-9]{0,2}) <([1-9][0-9]{0,2})$/u.exec(
    available.engines?.node ?? "",
  );
  const node = version(nodeVersion.replace(/^v/u, ""));
  if (!range || Number(range[1]) >= Number(range[2]) || !node)
    throw new Error("Release Node compatibility metadata is unavailable.");
  const pipelineEntries = (value) =>
    JSON.stringify(
      Object.entries(value.pipelines).sort(([a], [b]) =>
        a < b ? -1 : a > b ? 1 : 0,
      ),
    );
  return Object.freeze({
    scope: "runtime-contract",
    node:
      node.numbers[0] >= BigInt(range[1]) && node.numbers[0] < BigInt(range[2]),
    configuration:
      from.configurationVersion === configurationVersion &&
      to.configurationVersion === configurationVersion,
    state:
      from.runnerVersion === runtime.runnerVersion &&
      from.runStateVersion === runtime.runStateVersion &&
      to.runnerVersion === runtime.runnerVersion &&
      to.runStateVersion === runtime.runStateVersion &&
      pipelineEntries(from) === pipelineEntries(to),
  });
}
