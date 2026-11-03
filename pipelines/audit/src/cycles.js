// Only a completed clean pass closes a logical owner's series. Reservations,
// invalid output and reconstruction remain in that same series and budget.
export function cyclePosition(history, number = history.length + 1) {
  const previous = history.slice(0, number - 1);
  const lastClean = previous.findLastIndex(
    ({ outcome }) => outcome === "clean",
  );
  return {
    cycle: previous.filter(({ outcome }) => outcome === "clean").length + 1,
    pass: number - lastClean - 1,
  };
}

export function findingRecheckCycle(
  state,
  number = state.recheckHistory.length,
) {
  const sourcePass =
    state.recheckHistory[number - 1]?.sourcePass ??
    state.pendingBatch.sourcePass;
  const previous = state.recheckHistory
    .slice(0, number - 1)
    .filter((pass) => pass.sourcePass === sourcePass);
  return { sourcePass, ...cyclePosition(previous) };
}

export function recheckRole(state, number = state.recheckHistory.length) {
  return state.settings.mode === "lazy" ||
    (state.settings.mode === "combined" &&
      findingRecheckCycle(state, number).cycle === 1)
    ? "auditor"
    : "reviewer";
}

export function acceptsCleanDiscovery(state, number = state.history.length) {
  const { cycle, pass } = cyclePosition(state.history, number);
  return state.settings.mode !== "combined" || (cycle > 1 && pass === 1);
}

export function acceptsCleanRecheck(
  state,
  number = state.recheckHistory.length,
) {
  if (state.settings.mode !== "combined") return true;
  const { cycle, pass } = findingRecheckCycle(state, number);
  return cycle > 1 && pass === 1;
}
