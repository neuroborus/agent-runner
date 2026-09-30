// Provider-private identities never cross this boundary. Observers receive only
// semantic activity and the number of commands whose completion is still owed.
const TURN_PROGRESS = Object.freeze({
  SEMANTIC: "semantic",
  COMMAND_STARTED: "local-command-started",
  COMMAND_COMPLETED: "local-command-completed",
  TOOL_STARTED: "local-tool-started",
  TOOL_COMPLETED: "local-tool-completed",
});

export function createTurnProgress(onProgress) {
  const commands = new Map();
  let activeCommands = 0;
  function emit(kind) {
    onProgress?.(Object.freeze({ kind, activeCommands }));
  }
  return Object.freeze({
    semantic() {
      emit(TURN_PROGRESS.SEMANTIC);
    },
    start(id, command = true) {
      if (commands.has(id)) return;
      if (commands.size >= 16_384) {
        throw new RangeError("Provider command progress exceeds its bound.");
      }
      commands.set(id, { active: true, command });
      if (command) activeCommands += 1;
      emit(
        command ? TURN_PROGRESS.COMMAND_STARTED : TURN_PROGRESS.TOOL_STARTED,
      );
    },
    complete(id, command) {
      const entry = commands.get(id);
      if (
        entry?.active !== true ||
        (command !== undefined && entry.command !== command)
      )
        return;
      entry.active = false;
      if (entry.command) activeCommands -= 1;
      emit(
        entry.command
          ? TURN_PROGRESS.COMMAND_COMPLETED
          : TURN_PROGRESS.TOOL_COMPLETED,
      );
    },
    retire() {
      // Called only after provider/process retirement, including failed attempts.
      for (const [id, entry] of commands) {
        if (entry.active) this.complete(id);
      }
      commands.clear();
    },
  });
}
