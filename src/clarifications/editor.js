import { spawn } from "node:child_process";

import { ClarificationError } from "./files.js";

function parseEditorCommand(command) {
  const argumentsList = [];
  let current = "";
  let quote = null;
  let escaped = false;
  let started = false;

  for (const character of command) {
    if (escaped) {
      current += character;
      escaped = false;
      started = true;
    } else if (character === "\\" && quote !== "'") {
      escaped = true;
      started = true;
    } else if (quote !== null) {
      if (character === quote) {
        quote = null;
      } else {
        current += character;
      }
      started = true;
    } else if (character === "'" || character === '"') {
      quote = character;
      started = true;
    } else if (/\s/u.test(character)) {
      if (started) {
        argumentsList.push(current);
        current = "";
        started = false;
      }
    } else {
      current += character;
      started = true;
    }
  }

  if (escaped || quote !== null) {
    throw new ClarificationError("Editor command contains invalid quoting.", {
      code: "ERR_INVALID_EDITOR_COMMAND",
    });
  }
  if (started) {
    argumentsList.push(current);
  }
  if (argumentsList.length === 0 || argumentsList[0].length === 0) {
    throw new ClarificationError("Editor command must name an executable.", {
      code: "ERR_INVALID_EDITOR_COMMAND",
    });
  }
  return argumentsList;
}

export async function defaultLaunchEditor(command, transcriptPath) {
  const [executable, ...argumentsList] = parseEditorCommand(command);
  await new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(executable, [...argumentsList, transcriptPath], {
      stdio: "inherit",
    });
    child.once("error", (cause) =>
      rejectPromise(
        new ClarificationError("Cannot launch the configured editor.", {
          cause,
          code: "ERR_EDITOR_UNAVAILABLE",
        }),
      ),
    );
    child.once("exit", () => resolvePromise());
  });
}

export function editorCandidates(env) {
  const candidates = [];
  for (const name of ["VISUAL", "EDITOR"]) {
    const value = env?.[name];
    if (typeof value !== "string") {
      continue;
    }
    const command = value.trim();
    if (
      command.length === 0 ||
      value.length > 4_096 ||
      /[\0\r\n]/u.test(value)
    ) {
      continue;
    }
    if (!candidates.includes(command)) {
      candidates.push(command);
    }
  }
  return candidates;
}
