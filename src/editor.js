import { spawn } from "node:child_process";

export class EditorError extends Error {
  constructor(message, { cause, code } = {}) {
    super(message, { cause });
    this.name = "EditorError";
    this.code = code;
  }
}

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
    throw new EditorError("Editor command contains invalid quoting.", {
      code: "ERR_INVALID_EDITOR_COMMAND",
    });
  }
  if (started) {
    argumentsList.push(current);
  }
  if (argumentsList.length === 0 || argumentsList[0].length === 0) {
    throw new EditorError("Editor command must name an executable.", {
      code: "ERR_INVALID_EDITOR_COMMAND",
    });
  }
  return argumentsList;
}

export async function defaultLaunchEditor(command, path) {
  const [executable, ...argumentsList] = parseEditorCommand(command);
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(executable, [...argumentsList, path], {
      stdio: "inherit",
    });
    child.once("error", (cause) =>
      rejectPromise(
        new EditorError("Cannot launch the configured editor.", {
          cause,
          code: "ERR_EDITOR_UNAVAILABLE",
        }),
      ),
    );
    child.once("close", (exitCode, signal) =>
      resolvePromise(Object.freeze({ exitCode, signal })),
    );
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

// A launched editor's exit is an outcome, never a reason to open a fallback.
export async function openConfiguredEditor(
  path,
  { env = process.env, launchEditor = defaultLaunchEditor } = {},
) {
  for (const command of editorCandidates(env)) {
    try {
      const outcome = await launchEditor(command, path);
      // Clarification-service injected launchers historically returned no outcome.
      return outcome ?? Object.freeze({ exitCode: 0, signal: null });
    } catch (cause) {
      if (
        cause?.code !== "ENOENT" &&
        !["ERR_EDITOR_UNAVAILABLE", "ERR_INVALID_EDITOR_COMMAND"].includes(
          cause?.code,
        )
      ) {
        throw cause;
      }
    }
  }
  return null;
}
