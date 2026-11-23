import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";

// Restore actual prior bytes after the native replacement, before the real
// service reads them back. Scope the finite interception to this transcript.
export function restoredAppendReadback(t, service, operation, onReplacement) {
  return async (options) => {
    const priorBytes = await fs.readFile(options.transcriptPath);
    const nativeRename = fs.rename;
    let replacements = 0;
    const mockedRename = t.mock.method(fs, "rename", async (from, to) => {
      await nativeRename(from, to);
      if (to !== options.transcriptPath) return;
      assert.equal(++replacements, 1, "Only one native append replacement");
      const resultBytes = await fs.readFile(to);
      assert.notDeepEqual(resultBytes, priorBytes);
      await onReplacement({ priorBytes, resultBytes, transcriptPath: to });
      await fs.writeFile(to, priorBytes);
    });
    syncBuiltinESMExports();
    try {
      const snapshot = await service[operation](options);
      assert.equal(replacements, 1);
      assert.equal(snapshot.content, priorBytes.toString("utf8"));
      return snapshot;
    } finally {
      mockedRename.mock.restore();
      syncBuiltinESMExports();
    }
  };
}
