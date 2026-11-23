import { rename, writeFile } from "node:fs/promises";

import {
  createClarificationService,
  createRunner,
  createRunStore,
} from "../../src/index.js";
import { configurationLoader, createAdapter } from "./runner.js";

const [stateRoot, runId, receiptPath] = process.argv.slice(2);
const service = createClarificationService({ interactive: false });
const runner = createRunner({
  runStore: createRunStore({ stateRoot }),
  loadConfiguration: configurationLoader(),
  adapters: { codex: createAdapter({ questionFirst: true }) },
  clarifications: {
    ...service,
    async appendQuestionRound(options) {
      await service.appendQuestionRound(options);
      // The parent kills this owner after verified replacement but before the
      // hash/count/editor transition. Keep stdin open instead of sleeping.
      process.stdin.resume();
      await writeFile(`${receiptPath}.tmp`, "append-readback\n");
      await rename(`${receiptPath}.tmp`, receiptPath);
      await new Promise(() => {});
    },
  },
});
await runner.resume({ runId });
