import assert from "node:assert/strict";
import test from "node:test";

import { Client, InMemoryTransport } from "@modelcontextprotocol/client";

import { createMcpServer } from "../../src/mcp/index.js";

test("MCP discovers and validates portable effort before dispatch", async (t) => {
  const calls = [];
  const server = createMcpServer({
    issueReportingEnabled: false,
    control: {
      async runStart(input) {
        calls.push(input);
        return { runId: "saved-run" };
      },
    },
  });
  const client = new Client({ name: "effort-test", version: "1.0.0" });
  const [clientTransport, serverTransport] =
    InMemoryTransport.createLinkedPair();
  t.after(() => client.close());
  t.after(() => server.close());
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  const start = (await client.listTools()).tools.find(
    ({ name }) => name === "run_start",
  );
  const values = ["current", "low", "medium", "high", "xhigh"];
  assert.deepEqual(start.inputSchema.properties.effort.enum, values);
  assert.deepEqual(
    start.inputSchema.properties.roleOverrides.additionalProperties.properties
      .effort.enum,
    values,
  );
  assert.match(start.description, /effort separately from model/u);
  assert.match(
    start.inputSchema.properties.effort.description,
    /current retains/u,
  );
  const input = {
    idempotencyKey: "effort-start",
    pipelineId: "plan-execution",
    projectPath: "/project",
    taskPath: "/task",
    mode: "lazy",
  };
  for (const effort of values) {
    const response = await client.callTool({
      name: "run_start",
      arguments: { ...input, effort, roleOverrides: { worker: { effort } } },
    });
    assert.notEqual(response.isError, true);
    assert.equal(calls.at(-1).effort, effort);
    assert.equal(calls.at(-1).roleOverrides.worker.effort, effort);
  }
  for (const effort of [
    null,
    1,
    "",
    "max",
    "HIGH",
    " high",
    "gpt-5.6-sol xhigh",
  ]) {
    for (const override of [
      { effort },
      { roleOverrides: { reviewer: { effort } } },
    ]) {
      const response = await client.callTool({
        name: "run_start",
        arguments: { ...input, ...override },
      });
      assert.equal(response.isError, true);
    }
  }
  assert.equal(calls.length, values.length);
});
