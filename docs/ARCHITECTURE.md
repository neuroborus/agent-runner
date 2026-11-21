# Architecture

Agent Runner is an npm-workspaces monorepo with one root CLI/runtime, shared
commit-plan and custom-plan contracts, and independently owned pipeline workspaces.

Use the [architecture map](architecture/README.md) before changing a runtime boundary.
Read the affected topic and owning pipeline or package contract.

## Dependency Direction

Read [Dependency Direction](architecture/runtime-ownership.md#dependency-direction).

## Root Runner Ownership

Read [Root Runner Ownership](architecture/runtime-ownership.md#root-runner-ownership).

## Pipeline Ownership

Read [pipeline composition](architecture/pipelines/README.md) and
[descriptor ownership](architecture/pipelines/registry.md#pipeline-ownership).

### Historical validation policy stops

Read [Historical validation policy stops](architecture/pipelines/validation-history.md#historical-validation-policy-stops).

## Structured Result Headroom

Read [Structured Result Headroom](architecture/structured-results.md#structured-result-headroom).

## Local application packaging

Read [Local application packaging](architecture/releases/packaging.md#local-application-packaging).

## On-demand release compatibility

Read [On-demand release compatibility](architecture/releases/compatibility.md#on-demand-release-compatibility).

## Exact candidate preparation

Read [Exact candidate preparation](architecture/releases/preparation.md#exact-candidate-preparation).

## Candidate activation and restart

Read [Candidate activation and restart](architecture/releases/activation.md#candidate-activation-and-restart).

## Immutable application startup

Read [Immutable application startup](architecture/startup.md#immutable-application-startup).

### Serialized runtime admission

Read [Serialized runtime admission](architecture/startup.md#serialized-runtime-admission).

## Runner Configuration

Read [Runner Configuration](architecture/configuration.md#runner-configuration).

## Run Lifecycle

Read [Run Lifecycle](architecture/run-lifecycle.md#run-lifecycle).

## Operator Guidance

Read [Operator Guidance](architecture/operator-guidance.md#operator-guidance).

## MCP Control Plane

Read [MCP Control Plane](architecture/mcp/control-plane.md#mcp-control-plane).

### Bounded action-free continuation

Read [Bounded action-free continuation](architecture/mcp/continuation.md).

## External Run State

Read [External Run State](architecture/state/storage.md).

### Provider inactivity deadlines

Read [Provider inactivity deadlines](architecture/recovery/inactivity.md#provider-inactivity-deadlines).

### Durable availability episodes

Read [Durable availability episodes](architecture/recovery/availability.md#durable-availability-episodes).

### Durable authentication-required pauses

Read [Durable authentication-required pauses](architecture/recovery/authentication.md#durable-authentication-required-pauses).

### State-owned operator stop protocol

Read [State-owned operator stop protocol](architecture/recovery/operator-stops.md#state-owned-operator-stop-protocol).

### Bounded ownership-failure diagnostics

Read [Bounded ownership-failure diagnostics](architecture/recovery/ownership-diagnostics.md#bounded-ownership-failure-diagnostics).

### Common envelope and pipeline migrations

Read [Common envelope and pipeline migrations](architecture/migrations/common-envelope.md).

## Agent Context Recovery

Read [Agent Context Recovery](architecture/providers/sessions.md#agent-context-recovery).

### Preparation custody

Read [Preparation custody](architecture/validation/preparation.md#preparation-custody).

## Clarification Lifecycle

Read [Clarification Lifecycle](architecture/clarifications.md#clarification-lifecycle).

## Shared Plan Contracts

Read [Shared Plan Contracts](architecture/shared-plans.md#shared-plan-contracts).

## Global Safety Policy

Read [Global Safety Policy](architecture/safety.md#global-safety-policy).
