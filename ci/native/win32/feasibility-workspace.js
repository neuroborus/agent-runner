import { createHash } from "node:crypto";

const need = (value) => {
  if (!value) throw new Error("Incomplete held Windows workspace observation");
};
const hash = (value) =>
  createHash("sha256").update(JSON.stringify(value)).digest("hex");

export function windowsFeasibilityWorkspaceLaunch(role, args) {
  return (
    role === "launch" &&
    args.length === 10 &&
    ((args[0] === "null-probe" &&
      args[2] === "null-probe" &&
      args[7] === "workspace-rooted") ||
      (["read", "edit"].includes(args[0]) &&
        args[2] === "bundle" &&
        args[7] === args[0]))
  );
}

/** Private resource owner only. Callers retain payload operations and receipts. */
export function createWindowsFeasibilityWorkspace(caseId, effects) {
  need(["read", "edit", "null-probe"].includes(caseId));
  // Reuse the caller's validators without joining the platform index cycle.
  const { normalizeWindowsIdentity, sameWindowsIdentity } = effects;
  const acquisitions = { mappingPossible: false };
  let run, mapper, before, binding, holderIdentity, custody, payloadAssignment;
  let launchAttempted = false,
    payloadReleased = false,
    gitReleased = false;
  let gitAdmitted = false,
    gitReady = false,
    rows = 0,
    controllerBefore,
    controllerAfter,
    settled = false;
  const events = [];
  const record = (row, capture) => {
    events.push(row);
    capture?.(row);
  };
  const processRetired = async ({ pid, creationTime }) => {
    const witness = await effects.native(
      "process-retired",
      String(pid),
      creationTime,
    );
    need(witness.retired === true);
  };
  const readMap = async (terminal, capture) => {
    for (;;) {
      need(rows++ < 192);
      const row = await mapper.next();
      record(row, capture);
      if (row.event === "null-owner") {
        normalizeWindowsIdentity(row.owner);
        need(!holderIdentity && row.owner.pid === mapper.pid);
        acquisitions.holderIdentity = holderIdentity = row.owner;
      }
      if (row.event === "null-controller") {
        if (row.phase === "before") controllerBefore = row;
        if (row.phase === "after") controllerAfter = row;
      }
      if (row.event === "null-custody") {
        normalizeWindowsIdentity(row.owner);
        normalizeWindowsIdentity(row.child);
        need(
          row.owner.pid === mapper.pid &&
            sameWindowsIdentity(row.child, run.receipt.child),
        );
        need(
          [row.job, row.process].every((value) => /^[1-9][0-9]*$/u.test(value)),
        );
        acquisitions.custody = custody = row;
      }
      if (row.event === "null-target-set") {
        need(
          !payloadAssignment &&
            row.target === "payload" &&
            sameWindowsIdentity(row.identity, run.receipt.child),
        );
        acquisitions.payloadAssignment = payloadAssignment = row;
      }
      if (row.event === terminal) return row;
    }
  };
  const owner = {
    caseId,
    acquisitions,
    get settled() {
      return settled;
    },
    get possibleEffects() {
      return launchAttempted && !settled;
    },
    get holderSession() {
      return mapper;
    },
    get proof() {
      return acquisitions.workspaceProof;
    },
    get evidence() {
      return { ...acquisitions, events };
    },
    prepare: async (files, cwdIndex) => {
      need(!before);
      before = files;
      const observation = await effects.native("workspace-proof", caseId);
      acquisitions.trustedWorkspace = observation;
      normalizeWindowsIdentity(observation.verifier);
      const trusted = observation.workspace;
      need(
        observation.event === "workspace-proof" &&
          observation.role === caseId &&
          trusted.identity === files[cwdIndex].identity &&
          /^(?:[a-f0-9]{4}){1,1023}$/u.test(trusted.nativePathUtf16),
      );
      if (caseId !== "null-probe")
        need(
          observation.pipeTargetUtf16 ===
            Buffer.from("\\Device\\NamedPipe", "utf16le")
              .swap16()
              .toString("hex"),
        );
      return trusted;
    },
    launching: () => {
      need(!launchAttempted);
      launchAttempted = true;
    },
    acquired: (partial) => {
      need(!run);
      run = partial;
      acquisitions.receipt = partial.receipt;
    },
    beforeRelease: async (partial, capture) => {
      need(partial === run && partial.admission && !mapper);
      acquisitions.payloadAdmission = partial.admission;
      const trusted = acquisitions.trustedWorkspace.workspace;
      await effects.persist(`${caseId}-workspace-map-possible`, {
        receipt: partial.receipt,
        workspace: trusted,
        possible: true,
      });
      acquisitions.mappingPossible = true;
      mapper = effects.holder([
        ...effects.observerArgs(
          partial.receipt,
          caseId,
          partial.receipt.thread,
        ),
        String(partial.receipt.owner.pid),
        partial.receipt.owner.creationTime,
        "workspace-rooted",
      ]);
      binding = await readMap("null-bound", capture);
      normalizeWindowsIdentity(binding.owner);
      need(
        binding.owner.pid === mapper.pid &&
          binding.caseId === "workspace-rooted" &&
          binding.role === caseId &&
          binding.bound === true &&
          binding.mappedSetup === true &&
          binding.setSucceeded === true &&
          payloadAssignment?.setSucceeded === true &&
          custody,
      );
      need(
        sameWindowsIdentity(binding.owner, holderIdentity) &&
          sameWindowsIdentity(custody.owner, holderIdentity),
      );
      need(JSON.stringify(binding.workspace) === JSON.stringify(trusted));
      if (caseId !== "null-probe")
        need(
          binding.pipeTargetUtf16 ===
            acquisitions.trustedWorkspace.pipeTargetUtf16,
        );
      acquisitions.workspaceProof = {
        trusted,
        held: binding.workspace,
        payloadTarget: payloadAssignment.identity,
        holder: binding.owner,
        trustedVerifier: acquisitions.trustedWorkspace.verifier,
        ready: true,
      };
    },
    releasingPayload: () => {
      need(owner.proof?.ready && !payloadReleased);
      payloadReleased = true;
    },
    beforeGit: async () => {
      need(payloadReleased && !acquisitions.gitPossible);
      await effects.persist(`${caseId}-workspace-git-possible`, {
        receipt: run.receipt,
        possible: true,
      });
      acquisitions.gitPossible = true;
    },
    startedGit: (started) => {
      need(acquisitions.gitPossible && !acquisitions.gitStarted);
      acquisitions.gitStarted = started;
    },
    admittedGit: (admission) => {
      acquisitions.admission = admission;
      normalizeWindowsIdentity(admission.child);
      need(
        admission.admitted === true &&
          sameWindowsIdentity(admission.child, acquisitions.gitStarted.child),
      );
      gitAdmitted = true;
    },
    assignGit: async (capture) => {
      need(gitAdmitted && !acquisitions.gitAssignment);
      await effects.persist(`${caseId}-git-admission`, {
        receipt: run.receipt,
        gitStarted: acquisitions.gitStarted,
        admission: acquisitions.admission,
      });
      mapper.sendTarget(acquisitions.gitStarted);
      const assigned = await readMap("null-target-bound", capture);
      acquisitions.gitAssignment = assigned;
      need(
        assigned.target === "git" &&
          typeof assigned.setSucceeded === "boolean" &&
          typeof assigned.workspaceReady === "boolean",
      );
      if (assigned.setSucceeded)
        need(
          sameWindowsIdentity(
            assigned.identity,
            acquisitions.gitStarted.child,
          ) && !sameWindowsIdentity(assigned.identity, run.receipt.child),
        );
      need(hash(await effects.gitFiles()) === hash(before));
      gitReady = assigned.setSucceeded && assigned.workspaceReady;
      return {
        ...binding,
        bound: gitReady,
        workspaceReady: assigned.workspaceReady,
        payloadAssignment,
        gitAssignment: assigned,
      };
    },
    releasingGit: (release = true) => {
      need(acquisitions.gitStarted && !gitReleased);
      if (release) need(gitReady);
      gitReleased = true;
    },
    retire: async (
      { cancelPayload, cancelGit, closePayload, complete = false },
      capture,
    ) => {
      need(
        !settled &&
          (run || !launchAttempted) &&
          (!acquisitions.mappingPossible || mapper),
      );
      let cancellationFailed = false;
      try {
        if (run && !payloadReleased) await cancelPayload();
        else if (
          acquisitions.gitStarted &&
          !gitReleased &&
          !run.session.refused &&
          cancelGit
        )
          await cancelGit();
      } catch {
        cancellationFailed = true;
      }
      let retirement;
      if (run) {
        const retained = custody && mapper && !mapper.exited && !mapper.refused;
        const completed =
          typeof complete === "function" ? complete() : complete;
        retirement = await effects.native(
          cancellationFailed || (payloadReleased && !completed)
            ? "workspace-cancel"
            : "workspace-settle",
          ...effects.observerArgs(
            retained ? { ...custody, child: run.receipt.child } : run.receipt,
            caseId,
          ),
          "workspace-rooted",
        );
        need(
          retirement.retired === true &&
            retirement.jobEmpty === true &&
            retirement.child?.pid === run.receipt.child.pid &&
            retirement.child.creationTime === run.receipt.child.creationTime,
        );
        normalizeWindowsIdentity(retirement.verifier);
        need(
          ![run.receipt.owner, run.receipt.child, holderIdentity]
            .filter(Boolean)
            .some((identity) =>
              sameWindowsIdentity(identity, retirement.verifier),
            ),
        );
        record({ event: "null-job-retired", ...retirement }, capture);
        await closePayload();
        await processRetired(run.receipt.owner);
        if (gitAdmitted) await processRetired(acquisitions.admission.child);
      }
      let resourcesClosed = !acquisitions.mappingPossible;
      if (mapper) {
        need(holderIdentity);
        mapper.send("Q");
        const resources = await readMap("null-retired", capture);
        await mapper.finish(rows);
        resourcesClosed = resources.resourcesClosed;
        need(resourcesClosed === true);
        effects.releaseSession(mapper);
        await processRetired(holderIdentity);
        need(
          controllerBefore &&
            controllerAfter &&
            hash({ ...controllerBefore, phase: null }) ===
              hash({ ...controllerAfter, phase: null }),
        );
      }
      await effects.absent(`workspace\\${caseId}-null-endpoint`);
      const outsideAfter = await effects.files("outside\\sentinel");
      record({ event: "null-outside", after: outsideAfter }, capture);
      if (before) need(hash(await effects.gitFiles()) === hash(before));
      need(hash(outsideAfter) === hash(effects.outsideBaseline));
      acquisitions.retirement = {
        independent: true,
        jobEmpty: true,
        processRetired: true,
        resourcesClosed,
        endpointAbsent: true,
        holderRetired: true,
        outsideUnchanged: true,
        retirement,
      };
      settled = true;
      return acquisitions.retirement;
    },
  };
  return Object.freeze(owner);
}
