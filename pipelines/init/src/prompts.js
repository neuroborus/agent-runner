export const INIT_INSTRUCTIONS = `Review an infrastructure setup proposal, not a product implementation.
Every turn is read-only, including CHECK_AND_FIX. Return structured proposal content;
never publish files, edit ignore rules, stage, commit, alter Git controls or start another pipeline.
Inspect actual project instructions, validation commands, configured artifacts, existing
configuration, skills and guidance. Use repository evidence before asking material questions.
Destination configuration is hashed setup input/output, never this run's live configuration.
Preserve existing skills and useful local instructions. External setup permits zero target writes,
pointer files, ignore changes or global prerequisites. Reuse an unambiguous target-bound setup;
never merge competing placements, relocate resources or grant provider/global authority.
Do not delegate. Ask questions only in CLARIFY. A later material product decision must use
the owning runner's exceptional decision protocol; ordinary review findings return to revision.`;

export const PHASE_INSTRUCTIONS = Object.freeze({
  CLARIFY:
    "Resolve material setup scope and explicit placement separately from review mode. Return READY, QUESTIONS or BLOCKED. Competing placements require explicit selection before closure.",
  PROPOSE:
    "Return a complete minimal proposal with exact destinations, inspected prior hashes, proposed content and actual required checks. Preserve unrelated settings and existing skills. Integrated publication appends only necessary nonduplicate ignore exclusions, including exact publication temporaries. Use the supplied integrated finalization template with the actual ordered checks; select its exact path in both execution and polishing configuration. Existing skills remain byte-for-byte unchanged; their adjacent RUNNER.md preserves substantive checks while deferring staging and commit preparation to the owning pipeline boundary. Guidance is proposed now and published separately after prerequisites.",
  CHECK_AND_FIX:
    "Inspect and correct the complete durable proposal. Return its complete structured replacement even when unchanged. Do not write the proposed files.",
  CLEAN_CONFIRM:
    "In this distinct read-only turn inspect the exact proposal and its input bindings. Return CLEAN only with no findings; otherwise return concrete FINDINGS for the Planner.",
  REVIEW:
    "Independently review the exact proposal, complete setup requirements, actual checks and safety boundaries. Return CLEAN or concrete FINDINGS. Revisions invalidate dependent approvals.",
});
