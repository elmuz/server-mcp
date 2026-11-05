# Server MCP — Current Next-Phase Handoff

**Reviewed revision:** `d8340a8` (`origin/main`)
**Updated:** 2026-11-05
**Review mode:** Static review; no services or tests were run.

This is a short handoff, not a second backlog. **`docs/modernization-plan.md` is the
authoritative project plan**; follow its status, phases, acceptance criteria, and
verification steps. `docs/project-review.md` records current review findings and
recommended improvements.

## Current position

- The current release is `v0.5.0`; the container runtime in modernization plan section 3.8,
  Phase 2, is complete.
- The next in-repository feature is multi-target support (section 3.7). Start with its
  config and target registry phase; preserve existing single-target configuration behavior.
- The author sandbox, workspace isolation, deployer/approval boundary, and end-to-end
  isolation verification remain incomplete deployment work (section 3.8, Phases 3, 3b, 4,
  and 5). A hardened MCP container alone is not a complete boundary for hostile agent code.
- The remaining host-specific prerequisites are tracked in sections 3.5 and 3.6.

## Handoff priorities

1. **For in-repo feature work:** implement multi-target support in the order and scope in
   `docs/modernization-plan.md` section 3.7. Keep target identity explicit in tool routing,
   rate limits, audit records, metrics clients, and tests. Do not accept model-supplied
   hostnames, credentials, or arbitrary paths as target definitions.
2. **Before using with an untrusted author:** complete the separate sandbox and workspace
   isolation work, constrain MCP egress to configured destinations, and add repeatable
   tests that verify the author cannot read MCP secrets and the MCP cannot access the
   author workspace. Track cross-repository deployment work separately from MCP tools.
3. **For review follow-up:** triage the current findings in `docs/project-review.md` and
   move accepted implementation items into the canonical modernization plan before work
   starts. In particular, address output buffering limits and the stated limits of
   best-effort secret redaction.

## Guardrails

- Keep the fixed, validated tool catalog; do not add a generic shell or arbitrary network
  request tool.
- `confirm=true` is a model-supplied interlock, not human approval. Any human approval
  boundary must remain outside the author container.
- Do not share a writable checkout with a host process that executes agent-written files.
  Until workspace isolation lands, use a separate sandbox clone and review approved
  changes before running host-side tests, builds, hooks, or deployment.
- Never commit configuration secrets, tokens, private keys, or host-specific credentials.
- Use the full local and release verification procedures in `docs/modernization-plan.md`
  section 6 for implementation work; this handoff review did not run them.

## Superseded snapshot

The previous version of this document reviewed `81733d2` and included a detailed defect
list and release plan from that point in time. It is superseded: several listed issues
have since been fixed, and the canonical modernization plan now records the project
backlog and release status. Use the current source and linked review documents rather than
reopening old checklist items without revalidation.
