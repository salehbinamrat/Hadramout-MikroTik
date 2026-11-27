# User Manager v7 — isolated lab qualification

Status: NOT RUN. This protocol is not a qualification certificate or production authorization. Record exact RouterOS release and compatible User Manager package, platform, authenticated role, pinned endpoint, fixture revision, tested commit, UTC timestamps and reviewer. Use a dedicated isolated router or disposable compatible VM, synthetic users and plans, accounting-enabled lab NAS, no production users or credentials. Verify network separation and backup before any lab mutation. Sanitize traces and hash evidence; do not record passwords, shared secrets or real subscriber identifiers.

| ID | Scenario | Acceptance evidence |
|---|---|---|
| UM7-L01 | Account / family | Exact name and remote ID; v6 never receives UM7 menu commands. |
| UM7-L02 | Service settings | Confirm singleton native API projection and true/false/missing flags, including profiles disabled. |
| UM7-L03 | Assignments | Confirm exact user selector, state literals, end-time representation, multiple assignments and visibility limitations. |
| UM7-L04 | Profile and limitation | Exact profile and limitation IDs, reset schedules, time windows, rate direction and units; do not combine limits without verified semantics. |
| UM7-L05 | Active accounting | Confirm active, ended, session counters and timestamp fields; demonstrate absent accounting and stale records. |
| UM7-L06 | Monitor | Verify native API one-shot completion and precise selector. Require explicit matching .id and name; record actual field projection and whether multiple or anonymous rows can appear. Reject if identity cannot be established. |
| UM7-L07 | Total counters | Compare lab monitor totals against controlled traffic and accounting, including zero, resets, large values, concurrent sessions and missing values. |
| UM7-L08 | Combined read | Verify separate profile and session observations, settings/account drift rejection, failure of second read yields no partial result; no atomic snapshot claim. |
| UM7-L09 | Transport and permissions | Rejected, malformed, disconnected and incomplete reads; bounded deadlines and no automatic write retry. |
| UM7-L10 | Future mutation | Establish exact disabled creation, assignment, activation and readback semantics on lab only; durable one-shot claim and explicit authorization required before any production integration. |

All cases currently NOT RUN. Report PASS/FAIL/NOT RUN with evidence hash, expected and actual behavior and limitations. Do not treat a completed synthetic test as physical qualification. Monitor reader remains qualification-only. No historical consumption, expiry, eligibility or write permission inferred from active sessions or profile state. UM6 lab requirements remain independent. Dependency audit is mandatory at restore; no suppression. CI tooling warning DEP0169 remains to investigate against exact action/runtime source.
