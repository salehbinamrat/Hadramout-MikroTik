# User Manager v6 — isolated lab qualification

Status: NOT RUN. This protocol records required evidence, not a qualification certificate or authorization. Target: RouterOS 6.49.19 with actual compatible User Manager package. Each other supported build needs its own evidence. The v7 user-profile menu is not a v6 contract. See ADR-0003 legacy observations. Do not copy commands from community reports into a live dispatcher.

## Preconditions
- Dedicated isolated lab router (or disposable compatible VM); no real subscribers, production RADIUS/NAS, or production credentials. Verify separation and backup before changes. Stop if separation is uncertain.
- Record exact RouterOS/package versions, architecture, lab fixture revision, tested commit, UTC timestamps, operator and test reviewer. Verify TLS pin and authenticated user permissions. Use synthetic account and profile names and unique reservation marker.
- Use vendor-supported console/API help and sanitized actual API request/reply traces to determine exact command, selectors, parameters and response semantics. Never infer assignment identity from a numeric CLI row index.
- Do not expose passwords, session secrets, raw subscriber records or keys in evidence. Preserve before/after sanitized projections, expected results, actual results, and SHA-256 of evidence files.

## Required cases (all currently unverified)
| ID | Scenario | Acceptance evidence |
|---|---|---|
| UM6-L01 | Disabled creation | Exact remote ID, customer, username, unique marker and disabled state; no usable login or unintended assignment. |
| UM6-L02 | Identity collision | Duplicate or wrong-owner account/profile cannot mutate unrelated records. |
| UM6-L03 | Assignment visibility | Identify complete assigned, queued and inactive profiles, including cases with empty actual-profile; demonstrate whether API permissions can conceal rows. |
| UM6-L04 | Link semantics | Prove exact selectors and whether link and activate are atomic/combined or separable; verify disabled account stays disabled and validity/usage effects. |
| UM6-L05 | Existing intended and conflicting assignment | No duplicate or replacement; before/after exact identities and counts. |
| UM6-L06 | Trap, fatal, disconnect before and after command | Treat uncertain results as non-rearmable; no automatic resend, no deletion; review retained identity and assignment state. |
| UM6-L07 | Interrupted local persistence / restart | Durable claim remains; cannot rearm or lose evidence through restore. |
| UM6-L08 | Separate enable/activation semantics | Verify explicit authorization, exact identity, expiration/usage start and successful synthetic login; no change to unrelated accounts. |
| UM6-L09 | Concurrency and scope changes | Quiesce external changes; test concurrent claims, stale profile selection and changed local relationships; no cross-router operation. |
| UM6-L10 | Privilege limitations | Incomplete visibility, denied reads, malformed/ambiguous replies cannot authorize writes. |
| UM6-L11 | Controlled batch | Verify isolated synthetic small batch, correct counts, uncertain items retained separately, no print eligibility inferred from acknowledgement. |

For each case record PASS, FAIL or NOT RUN, supporting trace hash, exact observed behavior and any limitation. A missing artifact or unknown result is NOT RUN, not PASS. A lab pass is not production permission; actor authorization, managed generation, exclusive session, restore protection and final explicit product acceptance remain required. Until full assignment visibility and safe mutation semantics are established, keep production mutation disabled. If the legacy command combines link and activation, revise the lifecycle explicitly rather than pretending two operations are separable.

## Local review queue
P16c.4b.2c provides bounded local pages and counts for all retained profile-link attempts on one router, including drifted rows. Every attempt still requires review; neither an acknowledgement nor a visible intended profile proves assignment or eligibility. Keyset pages are individually consistent snapshots, not a frozen multi-page export. Validate scale with measured 10,000-record workloads before claiming performance.


## Synthetic local scale check
P16c.4b.2d adds a 10,000-row bulk synthetic fixture with real database constraints and triggers enabled, 10 deliberate local identity drifts, and one prepared seed excluded from the queue. Verify all 20 pages and exact state totals. Fixture envelopes are deliberately unusable placeholders, not real encrypted passwords; this tests metadata review only, not credential handling or creation throughput. Record elapsed review time (excluding setup) when the test runs. No hardware latency SLA or live-router qualification is inferred. The existing separate router-isolation regression remains mandatory.
