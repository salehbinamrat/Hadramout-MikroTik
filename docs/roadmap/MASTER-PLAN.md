# Master plan v1.0 — 2026-11-26
Do not mark steps complete until evidence exists.

| Phase | Steps | Exit gate |
|---|---|---|
| 1 | P01 reference audit; P02 requirements; P03 SDK/architecture; P04 source baseline; P05 CI | Both checks, four packages, physical target evidence |
| 2 | P06 boundaries; P07 SQLite; P08 transactions/migrations; P09 credentials; P10 audit/backups | Crash, migration, restore tests |
| 3 | P11 library comparison; P12 TLS transport; P13 capability detection; P14 reconnect/cancel; P15 v6/v7 lab | Live operation and interruption tests |
| 4 | P16 UM v6; P17 UM v7; P18 Hotspot; P19 PPPoE; P20 plans/usage/sessions | Correct adapter and actual data |
| 5 | P21 secure generation; P22 uniqueness; P23 batches; P24 reconciliation/resume; P25 archive | 100–10000 batches, no duplicate/lost confirmed vouchers |
| 6 | P26 model; P27 designer; P28 templates/QR; P29 thermal/paper; P30 export | Real printer and RTL fidelity |
| 7 | P31 sales; P32 distributors; P33 POS; P34 accounts; P35 reports | Transaction integrity |
| 8 | P36 multi-router; P37 metrics; P38 discovery; P39 topology; P40 diagnostics/change guard | Bounded polling; safe changes |
| 9 | P41 design; P42 RTL/accessibility; P43 permissions; P44 optional RADIUS; P45 security | Role isolation and offline operation |
| 10 | P46 cleanup; P47 performance; P48 real RouterOS; P49 install/upgrade/restore; P50 release | Full evidence and sign-off |

Every PR: inspect, write regression tests, implement, review, run Windows Core and Windows Release in parallel. Release tests precede packaging. No merge unless both succeed on exact head. Never bypass failures; diagnose root cause. Four packages with SHA256. No live production router changes without approval. No secrets in Git. No runtime web stack or empty placeholder projects.
