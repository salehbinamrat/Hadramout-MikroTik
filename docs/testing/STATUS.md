# Current evidence
- PR #1 merged d3666127acc9adc172738d654b1036fb3a0ec60a; Core 45851610712 / Release 45851610482 passed.
- PR #2 merged 75e7778a913528c0c7fc3540e3958c407916815f; Core 45852471045 / Release 45852470926 passed.
- PR #3 merged a3bcf4f4cb549d91dea8a2ad6bfe4ca0fcd5cbff; Core 45853570606 / Release 45853570539 passed.
- PR #4 merged b46e67bb926844c8e3d2dfe4b1df2b485d208c2f; Core 45854378233 / Release 45854378337 passed on 9ac746e67f478d18b25ead09881f3aa0cc30f62d. Artifact 15136135801. P09 hosted credential tests and x86/x64 probes passed.
- P10 initial snapshot/recovery-candidate/audit slice proposed; 11 tests and published probe. CI pending. Live activation, actor attribution, complete audit coverage, encrypted portable backups, cross-account re-entry/rekey policy, retention and scheduling remain open; no live restore.
- P01 deeper per-feature audit; physical Windows, RouterOS, printers; hard-kill, power-loss and disk-full tests pending. main remains unprotected; exact-head manual gate enforced. No production DB or real router changes.
