# Current evidence
- PR #1 merged d3666127acc9adc172738d654b1036fb3a0ec60a; Core 45851610712 / Release 45851610482 passed.
- PR #2 merged 75e7778a913528c0c7fc3540e3958c407916815f; Core 45852471045 / Release 45852470926 passed.
- PR #3 merged a3bcf4f4cb549d91dea8a2ad6bfe4ca0fcd5cbff; Core 45853570606 / Release 45853570539 passed.
- PR #4 merged b46e67bb926844c8e3d2dfe4b1df2b485d208c2f; Core 45854378233 / Release 45854378337 passed.
- PR #5 merged ca51f65541a5e8b9ff8fd9e764d7deb14fd2e345; Core 45855443868 / Release 45855443886 passed on 8f3f2c5980b9f1f8cddc1c9ff1f506e9bb1d0645; artifact 15134878557. P10a hosted snapshot and audit checks passed.
- P10b proposed password-authenticated AES-GCM backup, fixed KDF and strict bounded format, 12 test cases and x86/x64 published probe. CI pending.
- P10 remaining: large streaming backup, secure workspace and crash cleanup, cross-account re-entry/rekey, pre-activation safety snapshot, live activation, current-history preservation, full audit coverage/actor attribution, retention and scheduling. No live restore.
- P01 deeper per-feature audit; physical Windows, RouterOS, printers; hard-kill, power-loss and disk-full tests pending. main remains unprotected; exact-head manual gate enforced. No production DB or real router changes.
