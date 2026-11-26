# Current evidence
- PR #1 merged d3666127acc9adc172738d654b1036fb3a0ec60a; Core 45851610712 / Release 45851610482 passed.
- PR #2 merged 75e7778a913528c0c7fc3540e3958c407916815f; Core 45852471045 / Release 45852470926 passed.
- PR #3 merged a3bcf4f4cb549d91dea8a2ad6bfe4ca0fcd5cbff; Core 45853570606 / Release 45853570539 passed.
- PR #4 merged b46e67bb926844c8e3d2dfe4b1df2b485d208c2f; Core 45854378233 / Release 45854378337 passed.
- PR #5 merged ca51f65541a5e8b9ff8fd9e764d7deb14fd2e345; Core 45855443868 / Release 45855443886 passed on 8f3f2c5980b9f1f8cddc1c9ff1f506e9bb1d0645; artifact 15134878557. P10a hosted snapshot and audit checks passed.
- PR #6 merged 10cdb2cbb3709c1257260c9734e1cfbf6cc884f2; Core 45856787075 / Release 45856787079 passed on fa13c67d13054e3d89c49f38b59d9ef68d03b1c8; artifact 15136855368. P10b hosted tests passed.
- PR #7 merged 922ace11fc11b6a0f445c4db6830c45553603e19; Core 45857595270 / Release 45857595229 passed on c6b6f950f85263c5ae6c0dac1211d5104100deae; artifact 15136548580. Streaming and legacy tests passed in hosted CI; 16 GiB and real x86 OS not measured.
- PR #8 merged f293f3fb4d3f19523e58bea699c9d302bfd048c2; Core 45859016379 / Release 45859016325 passed on 02e845e36e3adaba0f49c4bb66d598c0ee354132; artifact 15138440387. P10d hosted checks passed; actual different-account/device testing pending.
- PR #9 merged b4dd68b579817f6bc0aa5bb31670f99692474eb1; Core 45861158859 / Release 45861158853 passed on e337fe4575ad104954def110f9c4f51adcf92531; artifact 15137074541. P10e verified protected preparation in hosted CI.
- P10f proposed shared restricted temporary workspace creation and verification, two new tests (Windows ACL inheritance and parallel isolation); all existing backup probes exercise the helper on x86/x64. CI pending. No new files or external dependencies.
- P10 remaining: verify workspace restrictions, managed crash cleanup, real cross-account/device validation, live activation with writer exclusion and fresh history, full audit coverage/actor attribution, retention and scheduling. No live restore.
- P01 deeper per-feature audit; physical Windows, RouterOS, printers; hard-kill, power-loss and disk-full tests pending. main remains unprotected; exact-head manual gate enforced. No production DB or real router changes.

## PR #8 build failure — 2026-11-26
Core run 45858437768 (job 140042839043) and Release run 45858437765 (job 140042838343) failed at compilation with xUnit2031, RestoreCredentialTests.cs lines 134–135. The analyzer rejects Assert.Single(collection.Where(predicate)); use Assert.Single(collection, predicate) instead. Both assertions retain exactly-one-success and exactly-one-rejection semantics; no test disabled and TreatWarningsAsErrors unchanged. Reviewed all C# test files for the same direct pattern. Both workflows passed on the corrected head before PR #8 merge.
