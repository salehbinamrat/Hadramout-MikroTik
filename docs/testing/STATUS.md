# Current evidence
- PR #1 merged d3666127acc9adc172738d654b1036fb3a0ec60a; Core 45851610712 and Release 45851610482 passed.
- PR #2 merged 75e7778a913528c0c7fc3540e3958c407916815f; Core 45852471045 and Release 45852470926 passed.
- PR #3 merged a3bcf4f4cb549d91dea8a2ad6bfe4ca0fcd5cbff; Core 45853570606 and Release 45853570539 passed on 7cd634da63b8e75af0aec8459d035a4a37a7e11f. Artifact 15134214791. P08 hosted migration tests passed; hard kill, real power loss and disk-full not tested.
- P09 credential protection proposed: schema v3, Windows DPAPI + AES-GCM, ten new tests, published smoke on both architectures. CI pending. Cross-account/machine tests, future voucher secrets, production UI/transport and backup/rekey policy remain open.
- P10 audit/backup pending. P01 deeper feature review, physical Windows/RouterOS/printer matrix pending. No real router changes.
- main remains unprotected; both checks manually verified before merge. Admin required to enforce protection.
