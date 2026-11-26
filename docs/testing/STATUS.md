# Current evidence
- PR #1 merged d3666127acc9adc172738d654b1036fb3a0ec60a; Core 45851610712 and Release 45851610482 passed.
- PR #2 merged 75e7778a913528c0c7fc3540e3958c407916815f; Core 45852471045 and Release 45852470926 passed on 828b649b459a700d4e945059e5a641f227c00ecb; artifact 15134093789. P06–P07 initial relational slice accepted in hosted CI.
- P01 deeper per-feature reference audit remains required; P02 initial scope documented; P03–P05 hosted baseline passed, physical target matrix pending.
- P08 proposed transactional schema versioning, WAL/FULL and persistent smoke test. CI pending. Power loss/hard kill, disk full, full production backup/restore and future schema upgrade evidence remain pending.
- P09–P10 credential protection, audit and backups pending. No production DB path, real router or printer changes.
- main is unprotected. Both checks are manually verified on exact PR head before merge; admin must configure required checks.
