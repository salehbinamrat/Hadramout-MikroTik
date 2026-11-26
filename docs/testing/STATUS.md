# Current evidence
- Foundation PR #1 merged at d3666127acc9adc172738d654b1036fb3a0ec60a. Core 45851610712 and Release 45851610482 succeeded on 551d18a5a507aaabf15d5ee6130c7f08a7239950; release artifact 15134257797. Hosted architecture, smoke and installer lifecycle evidence only.
- P01: initial code and root-license review; deeper per-feature review still required.
- P02 initial scope documented. P03–P05 hosted baseline passed. Physical target matrix not validated.
- P06–P07 initial relational slice proposed; CI pending. Tests exercise constraints, rollback, reopen and native SQLite on published x86/x64. No production DB creation yet.
- P08–P10 migrations, credential security and audit/backups pending.
- Branch main was reported unprotected and no rulesets were found at merge time. Required checks must be configured by repository admin; manual exact-head checks enforced meanwhile. No physical RouterOS or printer tests yet.
