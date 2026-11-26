# P01 — Initial reference evidence
Selective source/tree review, not full audit or live test. Independent implementation; inspect license at pinned revision before any code reuse.
- [Voucher Manager](https://github.com/ashrafeldawody/mikrotik-voucher-manager/tree/5ff0d70765049eaeb2060cda0a0783c45c2a5dac): src/connection.ts and src/strategies/usermanager.ts. FIFO, bounded reconnect, no blind write retry; separate v6/v7 paths and verify limits.
- [Pikro](https://github.com/digino/pikro/tree/d4661c32110ee1dc0b633e864aabc717234a553f): internal/handlers/hotspot.go and internal/sales/ledger_test.go. 100-card chunks, confirmed creations, durable transactional reconciliation.
- [MikhMon CE](https://github.com/kenweill/mikhmon-ce/tree/1a757add705b142b66c5e8e3e232c46649ce3a3d): hotspot/generateuser.php and voucher tree. Print modes; avoid fixed-position on-login script parsing.
- [PHPNuxBill](https://github.com/hotspotbilling/phpnuxbill/tree/157ca373863cb593676598810126a976cf205bca): system/controllers/voucher.php, voucher templates. Separate sales and activation, transactional ledger.
- [MikroTik Manager](https://github.com/2GT-Media-Group-LLC/mikrotik-manager/tree/0094630a3e7085d0cb58f2b7df6bd66bd9fe3c61): backend/src/routes/userManager.ts and security tests tree. Site isolation, change protection, typed failures.
- [Tik4Net](https://github.com/danikf/tik4net/tree/7406d81732d2139dc420097b5754e90c6b328bb4): integration test tree; candidate for TLS, timeout and concurrent operations.
- [KC.Tik4Net](https://github.com/KCTech-Lab/KC.Tik4Net): documentation review only; compare modern async, require v6 proof before adoption.
No upstream code copied. P01 deep per-feature and license review remains open.
