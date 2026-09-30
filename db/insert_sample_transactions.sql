/* ============================================================
   Sample manual inserts into tblStoreTransactionLogs
   Run this in SSMS to add a few test rows.
   RiskScore/IsRisky are left out here - they default to
   NULL / 0 (No) since scoring happens later via the API/ML step.
   ============================================================ */

USE CCTransactionMonitoringDB;
GO

INSERT INTO dbo.tblStoreTransactionLogs
    (Last4Digits, CountryOfTransaction, MerchantId, ItemDescription,
     Amount, CurrencyCode, TransactionDateTime, Channel)
VALUES
    ('4242', 'IN', 101, 'Grocery purchase',        1250.00, 'INR', '2026-07-25 10:15:00', 'card_present'),
    ('7891', 'IN', 102, 'Online electronics order',  8999.00, 'INR', '2026-07-25 14:42:00', 'ecom'),
    ('1123', 'US', 103, 'Coffee shop',                  6.50, 'USD', '2026-07-25 09:05:00', 'card_present'),
    ('9987', 'GB', 104, 'Flight booking',              412.75, 'GBP', '2026-07-24 22:30:00', 'ecom'),
    ('3456', 'IN', 101, 'Pharmacy',                     340.00, 'INR', '2026-07-26 08:00:00', 'mobile');
GO

-- Quick check
SELECT * FROM dbo.tblStoreTransactionLogs ORDER BY TransactionDateTime DESC;
GO