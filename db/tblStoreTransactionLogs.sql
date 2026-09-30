/* ============================================================
   tblStoreTransactionLogs
   Pure transaction record - no scoring/geo/device fields here.
   Those will live in separate tables (e.g. tblTransactionRiskScores,
   tblTransactionContext) so this table stays focused on "what
   happened", not "what we think about it".

   CARD DATA: only Last4 is ever stored. The full PAN passes
   through a tokenization/payment gateway step upstream and is
   never persisted or logged by this system.
   ============================================================ */

USE CCTransactionMonitoringDB;
GO

CREATE TABLE dbo.tblStoreTransactionLogs (
    TransactionId         BIGINT IDENTITY(1,1) NOT NULL PRIMARY KEY CLUSTERED,

    -- Card (masked only - never the full PAN)
    Last4Digits             CHAR(4)         NOT NULL,

    -- Transaction details
    CountryOfTransaction     CHAR(2)         NOT NULL,   -- ISO 3166-1 alpha-2
    MerchantId               INT             NOT NULL,   -- FK to tblMerchants once it exists
    ItemDescription          VARCHAR(255)    NULL,
    Amount                   DECIMAL(12,2)   NOT NULL,
    CurrencyCode              CHAR(3)         NOT NULL,   -- ISO 4217
    TransactionDateTime       DATETIME2       NOT NULL,
    Channel                   VARCHAR(20)     NOT NULL,   -- card_present/ecom/mobile/atm

    -- Risk assessment (filled in after rule/ML scoring)
    RiskScore                 DECIMAL(5,2)    NULL,       -- e.g. 0.00 to 100.00
    IsRisky                   BIT             NOT NULL DEFAULT 0,  -- 0 = No, 1 = Yes

    CreatedAt                 DATETIME2       NOT NULL DEFAULT SYSUTCDATETIME(),

    -- System-versioning for automatic audit history
    ValidFrom  DATETIME2 GENERATED ALWAYS AS ROW START NOT NULL,
    ValidTo    DATETIME2 GENERATED ALWAYS AS ROW END   NOT NULL,
    PERIOD FOR SYSTEM_TIME (ValidFrom, ValidTo),

    CONSTRAINT CK_tblStoreTransactionLogs_Last4 CHECK (Last4Digits NOT LIKE '%[^0-9]%')
)
WITH (SYSTEM_VERSIONING = ON (HISTORY_TABLE = dbo.tblStoreTransactionLogsHistory));
GO

CREATE INDEX IX_tblStoreTransactionLogs_MerchantId
    ON dbo.tblStoreTransactionLogs (MerchantId);
GO

CREATE INDEX IX_tblStoreTransactionLogs_TransactionDateTime
    ON dbo.tblStoreTransactionLogs (TransactionDateTime DESC);
GO