-- SentinelPay seed fixtures
-- Schema and demo data for local development.

CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    full_name       VARCHAR(255),
    role            VARCHAR(50) DEFAULT 'merchant',
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS accounts (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER REFERENCES users(id),
    account_number  VARCHAR(20) UNIQUE NOT NULL,
    currency        VARCHAR(3) DEFAULT 'NGN',
    balance         NUMERIC(18, 2) DEFAULT 0.00,
    status          VARCHAR(20) DEFAULT 'active',
    created_at      TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS transactions (
    id              SERIAL PRIMARY KEY,
    account_id      INTEGER REFERENCES accounts(id),
    reference       VARCHAR(64) UNIQUE NOT NULL,
    amount          NUMERIC(18, 2) NOT NULL,
    currency        VARCHAR(3) DEFAULT 'NGN',
    direction       VARCHAR(10) NOT NULL, -- 'credit' or 'debit'
    counterparty    VARCHAR(255),
    description     VARCHAR(500),
    status          VARCHAR(20) DEFAULT 'completed',
    created_at      TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kyc_records (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER REFERENCES users(id),
    bvn             VARCHAR(11),
    nin             VARCHAR(11),
    document_url    VARCHAR(500),
    verification_status VARCHAR(20) DEFAULT 'pending',
    submitted_at    TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS webhooks (
    id              SERIAL PRIMARY KEY,
    user_id         INTEGER REFERENCES users(id),
    callback_url    VARCHAR(500) NOT NULL,
    event_type      VARCHAR(50),
    created_at      TIMESTAMP DEFAULT NOW()
);

-- Fix for V-APP-11: audit log for money movement and other sensitive
-- operations. Also created defensively at app startup (app/audit.py) so
-- this applies to an already-initialised volume, not just a fresh install.
CREATE TABLE IF NOT EXISTS audit_log (
    id              SERIAL PRIMARY KEY,
    actor_user_id   INTEGER,
    action          VARCHAR(100) NOT NULL,
    resource_type   VARCHAR(50) NOT NULL,
    resource_id     VARCHAR(100),
    metadata        JSONB,
    created_at      TIMESTAMP DEFAULT NOW()
);

-- Seed users (passwords are MD5 of "password123", "admin2024", "merchant1")
INSERT INTO users (email, password_hash, full_name, role) VALUES
    ('admin@sentinelpay.io', '482c811da5d5b4bc6d497ffa98491e38', 'Adaeze Okonkwo', 'admin'),
    ('finance@sentinelpay.io', '78c2e10018a4fa37b4f4b5e62a8e90bb', 'Tunde Bakare', 'finance'),
    ('merchant1@example.com', 'b25bfe3edaa1cbf65f0d3a92a7c5dac9', 'Lagos Foods Ltd', 'merchant'),
    ('merchant2@example.com', 'b25bfe3edaa1cbf65f0d3a92a7c5dac9', 'Accra Logistics Co', 'merchant'),
    ('merchant3@example.com', 'b25bfe3edaa1cbf65f0d3a92a7c5dac9', 'Nairobi Tech Hub', 'merchant');

INSERT INTO accounts (user_id, account_number, currency, balance) VALUES
    (1, '0010000001', 'NGN', 0.00),
    (2, '0010000002', 'NGN', 0.00),
    (3, '0010000003', 'NGN', 2450000.00),
    (3, '0010000004', 'USD', 5200.00),
    (4, '0010000005', 'GHS', 87500.00),
    (5, '0010000006', 'KES', 1200000.00);

INSERT INTO transactions (account_id, reference, amount, direction, counterparty, description) VALUES
    (3, 'TXN-2026-001', 150000.00, 'credit', 'GTBank/0123456789', 'POS settlement batch'),
    (3, 'TXN-2026-002', 45000.00, 'debit', 'Vendor payment', 'Inventory restock'),
    (3, 'TXN-2026-003', 320000.00, 'credit', 'Access Bank/9876543210', 'Customer transfer'),
    (5, 'TXN-2026-004', 87500.00, 'credit', 'MTN MoMo', 'Mobile money settlement'),
    (6, 'TXN-2026-005', 1200000.00, 'credit', 'Safaricom M-Pesa', 'Mobile money settlement');

INSERT INTO kyc_records (user_id, bvn, nin, verification_status) VALUES
    (3, '22134567890', '12345678901', 'verified'),
    (4, '22198765432', '98765432109', 'verified'),
    (5, '22155544433', '55544433322', 'pending');
