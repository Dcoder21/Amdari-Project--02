-- SentinelPay schema (tables only, no data).
-- Safe to apply to any environment, including AWS: run it as a one-off
-- task. Demo data lives in seed_data.sql and must never reach a shared
-- environment.

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
