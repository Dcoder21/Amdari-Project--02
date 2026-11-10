-- SentinelPay demo data for local development and CI ONLY.
-- Weak, well-known passwords (MD5 of "password123", "admin2024",
-- "merchant1") and a seeded admin. NEVER apply this to a shared or
-- internet-reachable database; use schema.sql there.
-- Load after schema.sql.

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
