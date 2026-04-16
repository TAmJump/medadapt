-- =============================================================
-- MedAdapt v8 共通基盤テーブル
-- Cloudflare D1 Console (medadapt-db) で1文ずつ実行してください
-- =============================================================

-- 1. モジュール定義
CREATE TABLE IF NOT EXISTS modules (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  description  TEXT,
  unit_price   INTEGER DEFAULT 200,
  is_active    INTEGER DEFAULT 1,
  created_at   TEXT NOT NULL
);

-- 初期データ
INSERT OR IGNORE INTO modules VALUES ('medical-adapt',   'MedAdapt',       '医療介護連携OS',  200, 1, '2026-04-15');
INSERT OR IGNORE INTO modules VALUES ('property-adapt',  'Property Adapt', '不動産管理',      200, 0, '2026-04-15');
INSERT OR IGNORE INTO modules VALUES ('facility-adapt',  'Facility Adapt', '施設管理',        200, 0, '2026-04-15');

-- 2. 契約状態
CREATE TABLE IF NOT EXISTS subscriptions (
  id                       TEXT PRIMARY KEY,
  org_id                   TEXT NOT NULL,
  module_id                TEXT NOT NULL,
  status                   TEXT DEFAULT 'active',
  plan_type                TEXT DEFAULT 'monthly',
  trial_start_at           TEXT,
  trial_end_at             TEXT,
  started_at               TEXT,
  cancelled_at             TEXT,
  auto_renew               INTEGER DEFAULT 1,
  coupon_code              TEXT,
  coupon_applied_at        TEXT,
  free_months_remaining    INTEGER DEFAULT 0,
  square_customer_id       TEXT,
  last_billed_month        TEXT,
  created_at               TEXT NOT NULL,
  UNIQUE(org_id, module_id)
);
CREATE INDEX IF NOT EXISTS idx_sub_org    ON subscriptions(org_id);
CREATE INDEX IF NOT EXISTS idx_sub_module ON subscriptions(module_id);

-- 3. ロール定義
CREATE TABLE IF NOT EXISTS roles (
  id          TEXT PRIMARY KEY,
  module_id   TEXT,
  name        TEXT NOT NULL,
  permissions TEXT NOT NULL,
  created_at  TEXT NOT NULL
);

INSERT OR IGNORE INTO roles VALUES ('adapt_admin',       NULL,             'Adapt管理者',    '["all"]',                                    '2026-04-15');
INSERT OR IGNORE INTO roles VALUES ('org_admin',         NULL,             '法人管理者',     '["read","write","invite","billing"]',         '2026-04-15');
INSERT OR IGNORE INTO roles VALUES ('org_staff',         NULL,             '一般スタッフ',   '["read","write"]',                           '2026-04-15');
INSERT OR IGNORE INTO roles VALUES ('patient',           NULL,             '患者・家族',     '["read","select"]',                          '2026-04-15');
INSERT OR IGNORE INTO roles VALUES ('med_hospital',      'medical-adapt',  '病院・退院調整', '["read","write","discharge_notice"]',        '2026-04-15');
INSERT OR IGNORE INTO roles VALUES ('med_facility',      'medical-adapt',  '介護施設',       '["read","write","accept"]',                  '2026-04-15');
INSERT OR IGNORE INTO roles VALUES ('med_clinic',        'medical-adapt',  '訪問診療',       '["read","write","accept"]',                  '2026-04-15');
INSERT OR IGNORE INTO roles VALUES ('med_care_mgr',      'medical-adapt',  'ケアマネ',       '["read","write","accept"]',                  '2026-04-15');
INSERT OR IGNORE INTO roles VALUES ('med_pharmacy',      'medical-adapt',  '薬局',           '["read","write","accept"]',                  '2026-04-15');
INSERT OR IGNORE INTO roles VALUES ('med_visiting_nurse','medical-adapt',  '訪問看護',       '["read","write","accept"]',                  '2026-04-15');

-- 4. ユーザーごとのモジュール権限
CREATE TABLE IF NOT EXISTS user_module_permissions (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  module_id   TEXT NOT NULL,
  role_id     TEXT NOT NULL,
  granted_by  TEXT,
  granted_at  TEXT NOT NULL,
  revoked_at  TEXT,
  UNIQUE(user_id, module_id)
);

-- 5. クーポン
CREATE TABLE IF NOT EXISTS coupons (
  id               TEXT PRIMARY KEY,
  code             TEXT NOT NULL UNIQUE,
  name             TEXT NOT NULL,
  target_module_id TEXT,
  discount_type    TEXT NOT NULL,
  discount_value   INTEGER NOT NULL,
  max_uses         INTEGER,
  used_count       INTEGER DEFAULT 0,
  valid_from       TEXT NOT NULL,
  valid_until      TEXT,
  combinable       INTEGER DEFAULT 0,
  target_condition TEXT,
  is_active        INTEGER DEFAULT 1,
  created_at       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS coupon_usages (
  id          TEXT PRIMARY KEY,
  coupon_id   TEXT NOT NULL,
  org_id      TEXT NOT NULL,
  used_at     TEXT NOT NULL,
  applied_to  TEXT NOT NULL,
  UNIQUE(coupon_id, org_id)
);

-- 6. 通知
CREATE TABLE IF NOT EXISTS notifications (
  id          TEXT PRIMARY KEY,
  user_id     TEXT NOT NULL,
  module_id   TEXT,
  type        TEXT NOT NULL,
  title       TEXT NOT NULL,
  body        TEXT NOT NULL,
  action_url  TEXT,
  is_read     INTEGER DEFAULT 0,
  created_at  TEXT NOT NULL,
  read_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, is_read);

-- 7. 法人情報（organizations）
CREATE TABLE IF NOT EXISTS organizations (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  type        TEXT NOT NULL DEFAULT 'hospital',
  address     TEXT,
  phone       TEXT,
  email       TEXT,
  website_url TEXT,
  area_json   TEXT,
  logo_url    TEXT,
  created_at  TEXT NOT NULL,
  updated_at  TEXT
);

-- =============================================================
-- 既存ユーザーの users テーブルへの追加カラム
-- =============================================================
ALTER TABLE users ADD COLUMN last_login_at TEXT;
ALTER TABLE users ADD COLUMN square_customer_id TEXT;
ALTER TABLE users ADD COLUMN billing_email TEXT;
ALTER TABLE users ADD COLUMN org_type TEXT DEFAULT 'hospital';

-- =============================================================
-- 既存テストアカウントに subscriptions レコードを追加
-- （ADM-PROTEST / ADM-FREETEST / ADM-TIGER）
-- ※ org_id は users.id（内部UUID）を使う。以下は例。
--   実際のorg_idはD1で SELECT id FROM users WHERE login_id='ADM-PROTEST'; で確認する。
-- =============================================================
-- INSERT INTO subscriptions (id, org_id, module_id, status, started_at, created_at)
-- VALUES (lower(hex(randomblob(16))), '★ADM-PROTESTのuser.id★', 'medical-adapt', 'active', '2026-04-15', '2026-04-15');
