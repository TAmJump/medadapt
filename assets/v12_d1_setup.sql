-- v12 D1マイグレーション（Phase 8 マッサージ同意書）
-- 設計書: DESIGN_yaruze_v4_3_2026-05-24.html §41〜§47
-- 罠 §37-15 回避：既存テーブルへの ALTER は一切行わない。新規テーブル 4 つの追加 + roles への INSERT のみ。

-- ============================================
-- 1. consent_forms（同意書本体）§42-2-1
-- ============================================
CREATE TABLE IF NOT EXISTS consent_forms (
  id                  TEXT PRIMARY KEY,            -- CF-{uuid}
  org_id              TEXT NOT NULL,               -- 発行医療機関
  patient_id          TEXT NOT NULL,
  doctor_user_id      TEXT NOT NULL,               -- 保険医（med_clinic ロール）
  -- 厚労省必須項目
  consent_type        TEXT NOT NULL,               -- 'acupuncture' | 'massage' | 'both'
  disease_names       TEXT NOT NULL,               -- JSON 配列：[{name, onset_date}]
  notes               TEXT DEFAULT '',
  consent_date        TEXT NOT NULL,               -- 同意年月日 ISO
  validity_months     INTEGER DEFAULT 6,           -- 有効月数（変形徒手は 1）
  expires_at          TEXT NOT NULL,
  -- コンパス書式追加項目
  visit_plan          TEXT DEFAULT '年2回（6か月に1回）',
  difficulty_reasons  TEXT DEFAULT '',
  -- 状態管理
  status              TEXT DEFAULT 'draft',
  shared_to_user_id   TEXT,
  shared_at           TEXT,
  revoked_at          TEXT,
  revoked_reason      TEXT,
  renewed_from        TEXT,
  -- ハッシュチェーン（§43）
  content_hash        TEXT,
  prev_hash           TEXT,
  chain_index         INTEGER,
  -- 認定 TSA（§43・第 3 段階・Phase 9）
  tsa_token           TEXT,
  tsa_authority       TEXT,
  tsa_acquired_at     TEXT,
  -- PDF
  pdf_data            TEXT,                        -- Base64 エンコード PDF
  pdf_filename        TEXT DEFAULT '',
  -- 監査
  created_at          TEXT NOT NULL,
  updated_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cf_org      ON consent_forms(org_id);
CREATE INDEX IF NOT EXISTS idx_cf_patient  ON consent_forms(patient_id);
CREATE INDEX IF NOT EXISTS idx_cf_doctor   ON consent_forms(doctor_user_id);
CREATE INDEX IF NOT EXISTS idx_cf_status   ON consent_forms(status);
CREATE INDEX IF NOT EXISTS idx_cf_expires  ON consent_forms(expires_at);
CREATE INDEX IF NOT EXISTS idx_cf_chain    ON consent_forms(chain_index);

-- ============================================
-- 2. treatment_plans（訪問診療計画書）§42-2-2
-- ============================================
CREATE TABLE IF NOT EXISTS treatment_plans (
  id                   TEXT PRIMARY KEY,           -- TP-{uuid}
  consent_form_id      TEXT NOT NULL,              -- 1:1 関係
  org_id               TEXT NOT NULL,
  patient_id           TEXT NOT NULL,
  doctor_user_id       TEXT NOT NULL,
  visit_frequency      TEXT NOT NULL,              -- 'biannual' 等
  evaluation_frequency TEXT NOT NULL,              -- 'monthly' 等
  goals                TEXT DEFAULT '',
  treatment_method     TEXT DEFAULT '',
  content_hash         TEXT,
  created_at           TEXT NOT NULL,
  updated_at           TEXT NOT NULL,
  UNIQUE(consent_form_id)
);
CREATE INDEX IF NOT EXISTS idx_tp_consent  ON treatment_plans(consent_form_id);

-- ============================================
-- 3. signature_events（署名イベント）§42-2-3
-- ============================================
CREATE TABLE IF NOT EXISTS signature_events (
  id                  TEXT PRIMARY KEY,            -- SE-{uuid}
  consent_form_id     TEXT NOT NULL,
  signer_user_id      TEXT NOT NULL,
  signer_role         TEXT NOT NULL,               -- 'doctor' | 'patient' | 'acupuncturist'
  signature_method    TEXT NOT NULL,               -- 'electronic_seal' | 'handwritten_image' | 'typed_name'
  signature_data      TEXT,                        -- Base64 画像 / typed 氏名
  signed_at           TEXT NOT NULL,
  signed_ip           TEXT,
  signed_user_agent   TEXT,
  event_hash          TEXT NOT NULL,
  prev_event_hash     TEXT,
  tsa_token           TEXT,
  tsa_authority       TEXT,
  tsa_acquired_at     TEXT,
  created_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_se_consent  ON signature_events(consent_form_id);
CREATE INDEX IF NOT EXISTS idx_se_signer   ON signature_events(signer_user_id);

-- ============================================
-- 4. hash_chain（グローバル連鎖）§42-2-4
-- ============================================
CREATE TABLE IF NOT EXISTS hash_chain (
  chain_index      INTEGER PRIMARY KEY AUTOINCREMENT,
  entity_type      TEXT NOT NULL,                  -- 'consent_form' | 'signature_event' | 'treatment_plan' | 'revocation'
  entity_id        TEXT NOT NULL,
  entity_hash      TEXT NOT NULL,
  prev_chain_hash  TEXT NOT NULL,                  -- genesis: 64個の0
  chain_hash       TEXT NOT NULL,                  -- SHA-256(entity_hash + prev_chain_hash + created_at)
  created_at       TEXT NOT NULL,
  UNIQUE(entity_type, entity_id)
);
CREATE INDEX IF NOT EXISTS idx_hc_entity   ON hash_chain(entity_type, entity_id);

-- ============================================
-- 5. roles に med_acupuncturist 追加（§42-3）
-- ============================================
INSERT OR IGNORE INTO roles VALUES (
  'med_acupuncturist',
  'medical-adapt',
  '鍼灸マッサージ師',
  '["read","write","accept","consent_verify","report_submit"]',
  '2026-05-24'
);
