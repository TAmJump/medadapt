-- v13 D1マイグレーション（Phase 8 共通改ざん防止基盤 + 加算管理）
-- 設計書: DESIGN v4.5 §51〜§54
-- 罠 §37-15 絶対遵守：既存テーブルへの ALTER は一切なし。v12 で作った consent_forms / treatment_plans / signature_events / hash_chain も維持。
-- 本 v13 は「全帳票共通の改ざん防止基盤」を新規 signed_documents テーブルで実現し、既存 discharge_notices / org_ndas / consent_forms / documents を非侵襲的に紐付ける。

-- ============================================
-- 1. signed_documents（全帳票共通の改ざん防止メタ）
-- ============================================
-- 任意の既存テーブル（discharge_notices / org_ndas / consent_forms / documents 等）の
-- レコード 1 行に対して、ハッシュ・タイムスタンプ・QR検証URL・保険算定情報を付帯する共通台帳。
-- 既存テーブルは ALTER 一切なし。doc_kind + doc_id で参照する。

CREATE TABLE IF NOT EXISTS signed_documents (
  id                  TEXT PRIMARY KEY,            -- SD-{uuid}
  doc_kind            TEXT NOT NULL,               -- 'consent_form' | 'discharge_notice' | 'org_nda' | 'treatment_plan' | 'acupuncture_report' | 'joint_guidance_record'（退院時共同指導記録）
  doc_id              TEXT NOT NULL,               -- 既存テーブルの id（CF- / DN- / NDA- / TP- / DOC- 等）
  org_id              TEXT NOT NULL,               -- 発行医療機関
  patient_id          TEXT,                        -- 該当する患者がいる場合
  title               TEXT NOT NULL,               -- 文書タイトル（表示用）
  -- 改ざん防止
  content_snapshot    TEXT NOT NULL,               -- 確定時の全フィールドを JSON 化したスナップショット
  content_hash        TEXT NOT NULL,               -- SHA-256(content_snapshot)
  prev_hash           TEXT,                        -- 直前 signed_documents.content_hash（同一 doc_kind 内）
  chain_index         INTEGER,                     -- hash_chain.chain_index への参照
  -- 認定タイムスタンプ（Phase 9 で実装・Phase 8 ではカラムだけ確保）
  tsa_token           TEXT,                        -- RFC 3161 TimeStampToken（Base64）
  tsa_authority       TEXT,                        -- 'amano' | 'seiko' | 'tkc'（日本データ通信協会認定）
  tsa_acquired_at     TEXT,
  tsa_status          TEXT DEFAULT 'pending',      -- 'pending' | 'acquired' | 'not_required' | 'failed'
  -- QR 検証
  verify_token        TEXT NOT NULL,               -- HMAC トークン（公開 verify URL 用）
  qr_payload          TEXT,                        -- QR コードに埋め込む URL（Base64 PNG は生成時）
  -- 保険算定（医療保険対応）
  insurance_claim_kind TEXT,                       -- 'b013_ryouyouhi_doui'（療養費同意書交付料 100点） | 'b004_taiin_kyodo_1'（退院時共同指導料1） | 'b005_taiin_kyodo_2'（退院時共同指導料2） | 'visit_nursing_kyodo'（訪問看護退院時共同指導加算 600単位） | null
  claim_points        INTEGER,                     -- 算定点数（100 / 600 等）
  claim_unit          TEXT,                        -- 'medical_points'（医療保険点数） | 'care_units'（介護保険単位）
  claim_status        TEXT DEFAULT 'not_claimed',  -- 'not_claimed' | 'eligible' | 'claimed' | 'rejected'
  claim_recorded_at   TEXT,                        -- 算定登録日時
  claim_recorded_by   TEXT,                        -- 算定登録者 user_id
  claim_notes         TEXT DEFAULT '',
  -- 監査
  created_at          TEXT NOT NULL,
  finalized_at        TEXT,                        -- 確定（不可変化）日時
  created_by          TEXT NOT NULL,               -- 作成者 user_id
  UNIQUE(doc_kind, doc_id)
);
CREATE INDEX IF NOT EXISTS idx_sd_kind     ON signed_documents(doc_kind);
CREATE INDEX IF NOT EXISTS idx_sd_org      ON signed_documents(org_id);
CREATE INDEX IF NOT EXISTS idx_sd_patient  ON signed_documents(patient_id);
CREATE INDEX IF NOT EXISTS idx_sd_claim    ON signed_documents(insurance_claim_kind, claim_status);
CREATE INDEX IF NOT EXISTS idx_sd_verify   ON signed_documents(verify_token);
CREATE INDEX IF NOT EXISTS idx_sd_chain    ON signed_documents(chain_index);

-- ============================================
-- 2. document_attestations（文書に対する署名イベントの共通台帳）
-- ============================================
-- v12 の signature_events は consent_forms 専用だったが、本テーブルは全帳票共通。
-- v12 signature_events は破棄せず、consent_forms 専用の詳細台帳として温存（既存破壊ゼロ）。

CREATE TABLE IF NOT EXISTS document_attestations (
  id                  TEXT PRIMARY KEY,            -- AT-{uuid}
  signed_document_id  TEXT NOT NULL,               -- signed_documents.id
  attester_user_id    TEXT NOT NULL,
  attester_role       TEXT NOT NULL,               -- 'doctor' | 'patient' | 'acupuncturist' | 'nurse' | 'careManager' | 'pharmacist' | 'witness'
  attester_org_id     TEXT,
  attestation_method  TEXT NOT NULL,               -- 'electronic_seal' | 'handwritten_image' | 'typed_name' | 'sso_verified'
  attestation_data    TEXT,                        -- Base64 画像 or 氏名文字列
  attested_at         TEXT NOT NULL,
  attested_ip         TEXT,
  attested_user_agent TEXT,
  event_hash          TEXT NOT NULL,               -- SHA-256(event_data)
  prev_event_hash     TEXT,                        -- 同一 signed_document の直前 attestation
  tsa_token           TEXT,
  tsa_authority       TEXT,
  tsa_acquired_at     TEXT,
  created_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_da_sd       ON document_attestations(signed_document_id);
CREATE INDEX IF NOT EXISTS idx_da_user     ON document_attestations(attester_user_id);

-- ============================================
-- 3. insurance_claim_log（保険算定の監査ログ）
-- ============================================
-- 算定実績の追跡・レセプト送信前の確認・査定返戻時の証跡管理用

CREATE TABLE IF NOT EXISTS insurance_claim_log (
  id                  TEXT PRIMARY KEY,            -- CL-{uuid}
  signed_document_id  TEXT NOT NULL,
  org_id              TEXT NOT NULL,
  patient_id          TEXT,
  claim_kind          TEXT NOT NULL,               -- signed_documents.insurance_claim_kind と同じ
  claim_points        INTEGER NOT NULL,
  claim_unit          TEXT NOT NULL,
  claim_month         TEXT NOT NULL,               -- 'YYYY-MM'（請求月）
  claim_status        TEXT NOT NULL,               -- 'recorded' | 'submitted' | 'paid' | 'rejected' | 'reversed'
  receipt_number      TEXT,                        -- レセプト番号（任意）
  insurer_code        TEXT,                        -- 保険者番号
  notes               TEXT DEFAULT '',
  recorded_by         TEXT NOT NULL,
  recorded_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cl_sd       ON insurance_claim_log(signed_document_id);
CREATE INDEX IF NOT EXISTS idx_cl_org      ON insurance_claim_log(org_id);
CREATE INDEX IF NOT EXISTS idx_cl_month    ON insurance_claim_log(org_id, claim_month);

-- ============================================
-- 4. roles に witness（立会人）追加（必要に応じて）
-- ============================================
-- 既存ロールを維持しつつ、立会署名用に witness ロールを追加可能にする
INSERT OR IGNORE INTO roles VALUES (
  'witness',
  NULL,
  '立会人',
  '["read","attest"]',
  '2026-05-24'
);
