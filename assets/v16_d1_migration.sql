-- v16 D1 マイグレーション（v5.0.2 セッション・アプリ設計㉝）
-- 設計書: DESIGN_yaruze_v5_0_2026-05-26.html §3-2 / §4 / §5 / §6
--
-- 目的: 外部連携BOX（Phase 1-4）の永続化スキーマを整備する。
--   Phase 1: doc_kind 拡張は Worker 側の allowedKinds で対応（このSQLでは扱わない）
--   Phase 2: medical_document_shares（共有先・権限・状態） / medical_document_access_logs（閲覧・受領ログ）
--   Phase 3: doctor_profiles（医師資格確認・HPKI 関連情報）
--   Phase 4: signed_documents への ALTER（保存期限・署名レベル）/ medical_document_versions（新版発行）
--
-- 設計指針:
--   - すべての新規テーブルは IF NOT EXISTS で冪等
--   - 既存 signed_documents への ALTER は最小限・全列 DEFAULT 付きで後方互換
--   - 監査要件（医療法施行規則・医療情報システムの安全管理ガイドライン）に沿って
--     アクセスログは別テーブルに分離（操作証跡の改ざん防止）
--   - 共有停止（revoke）は論理削除（share_status='revoked'）で履歴を残す

-- ===========================================================
-- §3-2 Phase 2: 医療文書共有テーブル
-- ===========================================================

CREATE TABLE IF NOT EXISTS medical_document_shares (
  id                  TEXT PRIMARY KEY,
  signed_document_id  TEXT NOT NULL,                  -- 共有元 signed_documents.id
  patient_id          TEXT,
  from_org_id         TEXT NOT NULL,                  -- 共有元組織
  from_user_id        TEXT NOT NULL,                  -- 共有実行ユーザー
  to_org_id           TEXT,                            -- 共有先組織（自由入力時は NULL）
  to_user_id          TEXT,                            -- 個人指定共有時のみ
  to_role             TEXT,                            -- hospital / clinic_med / clinic_dent / visiting_nurse / pharmacy / care_manager / care_facility / rehab_provider / massage_acupuncture_provider / patient / family
  to_org_name         TEXT,                            -- 共有先組織名（自由入力スナップショット）
  permission          TEXT DEFAULT 'view',             -- view / download / acknowledge
  share_status        TEXT DEFAULT 'active',           -- active / acknowledged / rejected / revoked / expired
  shared_at           TEXT NOT NULL,
  expires_at          TEXT,
  acknowledged_at     TEXT,
  acknowledged_by     TEXT,
  rejected_at         TEXT,
  rejected_by         TEXT,
  reject_reason       TEXT,
  revoked_at          TEXT,
  revoked_by          TEXT,
  revoke_reason       TEXT,
  message             TEXT DEFAULT '',
  created_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mds_document ON medical_document_shares(signed_document_id);
CREATE INDEX IF NOT EXISTS idx_mds_patient  ON medical_document_shares(patient_id);
CREATE INDEX IF NOT EXISTS idx_mds_to_org   ON medical_document_shares(to_org_id);
CREATE INDEX IF NOT EXISTS idx_mds_to_user  ON medical_document_shares(to_user_id);
CREATE INDEX IF NOT EXISTS idx_mds_status   ON medical_document_shares(share_status);

-- ===========================================================
-- §4 Phase 2: 閲覧・受領確認ログ
-- ===========================================================
-- 監査ガイドライン準拠: 「誰が・いつ・何を・どこから」を全て記録。
-- IP/User-Agent も任意で保存（個人情報保護の観点で必要に応じて）

CREATE TABLE IF NOT EXISTS medical_document_access_logs (
  id                  TEXT PRIMARY KEY,
  signed_document_id  TEXT NOT NULL,
  share_id            TEXT,                            -- どの共有経由か（自組織アクセスなら NULL）
  patient_id          TEXT,
  user_id             TEXT,
  user_name           TEXT,                            -- スナップショット（ユーザー削除後も追跡可能に）
  org_id              TEXT,
  org_name            TEXT,
  role                TEXT,
  action              TEXT NOT NULL,                   -- view / download / print / acknowledge / reject / comment / revoke / verify / share
  ip_address          TEXT,
  user_agent          TEXT,
  detail              TEXT,                            -- 任意のコンテキスト（例: 「ページ3まで閲覧」）
  created_at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mdal_document ON medical_document_access_logs(signed_document_id);
CREATE INDEX IF NOT EXISTS idx_mdal_share    ON medical_document_access_logs(share_id);
CREATE INDEX IF NOT EXISTS idx_mdal_user     ON medical_document_access_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_mdal_action   ON medical_document_access_logs(action);
CREATE INDEX IF NOT EXISTS idx_mdal_patient  ON medical_document_access_logs(patient_id);
CREATE INDEX IF NOT EXISTS idx_mdal_created  ON medical_document_access_logs(created_at);

-- ===========================================================
-- §5 Phase 3: 医師本人確認・HPKI・署名レベル
-- ===========================================================
-- HPKI（厚労省 医療従事者公開鍵基盤）対応は v5.0.2 ではフィールド準備のみ。
-- 実カード読み取り / 外部CA連携は別途検討（半年後タスク §17）

CREATE TABLE IF NOT EXISTS doctor_profiles (
  id                              TEXT PRIMARY KEY,
  user_id                         TEXT NOT NULL,
  doctor_name                     TEXT NOT NULL,
  medical_license_number          TEXT,                     -- 医籍登録番号
  license_image_url               TEXT,                     -- 免許証画像保存先
  license_verified_status         TEXT DEFAULT 'pending',   -- pending / verified / rejected
  license_verified_at             TEXT,
  license_verified_by             TEXT,                     -- 確認した管理者の user_id
  organization_id                 TEXT,
  organization_name               TEXT,
  organization_verified_status    TEXT DEFAULT 'pending',   -- pending / verified / rejected
  organization_verified_at        TEXT,
  organization_verified_by        TEXT,
  hpki_enabled                    INTEGER DEFAULT 0,        -- 0: 未対応 / 1: 対応
  hpki_cert_subject               TEXT,                     -- 証明書 Subject DN
  hpki_cert_serial                TEXT,                     -- 証明書シリアル番号
  hpki_cert_issuer                TEXT,                     -- 発行 CA
  hpki_verified_at                TEXT,
  signing_authority_status        TEXT DEFAULT 'disabled',  -- disabled / enabled / suspended
  mfa_enabled                     INTEGER DEFAULT 0,        -- 多要素認証有効化フラグ
  created_at                      TEXT NOT NULL,
  updated_at                      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dp_user        ON doctor_profiles(user_id);
CREATE INDEX IF NOT EXISTS idx_dp_license     ON doctor_profiles(medical_license_number);
CREATE INDEX IF NOT EXISTS idx_dp_org         ON doctor_profiles(organization_id);
CREATE INDEX IF NOT EXISTS idx_dp_lic_status  ON doctor_profiles(license_verified_status);

-- ===========================================================
-- §6 Phase 4: signed_documents への保存期限・署名レベル列追加
-- ===========================================================
-- 例外的 ALTER: 文書ごとの保存期限管理は法定要件（医療法施行規則第20条等）のため必須。
-- すべて DEFAULT 付きで後方互換性を確保。

ALTER TABLE signed_documents ADD COLUMN retention_required  INTEGER DEFAULT 0;          -- 法定保存義務フラグ
ALTER TABLE signed_documents ADD COLUMN retention_years     INTEGER DEFAULT 5;          -- 保存年数（医療系は通常5年・診療録は2年・歯科は3年等）
ALTER TABLE signed_documents ADD COLUMN retention_until     TEXT;                       -- 算出済み保存期限（ISO日付）
ALTER TABLE signed_documents ADD COLUMN legal_basis         TEXT;                       -- 法的根拠（例: 医療法施行規則第20条 / 健保法第87条）
ALTER TABLE signed_documents ADD COLUMN delete_policy       TEXT DEFAULT 'logical';     -- logical / physical / archive
ALTER TABLE signed_documents ADD COLUMN signature_level     TEXT DEFAULT 'none';        -- none / system_verified / doctor_license_verified / hpki_signed / external_signed_pdf / paper_scan
ALTER TABLE signed_documents ADD COLUMN from_org_name       TEXT;                       -- 発行元組織名（外部連携BOX 用スナップショット）
ALTER TABLE signed_documents ADD COLUMN from_org_role       TEXT;                       -- 発行元種別
ALTER TABLE signed_documents ADD COLUMN issued_date         TEXT;                       -- 発行日（ISO日付）
ALTER TABLE signed_documents ADD COLUMN received_at         TEXT;                       -- 受領日時（外部受領時）
ALTER TABLE signed_documents ADD COLUMN version_no          INTEGER DEFAULT 1;          -- 版番号
ALTER TABLE signed_documents ADD COLUMN parent_document_id  TEXT;                       -- 旧版の signed_documents.id
ALTER TABLE signed_documents ADD COLUMN superseded_at       TEXT;                       -- 新版発行による旧版置換日時
ALTER TABLE signed_documents ADD COLUMN archived            INTEGER DEFAULT 0;          -- 論理削除フラグ

CREATE INDEX IF NOT EXISTS idx_sd_retention_until    ON signed_documents(retention_until);
CREATE INDEX IF NOT EXISTS idx_sd_signature_level    ON signed_documents(signature_level);
CREATE INDEX IF NOT EXISTS idx_sd_from_org           ON signed_documents(from_org_name);
CREATE INDEX IF NOT EXISTS idx_sd_parent             ON signed_documents(parent_document_id);
CREATE INDEX IF NOT EXISTS idx_sd_archived           ON signed_documents(archived);

-- ===========================================================
-- §6-1 Phase 4: 新版発行履歴テーブル
-- ===========================================================
-- 旧版→新版のリンクを別テーブルで明示的に管理（監査要件）

CREATE TABLE IF NOT EXISTS medical_document_versions (
  id                              TEXT PRIMARY KEY,
  parent_signed_document_id       TEXT NOT NULL,
  new_signed_document_id          TEXT NOT NULL,
  version_no                      INTEGER NOT NULL,
  reason                          TEXT,                       -- 新版発行理由（誤記訂正・追記・差し替え等）
  created_by                      TEXT NOT NULL,
  created_at                      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mdv_parent ON medical_document_versions(parent_signed_document_id);
CREATE INDEX IF NOT EXISTS idx_mdv_new    ON medical_document_versions(new_signed_document_id);

-- ===========================================================
-- §16 アセス・指示書の過去引継ぎ（履歴トレース用）
-- ===========================================================
-- 各記録テーブルに copied_from_record_id を持たせる必要があるが、
-- 既存の assessments / conferences / monitors はクライアント側 localStorage 中心の管理のため
-- D1 への永続化は signed_documents 経由（既に doc_type を持っている）。
-- assessment や monitor の引継ぎ元は documents.metadata JSON に
-- { "copied_from_id": "as_xxxx" } で記録する設計とし、
-- 専用テーブルは設けない（メタデータの肥大化を避けるため）。

-- ===========================================================
-- 結果確認用クエリ（migration 後・本番投入前に実行）
-- ===========================================================
-- SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'medical_document%' OR name='doctor_profiles';
-- SELECT name FROM pragma_table_info('signed_documents') WHERE name IN ('retention_required','retention_years','retention_until','legal_basis','signature_level','version_no','parent_document_id','archived');
-- SELECT COUNT(*) AS total_docs, SUM(retention_required) AS retention_required_count FROM signed_documents;

-- ===========================================================
-- ロールバック手順（緊急時のみ）
-- ===========================================================
-- DROP TABLE IF EXISTS medical_document_shares;
-- DROP TABLE IF EXISTS medical_document_access_logs;
-- DROP TABLE IF EXISTS doctor_profiles;
-- DROP TABLE IF EXISTS medical_document_versions;
-- -- ALTER TABLE で追加した列はそのまま残置（SQLite は DROP COLUMN を制限的にしかサポートしない）
-- -- 代替: app/Worker 側で参照しないようにフラグ管理

-- v16 マイグレーション完了
-- 次のステップ:
--   1. Worker側 (worker_v7_complete.js) の allowedKinds に新 doc_kind 23種を追加
--   2. /medical-docs/* エンドポイント群を実装
--   3. /verify/document/:id エンドポイントが新 signature_level を返すように拡張
