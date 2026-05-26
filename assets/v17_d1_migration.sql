-- v17 D1 マイグレーション（v5.0.5 セッション・アプリ設計㉞）
-- 設計書: HANDOVER §8-3 B 対応
--
-- 目的: signed_documents に TSA 構造化メタデータ列を追加する。
--   既存列: tsa_authority (TEXT), tsa_acquired_at (TEXT)
--   追加列: tsa_authority_name / tsa_cert_no / tsa_serial / hash_algorithm
--
-- これにより、app.html 側の buildTimestampCertHtml() が利用する
-- 6項目（事業者名・認定番号・付与日時(JST/UTC)・シリアル・ハッシュアルゴリズム・対象文書ハッシュ）
-- が Worker レスポンスから直接取得できるようになる。実 TSA 連携（セイコー/アマノ/GMO）
-- 着手時にこれらの列を実値で埋めるだけで本番化が完了する設計。
--
-- 設計指針:
--   - すべて DEFAULT 付きで後方互換（既存行は NULL 許容）
--   - hash_algorithm のデフォルトは 'SHA-256' （RFC 3161 推奨）
--   - tsa_authority_name は人間可読の事業者名（例: 'セイコータイムスタンプサービス'）
--   - tsa_authority は事業者識別子（既存：'amano' | 'seiko' | 'tkc' 等）と併用
--   - 実 TSA 連携前は Worker の応答生成側でモックデフォルトを埋める

-- ===========================================================
-- signed_documents への TSA 構造化メタ列追加
-- ===========================================================

ALTER TABLE signed_documents ADD COLUMN tsa_authority_name TEXT DEFAULT NULL;
ALTER TABLE signed_documents ADD COLUMN tsa_cert_no        TEXT DEFAULT NULL;
ALTER TABLE signed_documents ADD COLUMN tsa_serial         TEXT DEFAULT NULL;
ALTER TABLE signed_documents ADD COLUMN hash_algorithm     TEXT DEFAULT 'SHA-256';

-- consent_forms にも同じTSA構造化列を追加（同意書も TSA 対象のため対称構造とする）
ALTER TABLE consent_forms ADD COLUMN tsa_authority_name TEXT DEFAULT NULL;
ALTER TABLE consent_forms ADD COLUMN tsa_cert_no        TEXT DEFAULT NULL;
ALTER TABLE consent_forms ADD COLUMN tsa_serial         TEXT DEFAULT NULL;
ALTER TABLE consent_forms ADD COLUMN hash_algorithm     TEXT DEFAULT 'SHA-256';

-- ===========================================================
-- TSA 取得履歴テーブル（実 TSA 連携時の証跡保存）
-- ===========================================================
-- 1文書につき複数回 TSA を取得する可能性（再認証・更新）に備えて履歴を分離
-- 現状は signed_documents.tsa_* に最新値を保持しつつ、すべての取得イベントを timestamps テーブルへ追記

CREATE TABLE IF NOT EXISTS timestamps (
  id                  TEXT PRIMARY KEY,
  signed_document_id  TEXT NOT NULL,              -- 対象 signed_documents.id
  doc_kind            TEXT NOT NULL,
  authority           TEXT NOT NULL,              -- 'seiko' | 'amano' | 'gmo' | 'mock'
  authority_name      TEXT NOT NULL,              -- 人間可読名
  cert_no             TEXT,                       -- 認定番号
  serial              TEXT,                       -- TSA シリアル
  hash_algorithm      TEXT NOT NULL DEFAULT 'SHA-256',
  document_hash       TEXT NOT NULL,              -- 対象文書ハッシュ（取得時点）
  acquired_at_utc     TEXT NOT NULL,              -- ISO 8601 UTC
  acquired_at_jst     TEXT,                       -- ISO 8601 JST（表示用キャッシュ）
  status              TEXT NOT NULL DEFAULT 'success',  -- 'success' | 'failed' | 'pending'
  raw_response        TEXT,                       -- TSA からの生レスポンス（base64 等）
  verify_method       TEXT,                       -- 'qr' | 'authority_window' | 'rfc3161'
  created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_timestamps_signed_doc ON timestamps(signed_document_id);
CREATE INDEX IF NOT EXISTS idx_timestamps_doc_kind   ON timestamps(doc_kind);
CREATE INDEX IF NOT EXISTS idx_timestamps_acquired   ON timestamps(acquired_at_utc DESC);

-- ===========================================================
-- 動作確認用クエリ（手動実行用）
-- ===========================================================
-- 列追加の確認:
--   PRAGMA table_info(signed_documents);
--   PRAGMA table_info(consent_forms);
-- 新規テーブル確認:
--   SELECT name FROM sqlite_master WHERE type='table' AND name='timestamps';
