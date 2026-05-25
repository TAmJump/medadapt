-- =============================================================
-- v15 D1 Verification (v4.15 / 2026-05-25)
-- =============================================================
-- 目的: v14 までの consent_forms スキーマが正しく適用されているかを確認する。
-- 既存テーブルへの ALTER は一切なし（既存破壊ゼロ・確認のみ）。
--
-- v12 で consent_type 列、v14 で clinic_* / doctor_name 列が追加済み。
-- v15 では新規 column 追加は行わない。本ファイルは検証 SELECT のみ。
--
-- 適用方法:
--   wrangler d1 execute <DB_NAME> --file=assets/v15_d1_verification.sql
-- =============================================================

-- 1. consent_forms テーブルのスキーマ確認
.schema consent_forms

-- 2. consent_type が 'acupuncture' / 'massage' / 'both' のいずれかであることを確認
SELECT
  consent_type,
  COUNT(*) AS cnt
FROM consent_forms
GROUP BY consent_type;

-- 3. clinic_name が 「医療法人コンパス」に揃っているかを確認（v4.15 で統一）
-- 既存レコードに古い表記が残っていれば、別途下記の更新クエリを慎重に検討:
--   UPDATE consent_forms SET clinic_name = '医療法人コンパス'
--   WHERE clinic_name = '医療法人社団コンパス　コンパス内科歯科クリニック大宮';
-- ※ 旧表記での発行済み同意書は法的に有効なので、原則として過去レコードは書き換えない。
-- ※ 新規発行分は v4.15 以降「医療法人コンパス」で発行される。
SELECT clinic_name, COUNT(*) AS cnt FROM consent_forms GROUP BY clinic_name;

-- 4. signed_documents との JOIN 整合性確認
-- consent_form_id が signed_documents の document_id に存在するか
SELECT
  cf.id AS consent_form_id,
  cf.consent_type,
  cf.status,
  sd.id AS signed_doc_id,
  sd.chain_index,
  sd.tsa_acquired_at
FROM consent_forms cf
LEFT JOIN signed_documents sd
  ON sd.document_id = cf.id AND sd.doc_kind = 'consent_form'
ORDER BY cf.created_at DESC
LIMIT 10;
