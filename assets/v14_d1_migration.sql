-- v14 D1 マイグレーション（v4.15 セッション）
-- 設計書: DESIGN_yaruze_v4_15_2026-05-25.html §67-2
--
-- 目的: consent_forms に clinic_name / clinic_address / clinic_tel / clinic_fax / doctor_name 列を追加し、
--       同意書発行時の保険医療機関情報・保険医氏名を永続化する。
--       これにより app.html / Worker でハードコードしていた "医療法人コンパス" / "後藤 基温" を、
--       D1 に保存された値で動的にレンダリングできるようにする。
--
-- 罠 §37-15 回避: ALTER TABLE は SQLite では限定的だが、新しい列追加は安全。
-- 既存データに対しては DEFAULT 値が適用される。

-- 1. 保険医療機関情報（PDF レンダリングで使用）
ALTER TABLE consent_forms ADD COLUMN clinic_name    TEXT DEFAULT '医療法人コンパス';
ALTER TABLE consent_forms ADD COLUMN clinic_address TEXT DEFAULT '〒330-0854　埼玉県さいたま市大宮区桜木町4-692-1　伊田グループビルⅢ405号室';
ALTER TABLE consent_forms ADD COLUMN clinic_tel     TEXT DEFAULT '048-783-2713';
ALTER TABLE consent_forms ADD COLUMN clinic_fax     TEXT DEFAULT '03-6369-4732';

-- 2. 保険医氏名（doctor_user_id とは別に、PDF レンダリング用に氏名を文字列で保存）
ALTER TABLE consent_forms ADD COLUMN doctor_name    TEXT DEFAULT '後藤 基温';

-- 3. 患者氏名・住所・生年月日のスナップショット（PDF レンダリング時の参照、患者テーブル変更影響を受けない）
ALTER TABLE consent_forms ADD COLUMN patient_name    TEXT DEFAULT '';
ALTER TABLE consent_forms ADD COLUMN patient_address TEXT DEFAULT '';
ALTER TABLE consent_forms ADD COLUMN patient_birth   TEXT DEFAULT '';    -- ISO 形式（YYYY-MM-DD）または和暦 JSON

-- 4. 厚労省様式 V2 用構造化データ（type 別の症状・施術部位等を JSON で保存）
ALTER TABLE consent_forms ADD COLUMN form_payload   TEXT DEFAULT '{}';   -- JSON: symptoms / treatments / visit etc

-- 5. インデックス追加（clinic 別の集計、再同意元検索など）
CREATE INDEX IF NOT EXISTS idx_cf_clinic_name ON consent_forms(clinic_name);
CREATE INDEX IF NOT EXISTS idx_cf_renewed_from ON consent_forms(renewed_from);

-- ============================================
-- 結果確認用クエリ（migration 後）
-- SELECT consent_type, clinic_name, doctor_name, COUNT(*) FROM consent_forms GROUP BY consent_type, clinic_name;
-- ============================================
