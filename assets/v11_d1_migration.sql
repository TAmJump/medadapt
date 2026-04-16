-- v11 D1マイグレーション（退院通知フロー改修）

-- 1. discharge_notices に meeting_url カラム追加（既に実行済みの場合はスキップ）
ALTER TABLE discharge_notices ADD COLUMN meeting_url TEXT DEFAULT '';

-- 2. discharge_notices に PDF保存用カラム追加
ALTER TABLE discharge_notices ADD COLUMN pdf_data TEXT DEFAULT '';
ALTER TABLE discharge_notices ADD COLUMN pdf_file_type TEXT DEFAULT '';
