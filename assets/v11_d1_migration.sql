-- v11 D1マイグレーション（退院通知フロー改修）
-- discharge_notices に meeting_url カラム追加

ALTER TABLE discharge_notices ADD COLUMN meeting_url TEXT DEFAULT '';

-- 動作確認用：現在のdischarge_noticesの内容確認
-- SELECT id, title, status, meeting_url FROM discharge_notices ORDER BY created_at DESC LIMIT 10;
