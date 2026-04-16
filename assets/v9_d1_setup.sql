-- ============================================================
-- MedAdapt v9 D1セットアップ
-- Cloudflare D1 Console で1文ずつ実行してください
-- ============================================================

-- 1. 法人間NDAテーブル
CREATE TABLE IF NOT EXISTS org_ndas (
  id             TEXT PRIMARY KEY,
  org_id_a       TEXT NOT NULL,
  org_id_b       TEXT NOT NULL,
  status         TEXT DEFAULT 'pending',
  requested_at   TEXT NOT NULL,
  signed_at      TEXT,
  signed_by      TEXT,
  signed_ip      TEXT,
  terminated_at  TEXT,
  UNIQUE(org_id_a, org_id_b)
);

-- 2. 退院通知テーブル
CREATE TABLE IF NOT EXISTS discharge_notices (
  id             TEXT PRIMARY KEY,
  patient_id     TEXT NOT NULL,
  issued_by      TEXT NOT NULL,
  org_id         TEXT NOT NULL,
  title          TEXT NOT NULL,
  memo           TEXT DEFAULT '',
  pdf_url        TEXT DEFAULT '',
  pdf_filename   TEXT DEFAULT '',
  status         TEXT DEFAULT 'active',
  created_at     TEXT NOT NULL,
  closed_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_dn_org ON discharge_notices(org_id);

-- 3. 通知受信者・アクセス権限テーブル
CREATE TABLE IF NOT EXISTS notice_recipients (
  id                TEXT PRIMARY KEY,
  notice_id         TEXT NOT NULL,
  recipient_org_id  TEXT NOT NULL,
  access_stage      INTEGER DEFAULT 1,
  joined_at         TEXT,
  declined_at       TEXT,
  proposal          TEXT DEFAULT '{}',
  proposal_at       TEXT,
  created_at        TEXT NOT NULL,
  UNIQUE(notice_id, recipient_org_id)
);
CREATE INDEX IF NOT EXISTS idx_nr_notice ON notice_recipients(notice_id);
CREATE INDEX IF NOT EXISTS idx_nr_org ON notice_recipients(recipient_org_id);

-- 4. 日程調整テーブル
CREATE TABLE IF NOT EXISTS schedule_polls (
  id              TEXT PRIMARY KEY,
  notice_id       TEXT NOT NULL,
  created_by      TEXT NOT NULL,
  status          TEXT DEFAULT 'open',
  confirmed_slot  TEXT,
  call_url        TEXT,
  deadline        TEXT,
  created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schedule_slots (
  id             TEXT PRIMARY KEY,
  poll_id        TEXT NOT NULL,
  slot_datetime  TEXT NOT NULL,
  label          TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS schedule_votes (
  id            TEXT PRIMARY KEY,
  slot_id       TEXT NOT NULL,
  voter_org_id  TEXT NOT NULL,
  voter_type    TEXT DEFAULT '',
  answer        TEXT NOT NULL,
  voted_at      TEXT NOT NULL,
  UNIQUE(slot_id, voter_org_id)
);

-- 5. 患者最終選択テーブル
CREATE TABLE IF NOT EXISTS match_selections (
  id              TEXT PRIMARY KEY,
  notice_id       TEXT NOT NULL,
  patient_id      TEXT NOT NULL,
  selected_org_id TEXT NOT NULL,
  selected_at     TEXT NOT NULL,
  note            TEXT DEFAULT ''
);
