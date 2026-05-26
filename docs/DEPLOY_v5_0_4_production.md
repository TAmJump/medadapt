# 本番デプロイ手順書（v5.0.4 / Cloudflare Worker + D1 + R2）

## 前提

- Cloudflare アカウント所有者: 大下さん（animalb001@gmail.com）
- 既存 Worker: `medadapt-api-v2.animalb001.workers.dev`
- 既存 D1: `medadapt-prod`（過去 v8〜v14 マイグレーション適用済）
- 新規 R2 バケット: `medadapt-files`（v5.0.4 で追加・要作成）

---

## デプロイ方法の選択

### 方法A: GitHub Actions 経由（推奨・初期セットアップ後は自動化）

> **⚠️ 初回セットアップ時の追加手順**:
> Claude（私）の GitHub PAT には `workflow` スコープがないため、`.github/workflows/worker.yml` を直接コミットできません。大下さんの手元で以下を実行してください:
> ```bash
> cp docs/deploy_templates/worker.yml .github/workflows/worker.yml
> git add .github/workflows/worker.yml
> git commit -m "ci: Worker デプロイ用 GitHub Actions 追加"
> git push origin main
> ```
> または GitHub Web UI で直接 `.github/workflows/worker.yml` を作成し、`docs/deploy_templates/worker.yml` の内容をコピペしてもOK。


1. **Cloudflare API トークン取得**
   - https://dash.cloudflare.com/profile/api-tokens → 「Create Token」
   - テンプレート: 「Edit Cloudflare Workers」
   - 必要権限: Account = `Workers Scripts:Edit`, `D1:Edit`, `R2:Edit`
   - トークンをコピー

2. **Cloudflare Account ID 取得**
   - Cloudflare Dashboard 右サイドバー「Account ID」をコピー

3. **D1 Database ID 取得**
   - `wrangler d1 list` または Dashboard → Workers & Pages → D1
   - `medadapt-prod` の Database ID をコピー

4. **GitHub Secrets 設定**
   - GitHub リポジトリ: https://github.com/TAmJump/medadapt/settings/secrets/actions
   - 以下を「New repository secret」で追加:
     - `CLOUDFLARE_API_TOKEN` = (上記1のトークン)
     - `CLOUDFLARE_ACCOUNT_ID` = (上記2のID)

5. **wrangler.toml の database_id 差し替え**
   - `wrangler.toml` の `REPLACE_WITH_ACTUAL_D1_ID` を上記3のIDに置換
   - コミット & push

6. **R2 バケット作成**（初回のみ）
   ```bash
   wrangler r2 bucket create medadapt-files
   ```
   または Cloudflare Dashboard → R2 → 「Create bucket」

7. **D1 v16 マイグレーション適用 + Worker デプロイ**
   - GitHub → Actions → 「Deploy Cloudflare Worker」→ Run workflow
   - 「Apply D1 migration」を `true` に選択（初回のみ）
   - 2回目以降は `false`（コード変更のみ）

### 方法B: ローカルから wrangler 直接実行（緊急時・初回確認用）

```bash
# 1. wrangler インストール
npm install -g wrangler

# 2. Cloudflare 認証
wrangler login

# 3. D1 database_id 確認
wrangler d1 list
# → wrangler.toml の database_id を差し替え

# 4. R2 バケット作成（初回のみ）
wrangler r2 bucket create medadapt-files

# 5. D1 v16 マイグレーション適用（本番）
wrangler d1 execute medadapt-prod --remote --file=assets/v16_d1_migration.sql

# 6. Worker デプロイ
wrangler deploy

# 7. 動作確認
curl https://medadapt-api-v2.animalb001.workers.dev/
```

---

## デプロイ後の E2E 動作確認チェックリスト

### ① 外部連携BOX
- [ ] アプリでログイン → 患者を1人選択 → 「⑦ 外部連携BOX」タブ
- [ ] 「+ 文書をアップロード」 → 「退院サマリ」種別で登録 → トースト「登録完了（D1同期済）」
- [ ] リロード後も登録した文書が表示される（D1永続化）
- [ ] 詳細を開く → 「+ 別の組織と共有」→ 「○○訪問看護」「visiting_nurse」「閲覧のみ」で共有 → トースト「共有しました（D1同期済）」
- [ ] 「共有されたBOX」モーダル → 別アカウントでログインして受領確認できる
- [ ] 「新版発行」ボタン → v2 文書が作成され、v1 は archived 表示

### ② 居宅療養管理指導
- [ ] サイドバー「居宅療養管理指導」→ 「+ 新規記録」
- [ ] 全項目入力 → 「作成」 → 一覧に表示
- [ ] 編集モード → 「PDF出力」→ PDFダウンロード成功
- [ ] 「⑥ 記録・監査」タブで「居宅療養管理指導記録」帳票として保存されている

### ③ 歯科診療・指示書
- [ ] サイドバー「歯科診療・指示書」→ 「+ 歯科診療情報提供書」
- [ ] 主訴・口腔内所見・補綴物状態 等の歯科特有項目入力 → 作成
- [ ] 文書種別プルダウンを「歯科訪問診療指示書」に切替 → モーダル再描画され項目が「指示対象」「指示内容」に変わる

### ④ 診療情報提供書
- [ ] サイドバー「診療情報提供書」→ 「+ 新規発行」
- [ ] 全項目入力 → 「発行」
- [ ] 編集モード → 「（手動で）受領確認」ボタン → 「受領確認済」緑バナーに変わる

### ⑤ 過去引継ぎ
- [ ] 既存アセスメントがある患者で、新規アセス作成 → 確認ダイアログ「前回のアセスメント（YYYY-MM-DD）の値を引き継ぎますか？」
- [ ] 「OK」→ 黄色背景のフィールドが表示される
- [ ] 1つのフィールド編集 → 黄色背景が解除される

### ⑥ 医師認証フォーム
- [ ] 設定画面 → 「医師認証・署名権限」セクション
- [ ] 医籍登録番号・所属医療機関を入力 → 「プロフィール保存」
- [ ] 「免許証画像アップロード」→ jpg を選択 → R2 アップロード成功
- [ ] admin アカウントで「資格確認済みにする」→ バッジが「認証済み」に変わる

### ⑦ 保存期限通知
- [ ] 患者ハブの「次にやること」に「保存期限残N日：○○」表示
- [ ] クリック → 外部連携BOXタブへ遷移

### ⑧ アクセス制御
- [ ] 別組織アカウントでログイン → 自院以外の同意書 URL に直接アクセス → 「閲覧権限がありません」403
- [ ] `clinic_dent`（歯科）アカウントに `visit_nurse_instruction`（訪問看護指示書）を共有しようとする → 403「この役割（clinic_dent）には visit_nurse_instruction の共有は許可されていません」

---

## 障害時のロールバック手順

### Worker ロールバック
```bash
# 前のバージョンに戻す
wrangler rollback --version-id <PREVIOUS_VERSION_ID>
```
または Cloudflare Dashboard → Workers → medadapt-api-v2 → Deployments → 「Rollback」

### D1 ロールバック
v16 マイグレーションは ALTER TABLE で列追加のみのため、データ破壊なし。
ロールバックが必要な場合は新規テーブルのみ DROP:
```sql
DROP TABLE IF EXISTS medical_document_shares;
DROP TABLE IF EXISTS medical_document_access_logs;
DROP TABLE IF EXISTS doctor_profiles;
DROP TABLE IF EXISTS medical_document_versions;
```
※ ALTER 列の削除は SQLite では困難。アプリ側で参照しないようにすればよい。

### R2 ロールバック
データ削除は手動（`wrangler r2 object delete medadapt-files <key>`）。
バケット自体は残しても害なし。

---

## トラブルシューティング

### Q. `wrangler deploy` で「Authentication error」
→ `wrangler login` 再実行 or `CLOUDFLARE_API_TOKEN` の権限確認

### Q. D1 マイグレーションで「table already exists」
→ `IF NOT EXISTS` が効いているため無害。次のステップに進む。

### Q. `ALTER TABLE` で「duplicate column name」
→ 列が既に存在している（再実行時の正常動作）。無視してよい。

### Q. R2 アップロードで 503「R2 バケットが設定されていません」
→ `wrangler.toml` の `[[r2_buckets]]` binding が未設定 or バケット未作成。
→ `wrangler r2 bucket create medadapt-files` 実行後、再デプロイ。

### Q. CORS エラー
→ Worker の `cors` ヘッダ確認（既存）。`Access-Control-Allow-Origin: *` が設定されている。

---

## 次セッションへの引き継ぎ事項

- D1 / Worker / R2 すべて Cloudflare 側のデプロイは大下さんの手元で `wrangler` または GitHub Actions 経由で実行
- 実 HPKI 連携は半年後タスク（外部CA契約必要）
- 実 TSA 連携も半年後タスク（セイコー/アマノ/GMO のいずれか月額契約）
- 画像最適化（R2 + Cloudflare Images）は将来検討
