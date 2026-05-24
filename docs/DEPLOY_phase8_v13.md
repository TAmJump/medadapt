# Phase 8 v13 デプロイ手順書（v4.5 / 2026-05-24）

設計書 v4.5 §51〜§54 に基づく Phase 8 再定義の実装。

**v4.4 からの差分**：
- 単一の同意書機能 → **全帳票共通の改ざん防止基盤**に再構築
- 既存 v12 実装（consent_forms 等）は破壊せず温存
- コンパスクリニック書式の HTML テンプレート追加（実物 docx 1:1 再現）
- 医療保険算定対応（B013 療養費同意書交付料 100点 / B004 退院時共同指導料 / 訪問看護退院時共同指導加算）
- app.html に「同意書」「加算管理」メニュー追加（既存メニュー無傷）

---

## STEP 1: D1 migration 実行（必須）

medadapt-db に v13 のテーブルを追加。

### 1-1. Cloudflare ダッシュボードから実行

1. https://dash.cloudflare.com → Workers & Pages → D1 → `medadapt-db` を開く
2. 「Console」タブ
3. リポジトリの `assets/v13_d1_setup.sql` の中身をコピーして貼り付け
4. 「Execute」をクリック
5. 追加されるもの：
   - `signed_documents` テーブル + 6 INDEX
   - `document_attestations` テーブル + 2 INDEX
   - `insurance_claim_log` テーブル + 3 INDEX
   - roles へ `witness`（立会人）ロール

### 1-2. 確認クエリ

```sql
SELECT name FROM sqlite_master WHERE type='table'
AND name IN ('signed_documents','document_attestations','insurance_claim_log');
```
→ 3 行返ること

```sql
SELECT * FROM roles WHERE id IN ('med_acupuncturist','witness');
```
→ 2 行返ること（v12 で追加した med_acupuncturist + v13 で追加した witness）

### 1-3. v12 がまだ未投入の場合

先に v12 を投入：`assets/v12_d1_setup.sql` を同じ手順で実行。

---

## STEP 2: Worker デプロイ（必須）

`assets/worker_v7_complete.js` に共通改ざん防止 API 9 本追加 + v12 verify の認証スキップ修正済。

### 2-1. Cloudflare ダッシュボードから実行

1. https://dash.cloudflare.com → Workers & Pages → `medadapt-api-v2`
2. 「Edit code」
3. リポジトリの `assets/worker_v7_complete.js` を**全置換**
4. 「Save and deploy」

### 2-2. 追加された API 一覧（v13）

**公開エンドポイント（認証なし・QR / 検証 URL から第三者アクセス可）：**
| Method | Path | 用途 |
|---|---|---|
| GET | /verify/document/:sd_id | 共通改ざん検証 |
| GET | /consent/:id/verify | v12 互換（公開化済） |

**認証必須エンドポイント：**
| Method | Path | 用途 |
|---|---|---|
| POST | /signed-docs/finalize | 任意の帳票を確定して改ざん防止登録 |
| GET | /signed-docs/list | 一覧（doc_kind / patient_id / claim_kind フィルタ可） |
| GET | /signed-docs/:id | 詳細 |
| POST | /signed-docs/:id/attest | 共通署名イベント追加 |
| POST | /signed-docs/:id/claim | 保険算定の記録 |
| GET | /signed-docs/claim-summary | 月次算定サマリ |
| GET | /signed-docs/:id/qr | QR ペイロード返却 |
| GET | /signed-docs/by-doc/:kind/:id | 既存帳票 ID から逆引き |

### 2-3. 動作確認

```bash
# 1. 公開検証エンドポイント（認証なしでアクセス可能）
curl https://medadapt-api-v2.{subdomain}.workers.dev/verify/document/SD-DUMMY
# → {"error":"文書が見つかりません"} （404 だが認証は通る）

# 2. 加算サマリ（要認証）
curl -H "Authorization: Bearer {token}" \
  https://medadapt-api-v2.{subdomain}.workers.dev/signed-docs/claim-summary?month=2026-05
# → {"ok":true,"month":"2026-05","summary":[]}
```

---

## STEP 3: GitHub Pages 反映確認（自動）

push 後 1〜3 分で以下が反映：

- https://myaruze.tamjump.com/app.html
  - 左メニューに「**同意書**」「**加算管理**」が追加されている
  - サイドバーフッタに医監修クレジット表示
- https://myaruze.tamjump.com/index.html
  - ヒーロー直下に医監修パートナーセクション

---

## STEP 4: 機能動作確認（app.html 上で）

### 4-1. 同意書発行フロー

1. app.html ログイン → 左メニュー「同意書」
2. 「+ 同意書を発行する」
3. 患者選択 → 施術種別「あマ指」→ 同意日 → 有効6か月 → 傷病名（例：「変形性膝関節症（両）:2023-04-01」）→ 通院困難理由チェック → 算定対象 ON
4. 「発行する（医師署名へ進む）」→ 同意書詳細画面へ自動遷移
5. 「医師署名する」→ 氏名入力 → 状態が「医師署名済」に
6. 「患者署名する」→ 氏名入力 → 状態が「確定」に。`signed_documents` に自動 finalize される
7. 「PDFをプレビュー」→ 別タブでコンパス書式が表示される（実物 docx と同レイアウト）
8. 「QR検証URLをコピー」→ コピーした URL を別ブラウザで開くと改ざん検証ページ（公開）

### 4-2. 加算管理

1. 左メニュー「加算管理」
2. 当月の算定サマリ表示
3. 「算定対象」状態の同意書に「算定記録」ボタン → 算定済みに

---

## STEP 5: 既存帳票への適用（次フェーズで実装）

退院通知発行完了時 / NDA signed 時にも `/signed-docs/finalize` を呼ぶよう dischargePage / ndaPage を改修。本 v13 の段階では同意書のみ自動 finalize。

```javascript
// 例：dischargePage の発行完了時に追加
await api('/signed-docs/finalize', {method:'POST', body:JSON.stringify({
  doc_kind: 'joint_guidance_record',
  doc_id: dischargeId,
  title: '退院時共同指導記録 ' + patientName,
  content: dischargeRecord,
  patient_id: patientId,
  insurance_claim_kind: 'b004_taiin_kyodo_1',
  claim_points: 1500,
  claim_unit: 'medical_points'
})});
```

---

## 既存機能への影響（v13 で破壊していないこと）

- ✓ 退院通知（discharge_notices）：機能無傷
- ✓ NDA管理（org_ndas）：機能無傷
- ✓ 患者・利用者 / ダッシュボード / スタッフ管理 / 設定：機能無傷
- ✓ v12 で実装した同意書 API 13 本：機能無傷（verify だけ認証スキップに修正）
- ✓ 既存テーブル：ALTER 一切なし（罠 §37-15 絶対遵守）

---

## ロールバック手順（万一の場合）

1. Cloudflare Workers → medadapt-api-v2 → 旧バージョン（v12 段階の commit）に戻す
2. D1 は新規テーブルなので DROP TABLE で削除可能：
   ```sql
   DROP TABLE IF EXISTS insurance_claim_log;
   DROP TABLE IF EXISTS document_attestations;
   DROP TABLE IF EXISTS signed_documents;
   DELETE FROM roles WHERE id='witness';
   ```
3. app.html は git revert で前 commit に戻す

---

## 次セッション着手点

- 退院通知 / NDA の発行完了時に自動 finalize する dischargePage / ndaPage 改修
- patient-consent.html / acupuncturist-portal.html 新規作成（患者ポータル / 鍼灸師ポータル）
- Cloudflare Browser Rendering API でサーバ側 PDF 生成（クライアント側依存からの脱却）
- Phase 9 認定 TSA 統合（アマノ等と契約）

---

最新 HEAD：medadapt `{push 後に確認}`
