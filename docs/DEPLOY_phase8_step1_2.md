# Phase 8 マッサージ同意書 デプロイ手順書（v4.3 / 2026-05-24）

設計書 v4.3 §41〜§47 に基づく Phase 8 STEP 1〜2 の実装が完了しました。
本書は **大下が Cloudflare ダッシュボードで実行する作業**を順序立てて記載します。

---

## STEP 1: D1 migration 実行（必須）

medadapt-db に Phase 8 用テーブル 4 つを追加します。

### 1-1. Cloudflare ダッシュボードから実行

1. https://dash.cloudflare.com → Workers & Pages → D1 → `medadapt-db` を開く
2. 「Console」タブを開く
3. リポジトリの `assets/v12_d1_setup.sql` の中身をコピーして貼り付け
4. 「Execute」をクリック
5. 4 つのテーブル（consent_forms / treatment_plans / signature_events / hash_chain）と 1 つの role（med_acupuncturist）が追加される

### 1-2. 確認クエリ

```sql
SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'consent%' OR name='hash_chain' OR name='treatment_plans' OR name='signature_events';
```

期待結果：4 行返る（consent_forms / treatment_plans / signature_events / hash_chain）

```sql
SELECT * FROM roles WHERE id='med_acupuncturist';
```

期待結果：1 行返る（鍼灸マッサージ師 / medical-adapt）

---

## STEP 2: Worker デプロイ（必須）

`assets/worker_v7_complete.js` に Phase 8 API 13 本 + ヘルパー関数を追加しました。

### 2-1. Cloudflare ダッシュボードから実行

1. https://dash.cloudflare.com → Workers & Pages → `medadapt-api-v2` を開く
2. 「Edit code」または「Quick Edit」
3. リポジトリの `assets/worker_v7_complete.js` の中身をコピーして貼り付け（**全置換**）
4. 「Save and deploy」をクリック
5. デプロイ後の動作確認：以下を curl などで叩く

```
GET https://medadapt-api-v2.{your-subdomain}.workers.dev/consent/list
Authorization: Bearer {your-token}
```

期待結果：`{"ok":true,"items":[]}`（最初は空配列）

### 2-2. 追加された API 一覧

| Method | Path | 用途 |
|---|---|---|
| POST | /consent/create | 同意書 + 計画書 新規作成 |
| GET | /consent/list | 一覧（自院 + 共有された分） |
| GET | /consent/:id | 詳細 |
| PUT | /consent/:id | 下書き編集 |
| POST | /consent/:id/sign-doctor | 医師署名 |
| POST | /consent/:id/sign-patient | 患者署名 |
| POST | /consent/:id/share | 鍼灸師に共有 |
| POST | /consent/:id/revoke | 取消し |
| POST | /consent/:id/renew | 再同意発行 |
| GET | /consent/:id/verify | ハッシュチェーン検証（公開） |
| GET | /consent/:id/pdf | PDF 取得 |
| POST | /consent/:id/pdf-upload | PDF 保存（クライアント生成版） |
| POST | /consent/:id/report | 施術報告書 |

---

## STEP 3〜5（次フェーズ）

| STEP | 内容 | 担当 |
|---|---|---|
| 3 | app.html に「同意書管理」メニュー + 一覧/詳細/作成 UI | Claude（次セッション） |
| 4 | patient-consent.html / acupuncturist-portal.html 新規作成 | Claude（次セッション） |
| 5 | PDF 生成（Cloudflare Browser Rendering API）+ QR 生成 + ハッシュ埋め込み | Claude（Browser Rendering binding 追加が前提） |

---

## §48 医監修パートナー表示（v4.3）

### 3-1. LP（index.html）

✅ 実装済み：ヒーロー直下に「医監修パートナー」セクション追加
- 写真ファイル `assets/img/dr_goto_motoharu.jpg` は未配置（後藤先生から実写取得後にアップロード）
- 未取得時は医師アイコン SVG プレースホルダーが自動表示される

### 3-2. app.html

✅ 実装済み：サイドバーフッタに「医監修：後藤基温医師（医療法人社団コンパス 理事長）」1 行追加

### 3-3. 大下アクションアイテム（設計書 §48-4）

- [ ] 後藤先生に §48-1 プロフィール掲載の許諾を取得（書面）
- [ ] 後藤先生から顔写真（白衣 or スクラブ・正方形）を取得
- [ ] 取得した写真を `assets/img/dr_goto_motoharu.jpg` として配置 → push

---

## §49 画像生成（v4.3）

ChatGPT 用プロンプト集は設計書 §49-2〜§49-5 にあります。
生成した画像は `assets/img/generated/` 配下に命名規則に従って保管：

```
{用途}_{シーン}_{バリエーション}.png
例: hero_visit_v1.png
```

詳細は `assets/img/README.md` 参照。

---

## デプロイ後の動作確認シナリオ

### シナリオ A：管理者が同意書を新規作成

```bash
# 1. ログイン（既存方法）
curl -X POST {WORKER_URL}/auth/login \
  -d '{"login_id":"ADM-XXXXXX","password":"..."}'
# → token を保存

# 2. 同意書作成
curl -X POST {WORKER_URL}/consent/create \
  -H "Authorization: Bearer {token}" \
  -d '{
    "patient_id": "PT-XXXXX",
    "consent_type": "massage",
    "disease_names": [{"name":"変形性膝関節症","onset_date":"2023-04-01"}],
    "consent_date": "2026-05-24",
    "validity_months": 6,
    "treatment_plan": {
      "visit_frequency": "biannual",
      "evaluation_frequency": "monthly",
      "goals": "歩行能力の維持",
      "treatment_method": "あマ指施術"
    }
  }'
# → {"ok":true,"consent_form_id":"CF-xxxxx","treatment_plan_id":"TP-xxxxx"}
```

### シナリオ B：医師署名 → 患者署名 → 検証

```bash
# 3. 医師署名
curl -X POST {WORKER_URL}/consent/CF-xxxxx/sign-doctor \
  -H "Authorization: Bearer {token}" \
  -d '{"signature_method":"typed_name","signature_data":"後藤基温"}'

# 4. 患者署名
curl -X POST {WORKER_URL}/consent/CF-xxxxx/sign-patient \
  -H "Authorization: Bearer {token}" \
  -d '{"signature_method":"typed_name","signature_data":"山田太郎"}'

# 5. 検証（認証不要）
curl {WORKER_URL}/consent/CF-xxxxx/verify
# → {"valid":true,"content_hash":"...","chain_index":1,...}
```

---

## 罠と注意点（設計書から再掲）

- **罠 §37-15**：既存テーブルへの ALTER は行わない。v12 では新規テーブル 4 つの追加 + roles INSERT のみ
- **罠 §47-2**：Browser Rendering binding は STEP 5 で wrangler.toml に追加が必要（`[browser] binding = "BROWSER"`）
- **CPU 時間**：ハッシュ計算は Web Crypto API（高速）で実装済み。PDF 生成は Browser Rendering（別 service）に分離予定
- **TSA**：Phase 9 へ繰り越し。今は tsa_token 等のカラムは空で OK
- **HMAC 共有トークン**：QR コードの token クエリ検証は STEP 5 PDF 生成時に組み込み

---

最新 HEAD（push 後）：medadapt `{ commit }` ← Phase 8 STEP 1+2 + §48 表示
