# ｍやるゼ！（医療介護連携OS）開発ハンドオーバー v7.0
最終更新: 2026-06-29 ／ 作成: Claude（JIN＝大下 甚／タムジ.Corp 代表 の技術コビルダー）

> このドキュメント1枚で新しいチャットから完全に再開できることを目的とする。端折りなし。
> 役割分担：**コード実装・GitHub push は Claude が自律実行**／**Cloudflare・wrangler・DNS・Workerデプロイ・secrets は JIN が実行**。

---

## ★ v7.0 最重要トピック（前回 v6.0 から必読の変更）

### A. Worker は「手動 Deploy」必須（push では絶対に反映されない）— 今セッション最大の落とし穴
- リポジトリの GitHub Actions は **`.github/workflows/static.yml` の1本だけ**で、中身は **GitHub Pages（フロント app.html）のデプロイ専用**。
- **Worker（medadapt-api-v2）を自動デプロイするワークフローは存在しない。**
- したがって：
  - **フロント（app.html / index.html / assets/*.html）** → `git push` で Actions が走り **GitHub Pages に自動反映**。
  - **Worker（medadapt-api-v2）** → `git push` しても **1ミリも反映されない**。**Cloudflare ダッシュボード → medadapt-api-v2 → Edit code に最新 `assets/worker_v7_complete.js` を全文貼り付け → Deploy** を JIN が手動実行して初めて反映される。
- `wrangler.toml` は `database_id = "REPLACE_WITH_ACTUAL_D1_ID"`（未差し替え）・`database_name = "medadapt-prod"`（本番は `medadapt-db`）で**そのままでは `wrangler deploy` できない**。手動 Edit code 運用が前提。バインディング（DB/ADAPT_SVC/R2/secrets）はダッシュボードに既設なのでコードだけ差し替える。
- **将来の改善案（任意）**：GitHub Actions に Cloudflare Wrangler 自動デプロイを追加。要 ①`CLOUDFLARE_API_TOKEN` を GitHub Secrets に登録 ②`wrangler.toml` の `database_id` を実IDに ③R2 バインディング整合。

### B. Worker の正本は `assets/worker_v7_complete.js`（≈3938行）
- `wrangler.toml` の `main = "assets/worker_v7_complete.js"`。
- 認証ブロックは L606〜（token無し→401「認証が必要です」／session期限切れ→401「セッションが切れています」／ユーザー無し→401）。
- ルーター末尾フォールバックは `return err('Not found', 404)`（≈L3245）。consent ルートはそれより手前＝到達可能。
- OPTIONS（CORS preflight）は冒頭 L17 で `if (request.method === 'OPTIONS') return new Response(null, { headers: cors })`。CORS は `*`。

### C. 同意書 発行〜医師署名〜PDF が「動く状態」になった（今セッションで開通）
- 発行（`/consent/create`）→ 医師署名（`/consent/:id/sign-doctor`）→ PDFプレビューまで通る。
- これに至るまで **404が3層** あり、順に解消（§3-2 デバッグ経緯参照）。

---

## 0. 認証情報・接続情報（最重要・厳重管理）

| 項目 | 値 |
|---|---|
| GitHub PAT | `ghp_xxxxxxxx（PATは別途・GitHubには載せない）` |
| git user.name | `TAmJump` |
| git user.email | `animalb001@gmail.com` |
| リポジトリ | `TAmJump/medadapt` |
| 本番URL | https://myaruze.tamjump.com （GitHub Pages 自動デプロイ。`static.yml`） |
| API（Worker） | `medadapt-api-v2` ／ https://medadapt-api-v2.animalb001.workers.dev ／ **手動Deploy** |
| 通話補助Worker | `medadapt-whereby` |
| Cloudflareアカウント | `tamj_Account` ／ Account ID `b9de28abfd009bbf696ceec4da62c5b8` ／ subdomain `animalb001.workers.dev` |
| D1 | バインディング名 `DB` → データベース `medadapt-db` |
| Service binding | `ADAPT_SVC` → 親 `adapt-api`（子→親 課金同期用） |

**コミット／pushコマンド（Claudeが使用）**
```bash
git -c user.name=TAmJump -c user.email=animalb001@gmail.com commit -q -m "..."
git push -q https://TAmJump:ghp_xxxxxxxx（PATは別途・GitHubには載せない）@github.com/TAmJump/medadapt.git HEAD:main
```

**Worker（medadapt-api-v2）の env／secrets 名一覧**（値はCloudflare secretsに格納。Claudeは値を保持しない）
- `DB`（D1）, `ADAPT_SVC`（Service binding）, R2 バインディング（テンプレ/PDF保管、`MEDADAPT_FILES`）
- SES: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, `FROM_EMAIL`
- Square: `SQUARE_ACCESS_TOKEN`, `SQUARE_APP_ID`, `SQUARE_LOCATION_ID`, `SQUARE_PLAN_VARIATION_ID`, `SQUARE_API_BASE`, `SQUARE_VERSION`, `SQUARE_WEBHOOK_SIGNATURE_KEY`
- 内部連携: `INTERNAL_API_KEY`

---

## 1. 禁止語・表記ルール（全コピーで厳守）

- 禁止語（ユーザー向けコピー）：**完全 / 完璧 / 100%（コピー内） / ゼロ / 地獄**
  - ※ CSSの `width:100%` 等、コード内コメントは対象外（誤検出は無視）。
- **「鍼灸」は単独表記禁止**。必ず「はり・きゅう」または「はり師きゅう師」「あん摩マッサージ指圧」「鍼灸・マッサージ」「訪問マッサージ（鍼灸・マッサージ）」で表記。
- 装飾・絵文字・アイコンの無断追加禁止。デザインは白背景＋ヘアライン＋抑えた差し色。
- **検証フロー（毎コミット必須）**：`<script>` を全部抽出 → `node --check` → 禁止語 grep。
  ```bash
  python3 -c "import re;html=open('app.html',encoding='utf-8').read();body=''.join(s for s in re.findall(r'<script[^>]*>(.*?)</script>',html,re.DOTALL) if s.strip());open('/tmp/chk.js','w',encoding='utf-8').write(body)"
  node --check /tmp/chk.js
  ```

---

## 2. ファイル構成・主要アンカー（app.html ≈7400+行 / worker ≈3938行）

> 行番号は今セッションの編集でずれる。**必ず grep で再特定**すること。以下は機能アンカー。

**app.html（単一HTML・DOM生成JS。`h()`でDOM生成、`rr()`がルーター）**
- `const API='https://medadapt-api-v2.animalb001.workers.dev'`
- `let D={...consentDrafts,...}`（state）／`let S={...}`（画面状態。`S.user`=role/org/org_name/name/email/login_id/plan/owner_email）
- `api(path,opts)`：fetch ラッパ。token は `localStorage 'medadapt_token'`（`loadToken/saveToken`）。**401でログイン画面へ（rr）／404は toast して return null（フォーム再描画しない＝入力は消えない）**。`{silent404:true}` で404を握り潰し。
- `loadFromCloud()`（/sync GET）／`sv()`（D→localStorage＋/sync POST）。
- ナビ配列：patients/admin/staff/discharge/nda/**consent**/medical_referral/kyotaku/dental/claims/disaster/settings。**※ `acu_massage` はナビから削除済（後方互換ルートのみ）。`consent` ラベル＝「同意書」1つに統合。**
- ルーティング：`S.page==='consent'`→`acuMassagePage()`（①②③ハブ）／`S.page==='consent_list'`→`consentPage()`（一覧）／`S.page==='consent_detail'`→`consentDetailPage()`／`S.page==='consent_new'`→`consentNewPage()`／`acu_massage`→consentハブへ後方互換リダイレクト。
- `acuMassagePage()`：同意書ハブ。タイトル「同意書」、①同意書を発行（→consent_new、`S._editingWipId=null`）②発行済み同意書を見る（→consent_list）③療養費同意書交付料を算定（→claims）。説明は「訪問診療同意書メイン＋療養費の2系統」。
- `consentNewPage()`：発行フォーム。施術種別セレクト `cf-type`（**request_form＝訪問診療同意書（依頼書）が先頭・初期選択**／massage／acupuncture／both）。**あて先 `cf-addressee-sel`・発行元 `cf-clinic-sel`（登録→選択＋新規登録）**、同意日 `cf-date`、有効期間、傷病名、症状チェック、通院困難事由、B013算定 `cf-claim`。
- `getConsentMasters()/saveConsentMasters()`：あて先・発行元マスタ（localStorage `medadapt-consent-masters`）。初期値に「医療法人コンパス」。
- `serializeWip()/applyWip()`：下書きシリアライズ。`patientId/patientName/addressee/clinicId/consent_type/...` を保持。
- `previewConsentPDF(cfId)`：`/consent/:id`＋`/signed-docs/by-doc/...` を取得→テンプレHTMLを `window.open`→`consentTemplateRender(data)` で差し込み。consent_type で template 分岐（request_form/both→`consent_form_template.html`、acupuncture→`consent_form_acupuncture_template.html`、massage→`consent_form_massage_template.html`）。
- `consentDetailPage()`：詳細。「医師署名する」「PDFをプレビュー」（下書き〜確定の全状態で表示）「取消し」。
- `consentPage()`：発行済み一覧。カードに **PDFボタン**追加済（`previewConsentPDF(item.id)`、stopPropagationでカードクリックと分離）。`typeLabels` に request_form='訪問診療同意書（依頼書）' 追加済。

**assets/consent_form_template.html（依頼書テンプレ・720行）**
- `window.consentTemplateRender(data)` がプレースホルダに差し込み。
- 差し込み id：`addressee-name`（あて先）／`visit-plan`／`difficulty-grid`／`patient-address/name/phone`（自署）／`clinic-block`（発行元）／`e-cert-banner`＋`cert-signer/cert-timestamp/cert-tsa-authority`（電子署名バナー）／`timestamp-cert`＋`ts-*`（タイムスタンプ証明書）／`sd-id`/`content-hash-short`/`chain-index`（フッタ）／`qr-image`（検証QR）。
- 署名バナーは `data.signature.signed_at` があると表示。ラベルは `data.signature.signer_label`（医師署名なら「後藤 基温 医師（医療法人コンパス）」）優先、無ければ患者名（依頼者）。

---

## 3. Worker（medadapt-api-v2）の現状

### 3-1. 認証・データ所有者（今セッションで重要修正）
- 認証：`/auth/login`（login_id or email）, `/auth/qr-login`, 招待 `/staff-register`。session token 90日。`email_verified=0` だと403（新規adminログイン不可の典型。応急処置 §7）。
- **データ所有者は org admin に統一**（今セッション修正）：認証直後に
  ```js
  const _orgId = currentUser.org_id || currentUser.id;
  const _orgAdmin = currentUser.role==='admin' ? currentUser
    : await env.DB.prepare('SELECT * FROM users WHERE id=? AND role=?').bind(_orgId,'admin').first();
  const currentEmail = _orgAdmin ? _orgAdmin.email : currentUser.email;
  ```
  これで `/sync` 保存（ownerEmail＝admin email）と各検索（owner_email）が一致。スタッフ/サブアカウントでも同 org の患者・帳票にアクセス可。
- **特権アカウント全機能無料**（今セッション追加）：認証直後に
  ```js
  const PRIVILEGED_LOGIN_IDS = ['ADM-4D3R62']; // 監修医師 後藤 基温
  const PRIVILEGED_EMAILS = [];
  if ((currentUser.login_id && PRIVILEGED_LOGIN_IDS.includes(currentUser.login_id)) ||
      (currentUser.email && PRIVILEGED_EMAILS.includes(currentUser.email))) currentUser.plan='pro';
  ```
  → `/sync`・`/auth/me`・モジュールアクセス・フロント freeCheck・Freeバッジ・決済導線がすべて Pro 扱い。今後アカウントを足すならこの配列に追記して再Deploy。
- `/sync` GET/POST は patients/cases/conferences/monitors/assessments のみ owner_email 単位で保存・返却。
- **/sync POST の upsert は owner_email も ON CONFLICT 更新する**（今セッション修正：以前は owner_email を更新せず、古い owner_email が固定→「患者が見つかりません」404の根因だった）。

### 3-2. 今セッションの 404/500 デバッグ経緯（再発時の指針）
発行ボタンが通るまで、原因が層になっていた。**コンソールで切り分けるワンライナー**が有効：
```js
// 認証なしGETで本番Workerの実体確認（401「認証が必要です」が出れば worker_v7 稼働）
fetch('https://medadapt-api-v2.animalb001.workers.dev/consent/list').then(r=>r.text().then(t=>console.log('STATUS',r.status,'BODY',t)))
// sync→create を実データで（CREATEのBODYで原因確定）
(async()=>{const t=localStorage.getItem('medadapt_token');const s=await fetch('https://medadapt-api-v2.animalb001.workers.dev/sync',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+t},body:JSON.stringify(D)});console.log('SYNC',s.status,await s.text());const c=await fetch('https://medadapt-api-v2.animalb001.workers.dev/consent/create',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+t},body:JSON.stringify({patient_id:D.patients[0].id,consent_type:'request_form',consent_date:'2026-06-29'})});console.log('CREATE',c.status,await c.text())})()
```
- **層① Worker 未デプロイ**：consent ルートが本番に無く全404 → 手動 Deploy で解消。
- **層② owner_email の保存/検索ズレ**：404「患者が見つかりません」→ 認証直後 currentEmail を org admin に統一（3-1）。
- **層③ sync が owner_email を更新しない**：既存患者の owner_email が古いまま固定 → upsert の ON CONFLICT に `owner_email=excluded.owner_email` 追加。
- **層④（500）consent系テーブルが本番D1に未作成**：マイグレーション漏れ → initDB に CREATE TABLE 追加（3-3）。
- **層⑤（sign-doctor 500）hash_chain 主キー列名不一致**：コードは `chain_index` 参照・テーブルは `id` で作成 → CREATE を `chain_index` 主キーに統一＋`ALTER TABLE hash_chain RENAME COLUMN id TO chain_index` で既存テーブルも自動マイグレート。

### 3-3. consent系テーブル（今セッションで initDB に追加）
`initDB(env.DB)` は L39 でリクエストごとに `CREATE TABLE IF NOT EXISTS` を実行（=Deployだけで自動作成、D1手動操作不要）。追加したテーブル：
```sql
CREATE TABLE IF NOT EXISTS consent_forms (id TEXT PRIMARY KEY, org_id TEXT, patient_id TEXT, doctor_user_id TEXT, consent_type TEXT, disease_names TEXT, notes TEXT, consent_date TEXT, validity_months INTEGER, expires_at TEXT, visit_plan TEXT, difficulty_reasons TEXT, clinic_name TEXT, clinic_address TEXT, clinic_tel TEXT, clinic_fax TEXT, doctor_name TEXT, patient_name TEXT, patient_address TEXT, patient_birth TEXT, form_payload TEXT, status TEXT DEFAULT 'draft', renewed_from TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS treatment_plans (id TEXT PRIMARY KEY, consent_form_id TEXT, org_id TEXT, patient_id TEXT, doctor_user_id TEXT, visit_frequency TEXT, evaluation_frequency TEXT, goals TEXT, treatment_method TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS signature_events (id TEXT PRIMARY KEY, consent_form_id TEXT, signer_user_id TEXT, signer_role TEXT, signature_method TEXT, signature_data TEXT, signed_at TEXT, signed_ip TEXT, signed_user_agent TEXT, event_hash TEXT, prev_event_hash TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS hash_chain (chain_index INTEGER PRIMARY KEY AUTOINCREMENT, entity_type TEXT, entity_id TEXT, entity_hash TEXT, prev_chain_hash TEXT, chain_hash TEXT, created_at TEXT);
-- 既存テーブル救済（idで作られていた本番用）：
ALTER TABLE hash_chain RENAME COLUMN id TO chain_index;
```

### 3-4. 同意書 署名フロー（worker）
- `POST /consent/create`：権限（med_clinic/org_staff/org_admin/admin）→必須（patient_id/consent_type/consent_date）→request_form 以外は disease_names 必須→**患者検索（ownerEmail基準＋org JOIN救済）**→consent_forms＋treatment_plans を batch INSERT。`status='draft'`。
- `GET /consent/:id`：`{ ok, consent_form, treatment_plan, signatures }` を返す（**signatures＝署名イベント配列。PDFはここから医師署名を拾う**）。
- `POST /consent/:id/sign-doctor`：med_clinic/admin のみ。draft のみ。signature_events INSERT→`appendHashChain('signature_event',...)`→consent_forms.status='signed_by_doctor'。
- `POST /consent/:id/sign-patient`：signed_by_doctor のみ。署名→hash_chain→content_hash/chain_index 更新→status='signed_by_patient'。
- `appendHashChain(env,entityType,entityId,entityHash)`：`SELECT chain_hash FROM hash_chain ORDER BY chain_index DESC LIMIT 1` で前ハッシュ取得→sha256→hash_chain INSERT。
- 「確定（finalize）→ signed_document 生成＋タイムスタンプ（TSA）」は患者署名後フェーズ。**request_form の確定運用（医師署名のみで確定するか／患者自署まで要るか）は要設計判断**（現状：医師署名済の情報は PDF に出る、TSA確定は patient署名→finalize後）。

### 3-5. B1（組織レベル同期・未デプロイ）
- 組織レベルデータ（consentLog/opLog/medLinks/emergencyContacts/disaster/broadcasts/safetyReports/consentDrafts）の `/sync` 拡張パッチ：`medadapt-api-v2_B1_sync_patch.md`（initDB／GET /sync／POST /sync の3箇所）。**未デプロイ**。これが無いと監査ログ・連携先・災害・下書きが別端末/再ログインで消える。

---

## 4. 同意書まわり 今セッション実装まとめ（フロント・worker）

1. **ナビ統合**：「同意書（訪問診療）」＋「訪問マッサージ（鍼灸）」→「同意書」1つ。クリックで①②③ハブ。`acu_massage` は後方互換でハブへ。
2. **訪問診療同意書をメイン**：ハブ／①カード／施術種別ドロップダウン（request_form 先頭・初期選択）／一覧 typeLabels。ハブ下部の説明を「訪問診療同意書（依頼書）メイン＋はり・きゅう/あマ指 療養費」の2系統に整合化。
3. **入力が消えない**：必須漏れは markErr で赤枠のみ（rr()しない＝DOM入力保持）。**入力の自動退避**（form の input/change を debounce700ms で localStorage `medadapt-consent-wip`、復元バナーで戻せる）。
4. **一時保存＝複数患者対応**：`D.consentDrafts` に `kind:'wip'` で複数件保存（patientごと。`S._editingWipId` で更新/新規判定）。発行画面上部に「一時保存した下書き（N件）」一覧（再開・削除）。※ `D.consentDrafts` のクラウド同期は §3-5 B1 が要るが、ローカル保持は機能。前回コピペ候補は `kind!=='wip'` で除外。
5. **PDFボタン**：一覧カード右に「PDF」直接ボタン。詳細にも「PDFをプレビュー」。
6. **PDFに医師署名・タイムスタンプ反映**：`previewConsentPDF` が `detail.signatures` から doctor 署名を拾い、`data.signature`（signed_at／signer_label）・`doctor.has_seal`・`content_hash=event_hash`・`chain_index` を渡す。テンプレの signerLabel は signer_label 優先。
7. **あて先・発行元の登録→選択**：`getConsentMasters/saveConsentMasters`（localStorage `medadapt-consent-masters`）。発行フォームは `cf-addressee-sel`/`cf-clinic-sel` のドロップダウン＋「＋新規登録」（prompt）。body は選択発行元（id→clinic解決）と form_payload.addressee で送信。下書き保持にも対応（addressee/clinicId）。
8. **monetize/owner**：特権アカウント無料化（§3-1）、owner_email 統一（§3-1）。

---

## 5. 書類（医師同意・指示書）— 正式様式化プロジェクト（継続）

### 5-1. 公式様式の根拠（再調査不要）
療養費同意書は**はり・きゅう用／あん摩マッサージ指圧用の2様式が別物**（厚労省 新様式・令和6年10月〜）。
- **はり・きゅう**：対象6疾患＝神経痛／リウマチ／頸腕症候群（レセは「頸肩腕症候群」）／五十肩／腰痛症／頸椎捻挫後遺症＋その他。
- **あマ指**：症状＝筋麻痺／関節拘縮／その他、種類＝マッサージ／変形徒手矯正術、部位＝躯幹/右上肢/左上肢/右下肢/左下肢。
- 共通必須：発病年月日、初回/再同意、**往療：必要とする/しない＋理由**、注意事項等欄、保険医署名。
- 期間：はり・きゅう/マッサージ＝6ヶ月、**変形徒手矯正術＝1ヶ月**。B013算定時はレセ摘要欄に病名記載。

### 5-2. 残タスク（順番に・正しさ最優先で1書類ずつ）
1. **あて先・発行元マスタのクラウド同期**（今は localStorage のみ＝端末依存）。worker に org_settings 的テーブル（org_id×skey→JSON）を足し、/sync GET/POST で consentAddressees/consentClinics を同期。複数端末・スタッフ共有のため。
2. 療養費同意書を**公式2様式に完全分離**（はり・きゅう様式／あマ指様式の出し分け：往療欄・初回/再同意・注意事項等欄・保険医署名欄まで）。テンプレ `consent_form_acupuncture_template.html` / `consent_form_massage_template.html` は存在（render関数 `consentAcupunctureTemplateRender`/`consentMassageTemplateRender`）。
3. **訪問診療同意書（依頼書）の確定フロー設計**：医師署名のみで確定（signed_document＋TSA生成）するか、患者自署まで要るか。現状は患者署名→finalize で TSA確定。
4. **全書類に PDF保存／印刷／指定先送信＋保存先明示**を横展開（発行済みは D1 `documents` に保存。「〔法人名〕のサーバに保存、再表示・再送信可」と明記）。
5. **「自動退避・一時保存（複数）・赤枠保持・前回コピペ・あて先/発行元マスタ」を全書類へ横展開**（今回の consentNewPage の型を流用）：NDA／訪問診療同意書／診療情報提供書（別紙様式11）／居宅療養管理指導／歯科。
6. 診療情報提供書（別紙様式11）／居宅療養管理指導／歯科（様式11の2/歯科指示書）を順次正式化。

---

## 6. Google Play Console（GPC）ステータス（2026-06-29 時点）

アカウント：タムジ.Corp（個人用 / Account ID `8531951863872577016`）。3アプリ：
| アプリ | パッケージ | 状態 | インストール | 最終更新 |
|---|---|---|---|---|
| やるゼ！ | `com.tamjump.yaruze` | 製品版 | 14 | 2026-06-19 |
| ｍやるゼ！ | `com.tamjump.medvoo` | 製品版 | 14 | 2026-06-19 |
| ｔやるゼ！ | `com.tamjump.onetouch` | クローズドテスト | 1 | 2026-05-08 |

**次の作業（新規chatで画面共有しながら）**
- mやるゼ！（com.tamjump.medvoo）の「リリース → 製品版」or「アプリの概要」を共有 → ステータス（審査待ち／新ビルドUP／更新）を確認して1ステップずつ。
- 既知通知：assetlinks.json（Digital Asset Links）未関連付けでディープリンク不全の可能性。2026-07-25 から強化テスト（信頼できるパートナーのデバイス）。
- TWA運用：親/ｍ/ｔ は TWA。外注 buntyan（Coconala）。TutorialActivity起因リジェクトは修正済、AABはTWA-onlyで再ビルド方針。

**iOS 対応方針（新規）**
- TWA は Android 専用。iOS は同じ PWA を **PWABuilder（最短）** か Capacitor で WKWebView パッケージ化 → **App Store Connect** 提出。
- 要：Apple Developer Program（年99ドル）登録。manifest.json は配備済（`/app.html` start_url、standalone）。

---

## 7. よくある運用トラブルと応急処置（wrangler／JIN実行）

**新規adminがログインできない＝メール未確認（403）**
```bash
wrangler d1 execute medadapt-db --remote --command "SELECT login_id,email,email_verified,status,access_blocked_at FROM users WHERE login_id='ADM-XXXXXX'"
wrangler d1 execute medadapt-db --remote --command "UPDATE users SET email_verified=1, verify_token=NULL WHERE login_id='ADM-XXXXXX'"
wrangler d1 execute medadapt-db --remote --command "UPDATE users SET status='active', access_blocked_at=NULL, suspended=0 WHERE login_id='ADM-XXXXXX'"
```

**同意書発行が 404/500**（§3-2 の層別。まず §3-2 のワンライナーで CREATE の BODY を確認）
- 404「患者が見つかりません」→ owner_email ズレ（§3-1/3-3 反映済の worker をDeployしているか）。
- 500 → consent系テーブル未作成（§3-3）／hash_chain 列名（§3-2 層⑤）。**最新 worker_v7_complete.js を Deploy していない**ことが多い。

**本番反映**
- フロント：push→GitHub Pages 自動。Cloudflareで `app.html` / `assets/consent_form_template.html` をパージ → Ctrl+Shift+R。Service Worker は未登録（キャッシュは HTTP/エッジのみ）。
- **Worker：手動 Edit code 貼り付け→Deploy（★ A 参照。push では反映されない）**。

---

## 8. 今セッションのコミット履歴（新しい順）

- `c77f8b1` あて先・発行元をマスタ登録→選択式に（＋新規登録、下書き保持対応）
- `a3d5655` 発行フォームにあて先・発行元の入力欄を追加（body/下書き保持にも反映）※後続でセレクト化
- `5e94148` 医師署名・タイムスタンプをPDFに反映＋あて先をform_payload優先に
- `adb564c` 一覧カードにPDFボタン追加＋request_form表示名を訪問診療同意書に
- `f105f66` PDFプレビューを下書き〜確定の全状態で表示（書類確認用）
- `d9b3786` hash_chainの主キーをchain_indexに統一＋既存テーブルをALTERで自動マイグレート（sign-doctor 500解消）
- `61a7219` consent系テーブルをマイグレーション追加（500=テーブル未作成解消）
- `8a43d9d` sync upsertでowner_emailも更新（古いowner_email固定の404根因解消）
- `005d27c` データ所有者をorg adminに統一（owner_email一致／404解消）
- `bb93c9f` ①カード説明を発行可能な同意書の列挙に簡潔化
- `b212092` ハブ説明を訪問診療同意書メイン＋療養費の2系統に整合化
- `aec2d14` 同意書ナビ統合・訪問診療メイン化／一時保存を複数患者対応＋自動退避＋下書き一覧
- `6196bd0` 特権アカウント（監修医師ADM-4D3R62）を全機能無料化（plan=pro強制）

> ※ Worker系コミット（005d27c/8a43d9d/61a7219/d9b3786/6196bd0）は **JIN が Edit code に最新 worker_v7_complete.js を貼って Deploy 済**（本セッション中に発行〜署名が開通したことで確認）。

---

## 9. 関連リポジトリ・他案件（同一Cloudflareアカウント tamj_Account 内）

Workers & Pages：next-api（Next Innovation）, develop-api（不動産 develop.tamjump.com）, rebridge-api（M&A rebridge.tamjump.com）, carepay-api / carepass-api（CarePAY/Care Support Pass）, tamj-residence, tamjump-contact-api, tamjump-member-api, adapt-api（親・課金集約）, **medadapt-api-v2（本OS）**, medadapt-whereby, tamsic-send-letter, onetouch-api, late-shadow-b145。

> 本OS（ｍやるゼ！）以外は本ハンドオーバーの対象外。必要時に各リポジトリの引継書を参照。

---

## 10. 新規chatでまず確認すること（クイックスタート）

1. リポジトリ clone（PAT埋め込みURL）→ `assets/worker_v7_complete.js` と `app.html` の最新確認。
2. **本番 Worker が最新か**を §3-2 のワンライナーで確認（401「認証が必要です」＝v7稼働）。consent 系で500なら最新 worker_v7_complete.js を Deploy。
3. mやるゼ！で 発行→医師署名→PDFプレビュー が通るか（あて先・発行元・医師署名バナーが反映されるか）。
4. 続きのタスク：§5-2 残タスク（あて先/発行元マスタのクラウド同期→各書類の正式化・横展開）／§6 GPC・iOS。
