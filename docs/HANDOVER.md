# 🚀 やるゼ！プラットフォーム 引き継ぎ書（HANDOVER）

**最終更新**: 2026-05-25 / HEAD `05d4756`
**作成**: Claude (Anthropic)
**Owner**: TAmJ.Corp 代表 / 大下さん

---

## 📌 新規 chat 開始時の最重要指示

**大下さんからの恒久的な指示**（毎セッション必ず参照）:

> 「過去の会話や、このchatで話した内容、PAT等、何も端折らないでね。新規chatですぐに再開できるようにして。毎回説明が面倒だから、この件も引き継ぎ書に記載しといて。」

➡ **本ファイル（HANDOVER.md）を新規 chat 冒頭で読み込み、設計書最新版と合わせて全文把握すること。**
➡ **作業ごとに HANDOVER.md と DESIGN_yaruze_v*.html を必ず更新してから commit する。** これは恒久的なルール。

---

## 🏢 1. プロジェクト概要

### 1-1. ブランド構成

```
やるゼ！プラットフォーム（親ブランド）
├── ｔやるゼ！(adapt)         — タスク管理・引継ぎ系
├── ｍやるゼ！(medadapt)      — 医療介護連携OS（このリポジトリ）
└── ワンタッチ              — モバイル系
```

- ブランドタグライン: **VOO = Vision Of Oneness**（ひとつにつながる世界の構想）
- メインカラー: `cyan #0891b2` / グラデーション `linear-gradient(135deg, #0891b2, #06b6d4)`
- 医監修パートナー: **後藤 基温 医師**（医療法人社団コンパス 理事長 / コンパスメディカルグループ 代表理事）
- ペルソナ「大下さん」= タムジ.Corp 代表（ユーザー本人）

### 1-2. プロダクトのコア機能

ｍやるゼ！は退院支援・在宅連携専用プラットフォーム。以下を1つに統合:
1. 日程調整・連携（投票形式で確定、通話URL自動生成）
2. オンラインアセスメント
3. 共同指導（算定対応 / B004 1500点）
4. サービス担当者会議・モニタリング
5. 電子同意・記録テンプレ化（電子署名 + タイムスタンプ + SHA-256ハッシュチェーン）
6. 監査ログ・操作証跡

訪問マッサージ・訪問鍼灸の医療保険算定にも対応（B013 100点）。

---

## 📦 2. リポジトリ情報

### 2-1. リポジトリ一覧

| 名前 | URL | 役割 |
|---|---|---|
| **medadapt** | https://github.com/TAmJump/medadapt | ｍやるゼ！本体（このファイルがある場所） |
| adapt | （別途） | ｔやるゼ！ |
| onetouch_app | （別途） | ワンタッチ |

### 2-2. GitHub PAT（Personal Access Token）

**⚠️ セキュリティ上の理由から、本書には PAT を平文で記載しない。**

GitHub の Secret Scanning が公開リポジトリへの secret push をブロックする仕様のため、
**PAT は大下さんが別途管理しているシークレットボールトから取得すること**。

新規 chat で大下さんから「続ける」と言われた場合、まず以下を伝えて PAT を再共有してもらう:

> 「リポジトリ medadapt への push に PAT が必要です。
> 前回セッションで共有された GitHub Personal Access Token を、もう一度ペーストしてください。」

push 時の Remote URL 設定（PAT を `<TOKEN>` 部分に挿入）:
```bash
git remote set-url origin https://<TOKEN>@github.com/TAmJump/medadapt.git
```

PAT の権限スコープ: `repo`（フルアクセス）必要。

### 2-3. Git config

```bash
git config user.email "animalb001@gmail.com"
git config user.name "TAmJump"
```

### 2-4. 作業ディレクトリ（Claude のサンドボックス）

```
/home/claude/medadapt
```

新規 chat 開始時の初期化コマンド（`<TOKEN>` は大下さんから個別取得）:
```bash
cd /home/claude && git clone https://<TOKEN>@github.com/TAmJump/medadapt.git
cd medadapt
git config user.email "animalb001@gmail.com"
git config user.name "TAmJump"
```

### 2-5. デプロイ

- **本番LP**: https://myaruze.tamjump.com/
- **アプリ**: https://myaruze.tamjump.com/app.html
- **デプロイ方式**: GitHub Pages（main branch 自動デプロイ） + Cloudflare 経由独自ドメイン
- **CDN キャッシュ**: 1-2分で反映。古いキャッシュが残る場合は強制リロード（Ctrl+Shift+R / Cmd+Shift+R）

---

## 📂 3. 主要ファイル構成

```
medadapt/
├── index.html                                    # LP本体（16 sections / 337 divs）
├── app.html                                      # アプリ本体（SPAルーター）
├── acupuncturist-portal.html                    # 鍼灸師用ポータル
├── patient-consent.html                          # 患者同意取得画面
├── assets/
│   ├── consent_form_template.html               # 同意書依頼書（患者→医師 / コンパス独自書式）
│   ├── consent_form_acupuncture_template.html   # 医師交付同意書（はり・きゅう / 厚労省様式 v4.10）
│   ├── consent_form_massage_template.html       # 医師交付同意書（マッサージ / 厚労省様式 v4.10）
│   ├── worker_v7_complete.js                    # Cloudflare Worker 本体（D1 操作 + TSA連携）
│   ├── v8〜v13_d1_setup.sql                     # D1 マイグレーションスクリプト
│   └── img/
│       ├── dr_goto_motoharu*.jpg                # 後藤先生実写写真（v4.7配置）
│       └── generated/
│           └── v2/                               # 大下提供素材 42枚（v4.8組込）
│               ├── team_yaruze.jpg              # HERO背景（やるゼ!Tシャツ11人）
│               ├── photoshoot_3p.jpg / 5p.jpg   # チーム実写
│               ├── target_*.jpg × 6             # 6職種ペルソナ
│               ├── pain_*.jpg × 7               # PROBLEMS
│               ├── solve_*.jpg × 7              # SOLUTIONS After
│               ├── mood_*.jpg × 6               # SCENE STRIP + HERO BAND
│               ├── icon_*.png × 6               # アイコン
│               └── ogp_v2.jpg                   # OGP
├── docs/
│   ├── DESIGN_yaruze_v4_2_2026-05-24.html       # 旧版
│   ├── ... (v4.3 〜 v4.11)
│   ├── DESIGN_yaruze_v4_12_2026-05-25.html      # 最新版 ★
│   └── HANDOVER.md                              # このファイル ★
└── (その他: docker / cloudflare config 等)
```

---

## 📜 4. セッション・バージョン履歴（v4.2 〜 v4.12）

### v4.2 〜 v4.6（過去セッション、医監修導入 + 基本機能）

- §48 後藤先生 医監修パートナー導入（240×240 アバター、医師指示書への監修クレジット）
- Phase 8 STEP 1-2: 同意書 D1 migration + Worker API 13本
- Phase 8 v13: 全帳票共通 改ざん防止基盤 + コンパス書式 PDF + 医療保険算定対応
- Phase 8 v14: 退院通知・NDA 自動 finalize + 患者ポータル + 鍼灸師ポータル

### v4.7 — 後藤先生写真 + サイト素材13枚（2026-05-24）

- 後藤先生実写写真（505×481px → 480×480 / 240×240 JPG）を組込
- ChatGPT 生成サイト素材13枚（card 4 + hero 2 + icon 6 + OGP 1）を配置
- HERO BAND + FEATURE HIGHLIGHTS セクション新設
- ⚠️ **問題**: app.html のサイドバー img に `onerror: '...'` 文字列指定 → 後に v4.8.1 で起動不能の原因に
- ⚠️ **問題**: 大下未提供の画像（card_*, hero_*, icon_*_v1, ogp_v1）を勝手に生成・配置 → 後に v4.9 で全撤去
- HEAD: `62e1547`

### v4.8 — サイト素材42枚拡張パック組込（2026-05-25）

- 大下提供「サイト素材.zip」42枚を圧縮（73.8MB → 6.2MB / 8.3%）
- `assets/img/generated/v2/` に配置
- 5セクション新設: SCENE STRIP / SOLUTIONS Before-After / PERSONAS / REAL UI SHOWCASE / TEAM
- 構造: 11→16 sections, 221→364 divs
- HEAD: `98f5c30`

### v4.8.1 — app.html起動不能バグ修正（緊急）

- **症状**: `myaruze.tamjump.com/app.html` が真っ白、コンソールに `TypeError: parameter 2 is not of type 'Object' at h (app.html:371)`
- **原因**: v4.7 で追加した `onerror: 'this.style.display=\'none\''` 文字列を h() ヘルパーが addEventListener の第2引数として渡していた
- **修正**:
  - app.html L371: h() に防御ロジック（`on***` キーが function の時のみ addEventListener、string の時は setAttribute へフォールバック）
  - app.html L812: サイドバーの onerror 文字列を削除
- HEAD: `f53c64c`

### v4.9 — HERO刷新 + 古い素材撤去 + 過剰表現見直し

#### 9-1. HERO刷新
- 当初: 左カラム + ダークオーバーレイ
- 最終: 「上540px チーム写真 + 下白背景テキスト帯」レイアウトで顔と文字を完全分離

#### 9-2. 大下未提供素材の完全撤去
v4.7 で勝手に生成した画像11枚を全撤去:
- card_consent_v1 → v2/consent_signing
- card_discharge_v1 → v2/mood_discharge
- card_massage_v1 → v2/treatment_acu
- card_nda_v1 → v2/card_nda
- icon_*_v1.png × 6 → v2/icon_*.png × 6
- hero_team_v1 / hero_visit_v1 → 削除
- ogp_v1 → v2/ogp_v2
- ⚠️ **教訓**: 大下提供素材以外を勝手に生成しないルールを厳守

#### 9-3. 過剰表現監査（22箇所）
「0秒」「+1500点」「ゼロ」「全自動」「完全」「終了」等を実機能ベースに修正
詳細は §59-4 参照。残す自動表現:
- 通話URL自動生成（実装あり）
- 日程投票結果から自動確定（実装あり）
- 監査ログ自動保存（実装あり）

- HEAD: `307ae9f`

### v4.10 — 医師交付同意書 厚労省標準様式準拠の2書式（2026-05-25）

#### 10-1. 経緯
大下指摘「マッサージ系の同意書はどこにあるの？」+ 仕組み解説ドキュメント共有を受けて新規実装。

#### 10-2. 新規作成2ファイル

**`/home/claude/medadapt/assets/consent_form_acupuncture_template.html`**
- 厚労省「別添1別紙1」準拠（はり及びきゅう療養費用）
- 病名6種＋その他、発病年月日、同意区分（初回/再同意）、診察日、注意事項
- 同意文「鍼灸の施術に同意する」、保険医情報、印
- 有効期間6か月自動表示
- JS API: `window.consentAcupunctureTemplateRender(data)`

**`/home/claude/medadapt/assets/consent_form_massage_template.html`**
- 厚労省「別添2別紙1」準拠（あん摩マッサージ指圧療養費用）
- 傷病名、症状3階層（筋麻痺/萎縮5部位 + 関節拘縮12部位 + その他）
- 施術の種類2階層（マッサージ5部位 + 変形徒手矯正術4部位）
- 往療欄: 必要/不要 + 理由3択 + 介護保険要介護度
- 有効期間自動判定（変形徒手なら1か月警告色、それ以外6か月）
- JS API: `window.consentMassageTemplateRender(data)`

#### 10-3. 既存テンプレ
`/home/claude/medadapt/assets/consent_form_template.html` は「鍼灸・マッサージ同意書作成の依頼書 兼 訪問診療同意書及び計画書」（コンパス独自・患者→医師の依頼書）として残置・併存。

- 参照URL:
  - はり・きゅう: https://kouseikyoku.mhlw.go.jp/kinki/iryo_shido/000077054.pdf
  - マッサージ: https://kouseikyoku.mhlw.go.jp/kinki/iryo_shido/000077056.pdf
- HEAD: `50c775a`

### v4.11 — HERO顔被り完全解消 + 電子署名認証バナー起用

#### 11-1. HERO顔被り解消
- 大下指摘「TOP HEROで後藤先生と俺の顔が文字で隠れちゃってる」
- 最終CSSは `.hero` (min-height:880px) → 上540pxを画像、下を白背景テキスト帯に分離
- team_yaruze.jpg の顔位置と文字エリアが完全独立
- `background-position: center 30%`、`.hero::after` で底面をフェードアウト
- `.hero-text-block` を白背景の独立コンテナに
- モバイル: 380px画像→白背景

#### 11-2. 電子署名+TSA起用
- 大下指示「サイト内全ての同意書や指示書は必ず、電子署名＋タイムスタンプを起用してね」
- 同意書系3テンプレ全てに統一適用:
  - `.e-cert-banner`: cyan縁取りの認証バナー（✓アイコン + 「電子署名＋タイムスタンプ済」タイトル + e-文書法/電子署名法/SHA-256 ハッシュチェーン説明 + 署名者・タイムスタンプ・認証局の3情報）
  - `.seal-area.signed`: 印欄を「✓電子署名済」表示に変換（青系cyan配色 + 署名日時表示）
  - `formatSignedTime(iso)` ヘルパー関数
- 適用順:
  - 一次: acupuncture + massage (HEAD `841fd14`)
  - 二次: 既存 consent_form_template.html にも適用 (HEAD `3d7f381`)

### v4.12 — タイムスタンプ証明書ブロック（総務省認定タイムスタンプ業務準拠）

#### 12-1. 経緯
大下指示「同意書や医師の指示書のタイムスタンプは？sampleを見たい」
+ 参照URL: https://www.soumu.go.jp/main_sosiki/joho_tsusin/top/ninshou-law/timestamp.html

#### 12-2. 設計方針
v4.11 の e-cert-banner（電子署名のサマリ）に加えて、独立した **タイムスタンプ証明書** ブロックを新設。
総務省「認定タイムスタンプ業務（時刻認証業務 / 令和3年法律第146号）」と RFC 3161 (TSP) の要件を満たす情報項目を全て表示。

#### 12-3. タイムスタンプ証明書ブロックの内容
- 認定タイムスタンプ事業者名
- 認定番号（13-001 等）
- 付与日時 JST + UTC の両方を ISO 8601 形式で
- シリアル番号（16進）
- ハッシュアルゴリズム（SHA-256 固定）
- 対象文書ハッシュ（64桁の SHA-256）
- 認定根拠条文（令和3年法律第146号 第3条第1項）の説明
- 検証方法（QRコード / 認証局窓口）への案内

#### 12-4. 認定タイムスタンプ事業者（令和8年3月時点）
| 事業者名 | 提供会社 |
|---|---|
| セイコータイムスタンプサービス | セイコーソリューションズ |
| タイムスタンプサービス DiaStamp | 三菱電機デジタルイノベーション |
| アマノタイムスタンプサービス3161 | アマノ |
| 電子認証タイムスタンプ byGMO | GMOグローバルサイン |
| タイムスタンプサービス iScign | サイエンスパーク |
| ウイングアークタイムスタンプサービス | ウイングアーク1st |

指定調査機関: **一般財団法人 日本データ通信協会**

#### 12-5. 適用範囲
- 3テンプレ全て（acupuncture / massage / 既存依頼書）に統一適用
- HEAD: `05d4756`

---

## 📚 5. コミット履歴（最新10件）

```
05d4756 feat(v4.12): タイムスタンプ証明書ブロックを3テンプレに追加（総務省認定タイムスタンプ業務準拠）
3d7f381 feat(v4.11): 既存依頼書テンプレにも電子署名＋タイムスタンプ認証バナーを起用
841fd14 feat(v4.11): HERO顔被り問題の完全解消 + 同意書2書式に電子署名＋タイムスタンプ認証バナーを起用
50c775a feat(v4.10): 医師交付同意書 厚労省標準様式準拠の2書式を新規作成
307ae9f docs: v4.9 設計書のHEADを実値 398d455 に更新
398d455 feat(v4.9): 設計書v4.9策定 + 残存「自動」過剰表現の追加修正 + PROBLEMSタイトル誠実化
6af0a92 fix(v4.9): HERO写真背景化 + 大下さん未提供素材を削除 + 盛りすぎ表現の見直し
f53c64c fix(v4.8.1): app.html起動不能の重大バグ修正 + PROBLEMSを写真メイン型タイルに刷新
8259dd1 docs: v4.8 設計書の HEAD を実値 98f5c30 に更新
98f5c30 feat(v4.8): サイト素材42枚拡張パック組込 + 5セクション新設
```

最新の完全な log は `git log --oneline -20` で取得すること。

---

## ⚖️ 6. 設計ルール（過去の反省を踏まえて）

### 6-1. 絶対遵守ルール

1. **大下提供素材以外を勝手に生成しない** — v4.7で守れず v4.9で全撤去した重大事故あり
2. **過剰広告表現NG** — 医療現場LPとして薬機法・景品表示法を意識
   - NG: 「ゼロ」「完全」「全自動」「即時」「終了」「100%」
   - OK: 実機能ベース表現（「軽減」「抑止」「テンプレ化」「即時出力」）
3. **既存破壊なし** — D1 / Worker API / 他リポジトリ (adapt, onetouch_app) は touch せず
4. **構造整合性チェック** — section / div の open/close 対称、画像参照のリンク切れ確認
5. **animation opacity 注意** — `.anim-up` クラスが初期 opacity:0 → 0.65sでfadeIn、スクショは1500ms wait 必須
6. **設計書・引き継ぎ書を必ず更新してから commit する** — 大下さんの恒久指示

### 6-2. NG表現と正しい表現の対照表

| NG表現 | 正しい表現 |
|---|---|
| 誰でも保険適用 | 医師が医療上必要と認めた場合、医療保険の対象となることがあります |
| 無料 | 自己負担は保険証の負担割合に応じます |
| 肩こりで保険適用 | 慢性的な疼痛のうち、神経痛・腰痛症等が対象 |
| リラクゼーション目的で保険適用 | 慰安目的ではなく医療上必要な施術 |
| 必ず改善 | （言及しない） |
| 寝たきりが治る | （言及しない） |
| 記録自動生成 | 記録のテンプレ化 / テンプレ入力で即PDF |
| 電話調整ゼロ | 電話の往復を最小化 |
| 全自動でケアプランに反映 | システム上で集約、ケアプラン作成・更新の参照資料に活用 |
| 監査前夜の徹夜 → ワンクリック証跡 | 紙ベース監査準備 → QR検証で即時提示 |
| 0秒 記録作成 / +1500点 算定対応 | PDF出力 即時生成 / B004対応 1500点 |

---

## 🏥 7. 医療保険適用の仕組み（大下共有・施術所運用知識）

### 7-1. 訪問マッサージ・訪問鍼灸の医療保険適用

- **介護保険ではなく、医療保険の療養費**
- 鍼灸対象6疾患: 神経痛/リウマチ/頸腕症候群/五十肩/腰痛症/頸椎捻挫後遺症 + その他
- マッサージ対象: 筋麻痺/筋萎縮/関節拘縮（**診断名ではなく症状**）
- 訪問条件: 歩行困難・通院困難
- 同意書有効期間: **6か月**、変形徒手矯正術は **1か月**
- **再同意は対面診察必須**（電話再同意不可）

### 7-2. 料金（令和6年10月〜）

- 鍼灸 初検料 1術 1,950円 / 2術 2,230円
- マッサージ 1局所 450円
- 往療料 2,300円
- 施術報告書交付料 480円
- B013 療養費同意書交付料 **100点**
- B004 退院時共同指導料 **1500点**

### 7-3. 同意書フロー

```
患者・家族が利用希望
↓
医師が診察
↓
医師が同意書を発行（厚労省様式）
↓
国家資格者が自宅・施設へ訪問して施術
↓
患者は1割・2割・3割の自己負担を支払う
↓
残りを施術者側が保険者へ請求
```

---

## 📋 8. 現状の HEAD と未着手タスク

### 8-1. 現状

- **最新 HEAD**: `05d4756`（v4.12）
- **本番デプロイ**: 完了（GitHub Pages 経由）
- **設計書**: `docs/DESIGN_yaruze_v4_12_2026-05-25.html`
- **引き継ぎ書**: このファイル

### 8-2. 未着手タスク（優先順）

#### A. app.html 帳票の電子署名＋TSA 対応拡大
- app.html 内で発行される他の帳票:
  - 退院通知
  - NDA（法人間秘密保持契約）
  - 施術報告書
  - 退院時共同指導記録
  - サービス担当者会議記録
  - モニタリング記録
- これらにも `e-cert-banner` と `timestamp-cert` ブロックを統一適用する必要あり
- 現状: html2canvas + jsPDF でクライアント側生成しているため、Worker側の TSA データを取り込む API 拡張が必要

#### B. Worker API レスポンスに timestamp 構造化データを追加
- 現状の Worker は `tsa_status` / `tsa_acquired_at` までは対応済（v4.8 時点）
- 不足: `authority_name`, `cert_no`, `serial`, `hash_algorithm`, `document_hash` の構造化レスポンス
- D1 スキーマに `timestamps` テーブル追加するか、`signed_documents.tsa_payload` JSON 列を増やすか検討

#### C. 実 TSA との連携実装
- 候補: セイコー / アマノ / GMO のいずれか
- 月額契約 + API 呼び出し料金あり
- セイコー or アマノが医療機関での実績豊富

#### D. LP（index.html）コピーへの反映
- v4.11 で導入したタイムスタンプ証明書を LP のコピーでも明示
- 「全ての同意書・指示書に電子署名＋タイムスタンプ」を訴求文に追加

#### E. app.html の「Not found」バッジ問題（保留中）
- スクショで患者詳細画面の右上に「Not found」バッジが表示されることがある
- 「共有先なし」を取得しようとして API レスポンスがエラーになっている可能性
- まだ原因調査未着手

#### F. D1 スキーマ拡張: consent_forms に type 列
- 既存 `consent_forms` テーブルに `type` 列を追加し、`'acupuncture'` / `'massage'` / `'request_form'` を区別
- それぞれの構造化データを JSON で保存できるように
- Worker API 側で type に応じて呼ぶテンプレを分岐
- app.html UI で「はり・きゅう / マッサージ」選択を追加

---

## 🛠️ 9. 開発作業時の標準フロー

### 9-1. 新規 chat 開始時

1. このファイル（HANDOVER.md）と最新設計書（`docs/DESIGN_yaruze_v*.html`）を全文確認
2. `git log --oneline -10` で最新コミット履歴確認
3. 大下さんの今回の依頼事項を整理
4. 影響範囲を確認（既存破壊チェック）
5. 作業計画を提示

### 9-2. 実装中

- 大下提供素材以外は使わない
- 既存 D1 / Worker API は触らない
- 過剰広告表現禁止
- 構造整合性チェック（section / div open/close）

### 9-3. 完了時

1. ローカルで動作確認（playwright スクショ推奨）
2. `git add -A && git commit -m "feat/fix(vX.Y): 要約"` で commit
3. **設計書を更新**（`DESIGN_yaruze_v*.html` 新規版作成 or 既存版に章追加）
4. **HANDOVER.md を更新**（最新 HEAD、新セクションの履歴、新規未着手タスクを反映）
5. `git push origin main` でデプロイ
6. 大下さんに結果報告

### 9-4. スクショ撮影時の注意

- viewport 設定（デスクトップ 1366×900 / モバイル 412×800 を基本）
- `page.wait_for_timeout(1200)` で `.anim-up` の fadeIn 完了を待つ
- 全画面スクショは `clip` を指定するか `full_page=True`
- スクショ右上に「Not found」バッジが時々出る件は **app.html の保留 bug**（未調査）

---

## 🎨 10. デザインシステム

### 10-1. カラー

```css
--blue: #0891b2;           /* メインアクセント cyan */
--blue-d: #0e7490;          /* 濃色 */
--blue-l: #ecfeff;          /* 薄色 */
--ink: #0f172a;             /* 主テキスト */
--ink-m: #475569;           /* 中間 */
--ink-l: #64748b;           /* 薄色 */
--white: #ffffff;
--border: #e2e8f0;
--grad: linear-gradient(135deg, #0891b2, #06b6d4);
```

### 10-2. 認証バナーのデザイン

- **電子署名バナー (`.e-cert-banner`)**: シアン縁取り (`#0891b2`) + 薄シアン背景 (`#ecfeff` → `#f0fdfa` グラデ)
- **タイムスタンプ証明書 (`.timestamp-cert`)**: 紫縁取り (`#6366f1`) + 薄紫背景 (`#f5f3ff` → `#eef2ff` グラデ)
- **有効期間バナー (`.validity-banner`)**: 黄色系 (`#fffbe6` / `#d4a017`)、変形徒手なら警告色（赤系 `#fff0f0` / `#d44`）

---

## 📞 11. 連絡先 / 関係者情報

- **Owner**: 大下さん（タムジ.Corp 代表）
  - GitHub: TAmJump
  - Email: animalb001@gmail.com
- **医監修**: 後藤 基温 医師
  - 医療法人社団コンパス 理事長
  - コンパス内科歯科クリニック大宮（〒330-0854 埼玉県さいたま市大宮区桜木町4-692-1 伊田グループビルⅢ405号室）
  - TEL: 048-783-2713
- **クリニックの正式名称（書類記載用）**: 医療法人社団コンパス　コンパス内科歯科クリニック大宮

---

## 🔗 12. 重要な外部URL

### 12-1. 厚労省 / 総務省

- 療養費の改定等について: https://www.mhlw.go.jp/bunya/iryouhoken/iryouhoken13/01.html
- 同意書（はり・きゅう）: https://kouseikyoku.mhlw.go.jp/kinki/iryo_shido/000077054.pdf
- 同意書（マッサージ）: https://kouseikyoku.mhlw.go.jp/kinki/iryo_shido/000077056.pdf
- 総務省 タイムスタンプについて: https://www.soumu.go.jp/main_sosiki/joho_tsusin/top/ninshou-law/timestamp.html

### 12-2. 関連法令

- 認定認証業務の認定に関する規則（令和3年内閣府令第146号 → 法律第146号）
- 健康保険法 / 国民健康保険法 / 高齢者の医療の確保に関する法律
- e-文書法（民間事業者等が行う書面の保存等における情報通信の技術の利用に関する法律）
- 電子署名法（電子署名及び認証業務に関する法律）

---

## 🎯 13. このプロジェクトの本質

ｍやるゼ！は **「退院調整・在宅連携で疲れている医療現場を、ひとつのアプリで支える」** プロダクト。
病院・施設・訪問看護・薬局・鍼灸院がそれぞれの立場を超えてつながり、患者・家族の安心を最優先する。

**やってはいけないこと**:
- 誇大広告（「完全」「ゼロ」「100%」）
- 医療上のエビデンスのない効果訴求
- 提供素材以外の画像を勝手に生成
- D1 や Worker の既存 API を勝手に破壊

**やるべきこと**:
- 実機能ベースの誠実な表現
- 厚労省・総務省の標準様式に完全準拠
- 既存破壊なし・構造整合性チェック
- 設計書・引き継ぎ書の更新を怠らない

---

**END OF HANDOVER**

*本ファイルは毎セッション必ず更新する。新規 chat 開始時は本ファイルと最新設計書（`DESIGN_yaruze_v4_12_2026-05-25.html` またはそれ以降）を全文確認してから作業を開始すること。*
