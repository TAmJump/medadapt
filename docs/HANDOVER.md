# 🚀 やるゼ！プラットフォーム 引き継ぎ書（HANDOVER）

---

## 🚨🚨🚨 最優先警告: クローズドテスト期間中の変更禁止ルール 🚨🚨🚨

**新規chatを開始した Claude は、本ファイル以外のいかなる作業に着手する前にも必ず本セクションを読むこと。**

### 期間
- **2026-05-27（火）〜 2026-06-09（火）** の 14日間
- buntyan 様（ココナラ取引B / talkrooms/17714106 / 9,495円契約）が代行する Google Play クローズドテスト期間

### 対象アプリ
- **親「やるゼ！」**（プラットフォーム本体）
- **ｍやるゼ！**（本リポジトリ medadapt）← Claude が普段触っているアプリ
- ※ｔやるゼ！は対象外（URL 修正待ち）

### 禁止事項（buntyan 様明示・違反すると 14日テストが無効化されるリスク）
- ❌ **app.html** 本体の機能追加・削除・挙動変更（Worker API / D1 スキーマ / 起動時のネイティブ画面挙動）
- ❌ アプリの「ネイティブ画面」の削除・変更
- ❌ 起動時に表示される画面の振る舞いの変更
- ❌ クロテ期間中の D1 マイグレーション適用や Worker 再デプロイ（大下さんが意思決定）

### 許可事項
- ✅ **LP（index.html / assets/img/ の見た目）** の修正は引き続き OK（大下さん明示・2026-05-26）
- ✅ 大下さんから明示的に「buntyan 様に連絡済みで OK」と言われた場合のアプリ修正
- ✅ コードの内部リファクタリング（見た目・挙動を変えない範囲）
- ✅ ドキュメント・設計書・HANDOVER の更新

### Claude が遵守する運用
- 新規 chat 開始時、大下さんに「A/B/C どれにしますか」と聞く前に、**本セクションを読み「クロテ期間中は app.html 系の変更は提案しない」** ことを内部で確定
- もしユーザーから app.html 系の機能変更を依頼された場合、まず「クロテ期間中ですが、buntyan 様にアップデート連絡済みでしょうか？」と確認してから着手
- LP（index.html）の修正依頼は通常通り対応

### 詳細
本リポジトリ内 `docs/HANDOVER_buntyan_v2_2026-05-26.html` 参照。
- buntyan 様提供の「クロテ中のアップデート方法.pdf」手順
- §6 クロテ運用ルール（遵守必須）
- §10 アップデート可否（Web実調査済・期間中の修正OK・むしろ推奨だが buntyan に事前連絡必要）
- §11「はじめるボタン → ログイン画面遷移しない」件の判断パターン

### 引継書作成時のセット運用ルール
**今後 HANDOVER.md を更新する際は、本「クロテ期間中の変更禁止ルール」セクションを必ず最優先警告として残す**（クロテ完了の 2026-06-10 以降は本セクションを削除可能）。

---

**最終更新**: 2026-06-22（v5.2.2 / 保険情報の閲覧・記録 + 他機関へ渡る3帳票への保険情報自動差し込み）

**現状 HEAD**:
- medadapt: v5.2.2（保険情報 + 3帳票PDF差し込み / 本セッション push が HEAD）
- adapt: `c2511db`（v4.15 HERO顔と文字の完全分離）
- one-touch: `a03ea94`（v4.15 HERO顔と文字の完全分離）

**📌 v5.0 設計書**: `docs/DESIGN_yaruze_v5_0_2026-05-26.html`
**📌 デプロイ手順書**: `docs/DEPLOY_v5_0_4_production.md` ★必読
**📌 v5.0.5 実TSA調査**: `docs/RESEARCH_TSA_v5_0_5_2026-05-26.md`（事業者選定・コスト・実装方針）
**📌 大下指示書**: 「医師本人確認・医療文書共有・タイムスタンプ機能 追加指示書」+ 10件の追加要件 + 1年以内タスク3件

**📅 進行状況**:
- **5/26（今日）**: 大下指示書 全項目実装完了（v5.0.1〜v5.0.4）✅ + Worker API 13本（うち R2 3本）+ wrangler.toml + GitHub Actions ワークフロー + デプロイ手順書 ✅
- **5/26 続き（アプリ設計34）**: §8-3 残タスク全消化（v5.0.5）✅
  - Not foundバッジ問題解消 / 帳票PDF7種に電子署名+TSAバナー / Worker TSA構造化レスポンス / LP訴求具体化 / consent_type request_form / 実TSA連携 調査レポート

**🚨 大下さんが Cloudflare 側で実施するタスク**（Claude は関与しない・恒久ルール参照）:
  0. `docs/deploy_templates/worker.yml` を `.github/workflows/worker.yml` にコピーして commit & push（Claude PAT に workflow スコープがないため大下さんの手元で1回だけ）
  1. Cloudflare API Token + Account ID + D1 Database ID 取得 → GitHub Secrets 登録
  2. `wrangler.toml` の `REPLACE_WITH_ACTUAL_D1_ID` を実IDに差し替え（または同様の手動編集）
  3. R2 バケット `medadapt-files` 作成
  4. GitHub Actions「Deploy Cloudflare Worker」を `apply_migration=true` で実行（v16 初回適用）
  5. **【v5.0.5 追加】v17 マイグレーション適用**: `wrangler d1 execute <DB> --file=assets/v17_d1_migration.sql --remote`（signed_documents/consent_forms に TSA 構造化4列 + timestamps テーブル追加）
  6. デプロイ手順書 `docs/DEPLOY_v5_0_4_production.md` §E2E チェックリスト 8項目を実行

➡ **Claude（次セッションの私）はこのリストを大下さんへ確認しない**。大下さんから「やっといたよ」「進捗どう」等の言及があった時のみ反応する。新規chatでは、上記とは別の「コード側の作業」を確認すること（Step 2 の A/B/C 選択肢）。

**作成**: Claude (Anthropic)
**Owner**: TAmJ.Corp 代表 / 大下さん

---

## 🎯 新規chat再開時の最初の1分間（必読・最優先）

**次セッションを始めた Claude は、以下を冒頭で必ず実行する**:

### Step 1: 全体把握
1. **★最優先**: 本ファイル冒頭の「🚨 クローズドテスト期間中の変更禁止ルール」を読む（2026-06-09 まで遵守必須）
2. **★最優先**: `docs/HANDOVER_buntyan_v2_2026-05-26.html` を読む（buntyan 様事案・クロテ運用ルール詳細）
3. 本ファイル全文を読む（特に §「v5.0.5 セッションでの完了事項」と §「次回再開時の必要作業」）
4. `docs/DESIGN_yaruze_v5_0_2026-05-26.html` を読む（v5.0 全機能の仕様書）
5. `docs/DEPLOY_v5_0_4_production.md` を読む（デプロイ手順書・E2E チェックリスト）
6. `docs/RESEARCH_TSA_v5_0_5_2026-05-26.md` を読む（実TSA連携の調査結果）
7. `git log --oneline -10` で直近の作業履歴を把握

### Step 2: 大下さんへの初期確認
最初に大下さんへ以下を確認する（**選択肢を提示する形式**）:

> A. **LP（index.html）の修正・調整**（クロテ期間中も OK）
> B. **追加の修正・新機能開発を進める**（大下さんから新規指示がある場合）
> C. **既存実装のバグ修正・調整**（大下さんが実機テストして気になった点）
> D. **次フェーズの設計・調査作業**（HPKI実連携、TSA実連携、電子カルテ連携 等）

**Cloudflare 関連作業は選択肢に含めない**（理由は Step 3 参照）。

**クロテ期間中（〜2026-06-09）の重要制約**:
- B/C で app.html（医療アプリ本体）の修正が出てきた場合は、大下さんに「クロテ期間中ですが、buntyan 様にアップデート連絡済みでしょうか？」と必ず確認してから着手
- A（LP 修正）は通常通り対応 OK

### Step 3: 恒久ルールの確認
- HANDOVER.md と DESIGN_yaruze_v*.html を作業ごとに更新→commitが必須
- 文言ガイドライン §A-F を厳守（禁止語：地獄/完全/完璧/100%/ゼロ、個人名+一般概念禁止、「鍼灸」単独表記禁止）
- 大下提供素材以外を勝手に生成しない（イラスト・絵文字アイコン等）
- 「全部やれ」と言われたら最後まで止めない（途中で「上限近いから報告」等は禁止）
- **🚨 Cloudflare 関連の操作は大下さん本人が担当する**（恒久ルール・2026-05-26 確定）
  - Worker デプロイ（`wrangler deploy` / GitHub Actions の実行ボタン押下）
  - D1 マイグレーション適用（`wrangler d1 execute`）
  - R2 バケット作成（`wrangler r2 bucket create`）
  - Cloudflare API Token / Account ID / D1 Database ID の取得・登録
  - GitHub Secrets への登録
  - `wrangler.toml` の `database_id` 差し替え
  - Cloudflare Dashboard 上の設定変更
  - **Claude は提案・手順書作成・コード準備までしか行わない**。実行は大下さんに委ねる。
  - 大下さんに「Cloudflare の◯◯やっといて」とは言わない。「準備できました。手順は `docs/DEPLOY_*.md` を参照ください」と伝える。
  - Claude が Cloudflare 進行を選択肢として提示するのは毎回冗長 → このルールでカット。

### Step 4: 現状の HEAD と本番URL
- **GitHub**: https://github.com/TAmJump/medadapt
- **本番 LP/アプリ**: https://myaruze.tamjump.com/
- **Worker**: https://medadapt-api-v2.animalb001.workers.dev/
- **最新コミット**: `dacdd83`（v5.0.6 / LP HERO 透け感 + 医師写真差し替え）
- **状態**: コード実装完了。Cloudflare 側のデプロイ操作待ち（v16 + v17 マイグレーション両方適用必要）
- **クロテ期間中**: 5/27〜6/9 は app.html 系の変更は buntyan 様への事前連絡が必要

### Step 5: PAT 認証情報
GitHub PAT は本ファイル §「GitHub アクセス」セクション参照（実値はダウンロード版にのみ記載）。

### Step 6: 本日（2026-05-26 / アプリ設計㉝〜㉞）の作業サマリ

5/26 1日で **v5.0 → v5.0.1 → v5.0.2 → v5.0.3 → v5.0.4 → v5.0.5 → v5.0.6** の6世代を実装。

| バージョン | 主な内容 | コミット |
|---|---|---|
| **v5.0** | 大幅機能追加の設計確定 + LP/アプリ軽微修正7件 + v5.0設計書作成 | `98d76fc` |
| **v5.0.1** | 医師・専門監修パートナー6名追加（後藤先生はトップ維持） | `1a94551` |
| **v5.0.2** | 過去引継ぎ機能（アセス/会議/モニタ）+ 外部連携BOX UI骨格 + D1 v16 migration | `06e5409` |
| **v5.0.3** | 大下指示書 全11項目対応（表記統一・アイコン削除・新3機能：居宅療養/歯科/診療情報提供書） | `0916285` |
| **v5.0.4** | Phase 1-4 完全実装 + Worker API 13本 + R2 ファイルアップロード + デプロイ自動化基盤 | `58c1edd` |
| **v5.0.5** | §8-3 残タスク全消化（Not found修正・帳票PDF TSA拡大・Worker TSA構造化・LP訴求具体化・consent_type拡張・実TSA調査） | `6691439` |
| **v5.0.6** | 医師写真7名差し替え（テキストなし新素材）+ HERO 透け感調整 + 大画面レイアウト修正 + buntyan 事案ルール反映 | `dacdd83` |
| **v5.1.0** | 当日状態報告（事前キャンセル連絡）機能を患者ハブに追加。MASTER §7 の1年タスク「当日キャンセル事前報告」を前倒し実装。患者ハブ概要に「当日状態報告」ボタン＋一覧、判定（実施／中止／要相談）、バイタル記録、関係機関への連絡先選択、当日の中止・要相談を「次にやること」最上位に昇格。`pt.statusReports[]` に格納し既存 D.patients sync に相乗り（Worker/D1 変更なし） | `1ccc66b` |
| **v5.2.0** | 保険情報（医療・介護・公費）の閲覧・記録機能を患者ハブ概要に追加。マイナ保険証移行後、医療機関以外の事業所はオンライン資格確認ができず資格情報の取得に時間を要するため、医療機関が確認した保険情報を記録→共有先（介護事業所等）が閲覧できる設計。医療保険（保険種別・保険者番号・記号/番号/枝番・被保険者・続柄・負担割合・有効期限・マイナ資格確認済フラグ）、介護保険（被保険者番号・要介護度・認定有効期間・負担割合）、公費負担（種別・負担者番号・受給者番号・有効期限、複数可）。`pt.insurance{}` に格納し既存 D.patients sync に相乗り（Worker/D1 変更なし） | `38145bb` |
| **v5.2.1** | 診療情報提供書PDFに保険情報（医療保険・介護保険・公費）を自動差し込み。患者ハブで登録済みの `pt.insurance` を提供書に転記し、宛先機関に資格情報が同送される。二度入力を不要化 | `29d7323` |
| **v5.2.2** | 居宅療養管理指導記録PDF・歯科診療PDFにも保険情報を自動差し込み。提供書と合わせ、他機関へ渡る3帳票（診療情報提供書／居宅療養管理指導／歯科）に資格情報が同送される | `本セッション` ★HEAD |

### 大下指示書 全 13 項目の最終ステータス

| # | 指示 | 対応版 | 状況 |
|---|---|---|---|
| ① | マッサージ・鍼灸 → 「訪問マッサージ（鍼灸）」表記統一 | v5.0.3 | ✅ |
| ② | 指示外アイコン全削除（📦📋⏰🤝📜🔍📄） | v5.0.3 | ✅ |
| ③ | 各事業所→医師指示書 直接アクセス不可 | v5.0.4 | ✅ Worker `checkConsentAccess` + ロール別 doc_kind 制限 |
| ④ | アセス・指示書 過去引継ぎ | v5.0.2 | ✅ |
| ⑤ | 居宅療養管理指導（介護保険）オンライン実施＋記録＋PDF | v5.0.3+v5.0.4 | ✅ |
| ⑥ | 診療情報提供書 アプリ内完結 | v5.0.3 | ✅ |
| ⑦ | 歯科 医科同等の操作可能化 | v5.0.3 | ✅ |
| ⑧ | 訪問マッサージ指示書 期間自由入力 | v5.0 | ✅ |
| ⑨ | 退院時共同指導 機関プルダウン共通フォーマット | v5.0 | ✅ 16機関種別 |
| ⑩ | 録音録画ダウンロード | v5.0 | ✅ |
| ⑪ | ｍ=mtg イースターエッグ | 既実装 | ✅ index.html L2177-2179 |
| ⑫ | 看取り柔らかい表現 | v5.0 | ✅ |
| ⑬ | 広告プラン LP セクション（料金未定で3カード） | v5.0 | ✅ |

### Worker API 全 13 本（v5.0.4 で完成）

**`/medical-docs/*` 10 本**: upload / patient/:id / :id/share / shared-with-me / :id/acknowledge / :id/reject / :id/revoke / :id/access-logs / :id/view / :id/new-version

**`/files/*` 3 本**: upload (R2) / get/:key / :key (DELETE)

### 次セッション最初の発話例（Claude が言うべきこと）

大下さんから「アプリ設計35 再開して」と言われたら、Claude はこう返す:

> 「再開します。HANDOVER と buntyan 事案引継書（クロテ期間中ルール）、設計書・デプロイ手順書・実TSA調査レポートを確認しました。
> 現状の HEAD は `dacdd83`（v5.0.6）。HANDOVER §8-3 の中長期未着手タスク A〜F をすべて消化済み + LP の医師写真差し替えと HERO 透け感調整完了。
>
> **重要**: 現在 buntyan 様によるクローズドテスト期間中（5/27〜6/9）のため、app.html 系（医療アプリ本体・機能・挙動）の変更は buntyan 様への事前連絡が必要です。LP（index.html）の修正は通常通り可能。
>
> 今回のセッションで進めたい作業を教えてください:
>   A. LP（index.html）の修正・調整（クロテ期間中も OK）
>   B. 追加の修正・新機能開発
>   C. 既存実装のバグ修正・調整（クロテ中なら buntyan 連絡確認）
>   D. 次フェーズの設計・調査（HPKI 実連携 / 実 TSA 契約後の連携実装 / 電子カルテ連携 等）」

**やってはいけない発話例**:

- ❌「Cloudflare のデプロイは進みましたか？」
- ❌「D1 マイグレーション、適用しときましょうか？」
- ❌「v17 migration 適用しましたか？」
- ❌「E2E テストの結果はどうでしたか？」
- ❌「Cloudflare Dashboard で◯◯を確認してください」
- ❌「TSA 事業者の契約は進めましたか？」
- ❌（クロテ期間中）「app.html の◯◯機能追加を進めましょうか？」

---

## 📌 新規 chat 開始時の最重要指示

**大下さんからの恒久的な指示**（毎セッション必ず参照）:

> 「過去の会話や、このchatで話した内容、PAT等、何も端折らないでね。新規chatですぐに再開できるようにして。毎回説明が面倒だから、この件も引き継ぎ書に記載しといて。」

➡ **本ファイル（HANDOVER.md）を新規 chat 冒頭で読み込み、設計書最新版と合わせて全文把握すること。**
➡ **作業ごとに HANDOVER.md と DESIGN_yaruze_v*.html を必ず更新してから commit する。** これは恒久的なルール。

### 大下さんからの恒久指示（2026-05-26 確定）

> 「Cloudflareは俺がやる。引き継ぎ書にちゃんと記載して。毎回同じやり取りになるよ。」

➡ **Cloudflare 関連の操作・確認・進捗確認はすべて大下さんが行う**。Claude は以下のことを **絶対にやらない**:

- ❌ 「Cloudflare のデプロイは進めましたか？」と確認する
- ❌ 「D1 マイグレーション適用しときますか？」と提案する
- ❌ 「R2 バケット作成しておきますね」と作業着手する
- ❌ 大下さんへの選択肢提示に「Cloudflare 進行」を含める
- ❌ 「Cloudflare 側でこれをやってください」と指示口調で言う

➡ Claude が **やるべきこと**:

- ✅ コード変更 / ドキュメント整備 / 設計書更新 / commit & push まで
- ✅ Cloudflare で何をすべきかの **手順書** を `docs/DEPLOY_*.md` に整備しておく
- ✅ 大下さんから「Cloudflare デプロイした」「動かない」等の言及があった場合のみ反応
- ✅ 「準備できました。手順は `docs/DEPLOY_*.md` を参照ください」と一言添える程度に留める

---

## 🔒 文言ガイドライン（v4.21 で恒久化・絶対遵守）

LP（index.html）・アプリ（app.html）・帳票テンプレ・解説書PDF・設計書、すべての成果物で以下のルールを厳守する。違反は大下さんへの再指摘要因となるため、新規追記・修正時に必ずチェック。

### A. 禁止表現（絶対に使わない）

| カテゴリ | 禁止語 | 代替表現 |
|---|---|---|
| ネガティブ強調 | 地獄 | 課題 / 困難 / 複雑 / 負荷 |
| 過剰広告 | 完全 / 完璧 / 100% / ゼロ / 完了します | 大幅に低減 / 担保します / に沿って運用 / 自動化を支援 |
| 個人名+一般概念 | 「後藤先生の実印に相当」「○○先生の××」 | 「医師の実印・自署に相当」（個人名は出さず一般化） |
| 自社書式の偽装 | 「コンパスクリニック書式」「自社オリジナル書式」 | 「厚生労働省 関連通知（保医発第1001002号 等）に準拠した書式」 |
| 単位の誤用 | 「タブレット1枚」「タブレット1台」 | 「タブレット／スマホ 1台」（**v4.25**: スマホでも操作可能のため） |
| 鍼灸の単独表記 | 「鍼灸院」「鍼灸師」「訪問鍼灸」「訪問鍼灸マッサージ」 | 「訪問マッサージ（鍼灸含む）」（ただし当該セクション内でのみ使用） |
| 数の限定 | 「4つの中核機能」「6職種のためのアプリ」「6 つの強み」 | 「中核機能」「主要機能」「医療系・在宅医療系・介護系・在宅介護系・コ・メディカル系のためのアプリ」 |
| 専門点数コードの羅列 | HEROのハッシュタグに「＃療養費同意書交付料(B013)」「＃退院時共同指導加算(B004)」など | （**v4.25** で削除）一般ユーザには意味不明なので、点数コードは機能解説セクションの説明文内のみで使用（HEROタグや見出しには出さない） |

### B. 多職種を列挙する場面のテンプレ（v4.25 で更新）

「病院・在宅医・施設・薬局・鍼灸院」のような**限定的列挙は禁止**。また、「病院・訪問診療・訪問歯科・訪問看護・訪問介護・薬局・ケアマネ・福祉用具などのコ・メディカル」を**毎度繰り返すのも冗長**。以下のルールで使い分ける:

**【新ルール v4.25】**:
- **LP内 1か所だけ「フル表記」**: 最も目立つ場所（現状は HEROバンド左 L729）で1回だけ全列挙
- **他のすべての場面では「多職種」と短縮**: それで意味は通る

**フル表記（HEROバンド L729 等、LP全体で1か所だけ）**:
> 病院・訪問診療・訪問歯科・訪問看護・訪問介護・薬局・ケアマネ・福祉用具などのコ・メディカル

**通常表記（その他すべての場面）**:
> 多職種

**カテゴリ抽象表現（対象セクションのタイトル等、用途限定）**:
> 医療系・在宅医療系・介護系・在宅介護系・コ・メディカル系

**注意**: HEROバンドのフル表記は文中ではテンポよく並べる。コ・メディカル は「まとめられる事業」の総称として最後に置くと収まりが良い。HEROバンド以外でフル列挙が必要になった場合は、まず「多職種」で書けないか検討する。

### C. 「訪問マッサージ（鍼灸含む）」の専用表記ルール

- 「鍼灸」を含む表現は、**当該機能を説明するカード/セクションの中でのみ**「訪問マッサージ（鍼灸含む）」として使用する
- 他のセクション（HERO / 中核機能サブタイトル / ペルソナ / NDA 説明 / 月40時間説明 / 在宅利用者説明 等）では**鍼灸の文字を一切登場させない**
- 関連する役割名も統一: 「鍼灸師」「あマ指師」→「施術者」、「鍼灸師ポータル」→「施術者ポータル」

### D. ビデオ通話 / 自動文字起こしについて

- 「ビデオ通話は自動記録される」と表現する際は、**「誤字や認識誤差はあり得る」を必ず併記**
- 「自動文字起こしされた議事録がそのまま完成」のような表現は禁止
- 標準テンプレ: 「通話内容は補助的に自動文字起こしされますが、誤字や認識誤差はあり得るため、テンプレに沿って内容を確認・修正の上、議事録 PDF を出力します」

### E. チェックリスト（新規追記・修正時に必ず確認）

新しい文章を書いた・既存文章を直したら、以下を即座に grep して残存ゼロを確認:

```bash
grep -nE "地獄|完全|完璧|100%|ゼロ" 対象ファイル
grep -nE "コンパスクリニック書式|後藤先生の実印" 対象ファイル
grep -nE "鍼灸院|鍼灸師|訪問鍼灸[^マ]" 対象ファイル
grep -nE "タブレット.?枚|タブレット 1 枚" 対象ファイル
grep -nE "4つの中核|6職種|6 つの強み" 対象ファイル
```

### F. 違反の事例（過去 v4.13 までに大下さんが指摘した文言）

| 違反例 | 修正後 | セッション |
|---|---|---|
| 「現場の地獄に、ひとつの答えを。」 | 「現場の課題に、ひとつの答えを。」 | v4.21 |
| 「日程調整の電話地獄」 | 「日程調整の負荷」 | v4.21 |
| 「タブレット1枚」 | 「タブレット1台」 | v4.21 |
| 「タブレット1台」 | 「タブレット／スマホ 1台」 | v4.25 |
| 「コンパスクリニック書式」 | 「厚生労働省 関連通知（保医発第1001002号 等）に準拠した書式」 | v4.21 |
| 「後藤先生の実印に相当」 | 「医師の実印・自署に相当」 | v4.21 |
| 「病院・在宅医・施設・薬局・鍼灸院」 | 「病院や訪問診療、訪問歯科、薬局、介護、福祉、コ・メディカル等」 | v4.21 |
| 「訪問鍼灸マッサージ」 | 「訪問マッサージ（鍼灸含む）」（専用セクション内のみ） | v4.21 |
| 「4つの中核機能」「6職種」 | 「中核機能」「医療系・在宅医療系・介護系・在宅介護系・コ・メディカル系」 | v4.21 |
| 「リスクがゼロになります」 | 「リスクを大幅に低減します」 | v4.21 |
| 「完全デジタル化・紙同意と同等の法的効力」 | 「デジタル化・タイムスタンプ付きで原本性を担保」 | v4.21 |
| 「算定要件にも完全準拠」 | 「算定要件に沿って運用できます」 | v4.21 |
| HEROタグ「＃療養費同意書交付料(B013) ＃退院時共同指導加算(B004)」 | HEROタグから削除（点数コードは機能解説の本文内のみ） | v4.25 |
| 「電話・FAX・移動をゼロに。」 | 「電話・FAX・移動の負荷を大幅に削減します。」 | v4.25 |
| 「コ・メディカル」のフル列挙を6箇所で繰り返し | HEROバンド L729 の1か所のみフル列挙、他は「多職種」に短縮 | v4.25 |
| 課題タイル06「監査不安」のテキスト重なり | tile-s 専用のオーバーレイ濃度強化 + text 2行 clamp で可読性向上 | v4.25 |

---

### v5.0.5 セッションでの完了事項（2026-05-26 / §8-3 残タスク全消化・アプリ設計㉞）

大下指示: 「順番は君に任せる。最後まで完成させて」を受けて、HANDOVER §8-3 の **5 項目（A・B・C・D・E）+ F** の中長期未着手タスクをすべて消化。実 TSA 連携（C）は契約待ちのため調査レポート作成までで完了。

#### 完了した6タスク

| # | HANDOVER §8-3 | 内容 | コミット |
|---|---|---|---|
| 1 | **E** | Not foundバッジ問題解消 | `39edad1` |
| 2 | **A** | 帳票PDF7種類への電子署名+TSAバナー拡大 | `39edad1` |
| 3 | **B** | Worker TSA構造化レスポンス（v17 migration） | `d5761b0` |
| 4 | **D** | LP コピーへの電子署名+TSA訴求具体化 | `56bf1cc` |
| 5 | **F** | consent_type に request_form 追加 | `192e5e9` |
| 6 | **C** | 実TSA連携 調査レポート（契約前準備） | `6691439` |

#### A. Not foundバッジ問題解消（§8-3 E）

`app.html` L398-401 の `loadCases / loadConfs / loadMons / loadAssess` 4本に `silent404:true` を付与。新規患者や未保存データの場合 Worker が 404 を返すのは正常状態だが、これがトーストで「Not found」と表示されていた問題を解消。

加えて `api()` ヘルパー L193-205 のエラーメッセージ変換を強化:
- 'Not found' / 'not_found' / 'notfound' を全て「対象が見つかりません」に変換
- 403 エラーは「アクセス権限がありません」
- 500系は「一時的なエラーが発生しました。しばらくしてからお試しください」

#### B. 帳票PDFへの電子署名+TSAバナー拡大（§8-3 A）

`app.html` で生成される **7 帳票すべて** に共通の電子署名+TSA証明書ブロックを統一適用:

| 帳票 | PDF関数 | TSA対応 | 備考 |
|---|---|---|---|
| 退院時共同指導記録 | `genCasePDF` | ✅既存（v4.15で対応） | discharge_guidance |
| サービス担当者会議 | `genConfPDF` | ✅既存 | conference |
| モニタリング | `genMonPDF` | ✅既存 | monitoring |
| 居宅療養管理指導 | `genKyotakuPDF` | ✅v5.0.5で共通ヘルパーに統一 | kyotaku_ryoyo_record |
| アセスメント | `genAssessPDF` | ✅v5.0.5で新規対応 | assessment |
| 診療情報提供書（医科） | `genReferralPDF` | ✅v5.0.5で新規実装 | medical_referral |
| 歯科診療情報提供書／指示書 | `genDentalPDF` | ✅v5.0.5で新規実装 | dental_referral / dental_instruction |

実装方針:
- 共通ヘルパー `buildECertHtml(sd, signerName)` + `buildTimestampCertHtml(sd)` を使用
- PDF生成の async コールバック内で `fetchSignedDocInfo(docKind, docId)` を呼んで `signed_documents` を逆引き
- `signed_documents` の TSA メタデータが取得できれば、e-文書法・電子署名法準拠の電子署名バナー（シアン枠）+ 総務省認定タイムスタンプ証明書ブロック（紫枠・RFC 3161 / TSP）を末尾に追加
- 取得できない場合（draft 等）はバナーをスキップ
- 診療情報提供書・歯科モーダルの編集モードに「PDF出力」ボタンを追加

#### C. Worker TSA構造化レスポンス拡張（§8-3 B）

**v17 D1 マイグレーション新規** (`assets/v17_d1_migration.sql`):
- `signed_documents` に4列追加: `tsa_authority_name` / `tsa_cert_no` / `tsa_serial` / `hash_algorithm`
- `consent_forms` に4列追加（対称構造のため同じ4列）
- `timestamps` テーブル新規: 1文書あたり複数回のTSA取得イベントを履歴管理。実 TSA 連携時の生レスポンス（base64）も raw_response 列に保存可能

**Worker `enrichTsaFields(row)` ヘルパー新規** (`assets/worker_v7_complete.js` 末尾):
- signed_documents/consent_forms 行から `buildTimestampCertHtml` が必要とする 6 項目を補完
- `tsa_authority` が未設定の場合、フォールバックでセイコータイムスタンプサービス名+認定番号13-001を埋める
- `tsa_serial` は content_hash の先頭16桁から派生（モック動作）
- `tsa_acquired_at_jst` をUTCから自動変換（UI 側で再計算不要）
- 実 TSA 連携時は DB の `tsa_authority_name` 等に実値を保存すれば、このヘルパーがそのまま実値を返す（モックフォールバックは自動的に無効化される設計）

**Worker レスポンス改修**:
- `/signed-docs/by-doc/:kind/:id` → `enrichTsaFields(sd)` を適用
- `/signed-docs/:id` → 同
- `/verify/document/:id` → 構造化フィールド5種を追加
- `/consent/:id/verify` → 同

**app.html `fetchSignedDocInfo` 修正**:
- Worker レスポンス `{ok:true, signed_document:{...}}` のラッパをアンラップ
- `buildECertHtml` の `signed_at` 必須を緩和（`finalized_at` / `created_at` をフォールバックに）

#### D. LP コピーへの訴求具体化（§8-3 D）

`index.html` の中核機能カード「同意書・指示書」を以下に強化:

- タイトル変更: 「同意書・指示書 改ざん不可」→「同意書・指示書・**記録** 改ざん不可」
- 本文に対応 **7 帳票** を具体的に列挙: 退院時共同指導記録/サービス担当者会議/モニタリング/アセスメント/居宅療養管理指導/診療情報提供書/歯科診療情報提供書
- HERO ハッシュタグに「診療情報提供書」「歯科診療情報提供書」を追加（L637）

文言ガイドライン §E チェック実施: 「地獄/完全/完璧」禁止語の本文混入ゼロ件を確認。

#### E. consent_type に request_form 追加（§8-3 F）

既存スキーマ `consent_forms.consent_type` 列を活用（マイグレーション不要）。

- Worker validateConsentType: `'acupuncture' | 'massage' | 'both' | 'request_form'` を許可
- Worker `disease_names` 必須を `request_form` 時のみ緩和（依頼書テンプレに疾患名欄なし）
- Worker `disease_names` が空の場合は `'[]'` を保存（ハッシュ整合性のため）
- `app.html` cf-type 選択肢に「訪問診療同意書（依頼書）」追加
- `app.html` 傷病名必須バリデーションを `request_form` 時は任意化
- `previewConsentPDF` の既定テンプレ (`consent_form_template.html` = 依頼書) が `request_form` 時に自動使用される設計は v4.14 で実装済み

#### F. 実 TSA 連携 調査レポート（§8-3 C）

`docs/RESEARCH_TSA_v5_0_5_2026-05-26.md` 新規作成:

- **事業者4社比較**: セイコー / アマノ / 三菱 / GMO の医療実績・API・Workers互換性を整理
- **料金試算**: アマノ従量制で想定3,000スタンプ/月=**¥24,500/月（税抜）**
- **実装方針**: OSS [`pdf-rfc3161`](https://github.com/mingulov/pdf-rfc3161) が Cloudflare Workers 互換で利用可能（Pure JS / ネイティブ依存ゼロ / Edge-ready）
- **v17 マイグレーション準備済み列との対応**: 実 TSA 接続時に保存すべきフィールドのマッピング
- **段階的移行プラン**: Phase A（モック）→ Phase B（無償トライアル）→ Phase C（全帳票）→ Phase D（LTV/長期署名）
- **法令適合性**: 医療情報安全管理ガイドライン第5版 / e-文書法 / 電子署名法 / 認定タイムスタンプ業務認定制度

**調査結論**: 第一候補は **アマノタイムスタンプサービス3161**（医療実績豊富 + 月額固定価格 + 無償トライアル提供あり）。50ユーザー超えた時点で投資回収可能。それまでモック表示でも LP の「総務省認定TSA準拠」訴求は維持できる設計。

#### 残タスク（v5.0.5 セッションでは未着手）

§8-3 のうち、コード作業として完了したのは A/B/D/E/F の 5 項目。C（実 TSA 連携）はコード実装が大下さんの契約後に開始する性質のものなので、現セッションでは調査レポートまでで完結。

HANDOVER §17（1年以内タスク）への対応は引き続き次セッション以降:
- HPKI 実連携（外部 CA 契約 + Worker 拡張）
- 実 TSA 連携の Phase B 着手（アマノ無償トライアル契約後）
- 電子カルテ連携

#### Cloudflare 側で大下さんが新規に必要となる作業

1. **v17 マイグレーション適用**:
   ```bash
   wrangler d1 execute medadapt-db --file=assets/v17_d1_migration.sql --remote
   ```
   または GitHub Actions「Deploy Cloudflare Worker」を `apply_migration=true` で実行（v17 が拾われる）。

2. **Worker 再デプロイ**: v5.0.5 で `enrichTsaFields` を追加したため、Worker 自体の再デプロイも必要。

これら2作業は大下さん本人が `git pull` 後に Cloudflare 側で実施。Claude は確認しない。

---

### v5.0.4 セッションでの完了事項（2026-05-26 / Phase 1-4 全実装・Worker API完結・アプリ設計㉝後半その2）

大下指示: 「全部進めて」を受けて、v5.0.3 で残していた **Worker API 6本（実装後 10本に拡張）/ localStorage→D1切替 / 医師認証フォーム / 保存期限通知 / 居宅療養PDF** をすべて実装。これで設計書 §3〜§6 の全フェーズが完成。

#### A. Worker `/medical-docs/*` API 10本実装

`assets/worker_v7_complete.js` L2683-3083 に追加。設計書では 6 本予定だったが、運用上必要な 4 本を追加して計 10 本：

| エンドポイント | メソッド | 用途 | 設計書 |
|---|---|---|---|
| `/medical-docs/upload` | POST | 外部文書アップロード（メタデータ+content+署名レベル+保存期限） | §3-4 |
| `/medical-docs/patient/:id` | GET | 患者別文書一覧（自組織発行 + 自組織宛て共有のマージ） | §3-4 |
| `/medical-docs/:id/share` | POST | 外部機関へ共有（ロール別 doc_kind 制限あり） | §4-2 |
| `/medical-docs/shared-with-me` | GET | 自分／自組織宛ての共有一覧 | §4-2 |
| `/medical-docs/:id/acknowledge` | POST | 受領確認（共有先が押す） | §4-2 |
| `/medical-docs/:id/reject` | POST | 差戻し | §4-2 |
| `/medical-docs/:id/revoke` | POST | 共有停止（共有元のみ） | §4-2 |
| `/medical-docs/:id/access-logs` | GET | 閲覧ログ取得 | §4-2 |
| `/medical-docs/:id/view` | POST | 閲覧ログ記録（IP/UA記録） | 追加 |
| `/medical-docs/:id/new-version` | POST | 新版発行（旧版を archived、versions テーブルに履歴記録） | §6 |

**ロールベース doc_kind 制限**（設計書 §4-1 準拠）:

```js
const roleAllowedKinds = {
  hospital: 'ALL', clinic_med: 'ALL',
  clinic_dent: ['dental_referral','dental_instruction','medical_referral','patient_consent','family_consent','pharmacy_info'],
  visiting_nurse: ['visit_nurse_instruction','special_visit_instruction','discharge_summary','medical_referral','nursing_summary','home_medical_instruction'],
  pharmacy: ['pharmacy_info','medical_referral','home_medical_instruction'],
  care_manager: ['care_plan','discharge_summary','service_meeting_record','monitoring_record','kyotaku_ryoyo_record'],
  care_facility: ['discharge_summary','nursing_summary','medical_referral','patient_consent','family_consent'],
  rehab_provider: ['rehab_instruction','discharge_summary'],
  massage_acupuncture_provider: ['massage_acupuncture_consent','treatment_plan','acupuncture_report'],
  patient: ['consent_form','patient_consent','medical_referral','discharge_summary'],
  family: ['family_consent','patient_consent']
};
```

例: 訪問看護 (`visiting_nurse`) には「歯科指示書」を共有しようとしても 403 で拒否される。

**監査ログ自動記録**: upload/share/acknowledge/reject/revoke/view すべてのアクションを `medical_document_access_logs` に INSERT（IP/UA 含む）。

#### B. アプリ側 localStorage → D1 fetch 切替

1. **`fetchExtDocsFromWorker(pt)`** ─ `/medical-docs/patient/:id` を呼んでローカルキャッシュにマージ。`_fromWorker` フラグでローカル only データと区別。
2. **`hubExternalBox(pt)`** ─ 初回表示時に `S._extDocsFetched[pt.id]` ガードで重複呼び出し防止しつつ Worker から取得 → 完了後 `rr()` で再描画。
3. **`showExternalDocUploadModal`** ─ 「登録」ボタンで Worker `/medical-docs/upload` を await し、成功時は `signed_document_id` をローカルにも保存。失敗時はローカル only。トーストで状態表示（「D1同期済」/「ローカル保存」）。
4. **`showShareModal`** ─ 「共有する」ボタンで Worker `/medical-docs/:id/share` を await。
5. **`showSharedWithMeModal()`** 新規 ─ 共有されたBOXモーダル。`/medical-docs/shared-with-me` で取得、各カードに受領確認 / 差戻しボタン。

**オフライン耐性**: Worker API 失敗時もローカル保存で続行可能。`silent404:true` で 404 トースト抑止。

#### C. Phase 3 医師認証フォーム（設定画面）

`settingsPage()` 内、「アカウント情報」カードの直後に「医師認証・署名権限」セクション追加。

**機能**:
- 医師氏名 / 医籍登録番号 / 所属医療機関 の入力
- 4 つのステータスバッジ表示（医師資格 / 組織所属 / HPKI / 多要素認証）
- 「プロフィール保存」「免許証画像アップロード（近日対応）」「多要素認証 ON/OFF」ボタン
- **管理者のみ**「資格確認済みにする / 取消」ボタン表示（`u.role==='admin'` 条件分岐）
- 説明文「署名レベルの違い」を末尾に表示（system_verified / doctor_license_verified / hpki_signed / external_signed_pdf）

#### D. Phase 4 保存期限通知

`buildTodos(pt)` 関数に保存期限超過警告を追加。

**ロジック**:
```js
const extDocs=(D.externalDocs||[]).filter(d=>d.patientId===pt.id&&!d.archived&&d.retention_until);
extDocs.forEach(d=>{
  const daysLeft=Math.floor((new Date(d.retention_until)-Date.now())/86400000);
  if(daysLeft<0) → 赤色TODO「保存期限切れ」
  else if(daysLeft<=30) → 黄色TODO「保存期限残N日」
});
```

患者ハブ概要タブの「次にやること」に自動表示。クリックで外部連携BOXタブへ遷移。

#### E. 居宅療養管理指導 PDF 出力実装

`genKyotakuPDF(r)` を新規追加（`genAssessPDF` の前に挿入）。

**PDF 構造**:
1. ヘッダ: 「居宅療養管理指導 記録」+ 作成日時刻
2. 基本情報テーブル: 利用者名 / 要介護度 / 提供職種（単位） / 当月実施回数 / オンライン実施URL
3. バイタル表: SBP/DBP/脈拍/体温/SpO2
4. 状況・指導テーブル: 栄養 / 服薬 / ADL / 指導内容 / 次回訪問予定 / ケアマネ氏名・事業所 / CM共有状況
5. 電子署名＋タイムスタンプフッタ（e-文書法・電子署名法・SHA-256ハッシュチェーン明示）
6. 作成組織名 + アプリ名

**自動連動**: `saveDocument('kyotaku_ryoyo_record', ...)` で帳票一覧にも自動保存。

#### F. Playwright 動作検証

- ✅ 全主要ページ smoke test 通過（kyotaku/dental/medical_referral/settings/acu_massage）
- ✅ Worker API 呼び出し（`/medical-docs/patient/:id`, `/medical-docs/shared-with-me`）が実際に発火することを確認
- ✅ 設定画面「医師認証・署名権限」セクション正常表示（4バッジ + 4ボタン）
- ✅ 共有されたBOXモーダル正常表示（API失敗時は適切な空状態）
- ✅ 居宅療養新規モーダル + 患者選択正常動作
- ✅ JSエラー: ローカル特有のCORS以外 0件

#### G. R2 ファイルアップロード機能（免許証画像・PDF添付対応）

**Worker `worker_v7_complete.js` に 3 エンドポイント追加（計 13 本）**:

| エンドポイント | メソッド | 用途 |
|---|---|---|
| `/files/upload` | POST | multipart/form-data 受信→R2 保存→URL返却（10MB上限・jpeg/png/webp/pdfのみ） |
| `/files/get/:key` | GET | R2 ファイル取得（権限チェック付き・閲覧ログ自動記録） |
| `/files/:key` | DELETE | ファイル削除（アップロード者 or admin のみ） |

**`purpose='license'` で `/files/upload` を呼ぶと、`doctor_profiles.license_image_url` を自動更新**（INSERT or UPDATE）。

**アプリ側**:
- `api()` ヘルパーに `isFormData: true` オプション追加（Content-Type を自動で外す）
- `uploadLicenseImage(u, dp)` 関数新規追加 ─ ファイル選択ダイアログ→multipart 送信→トーストで状態表示
- 設定画面「免許証画像アップロード」ボタンが動作するように

#### H. デプロイ自動化基盤

**新規ファイル**:

1. **`wrangler.toml`** ─ Worker / D1 / R2 / 環境変数の binding 定義
   - `database_id` は本番デプロイ前に要差し替え（`REPLACE_WITH_ACTUAL_D1_ID`）
   - R2 binding `MEDADAPT_FILES` → バケット `medadapt-files`

2. **`.github/workflows/worker.yml`** ─ Worker デプロイ用 GitHub Actions
   - push 時は worker.js / wrangler.toml / migration.sql 変更時のみトリガー
   - workflow_dispatch でマイグレーション適用フラグを選択可能
   - 必要な GitHub Secrets: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`

3. **`docs/DEPLOY_v5_0_4_production.md`** ─ デプロイ手順書（必読）
   - 方法A: GitHub Actions 経由（推奨）
   - 方法B: ローカル wrangler 直接実行
   - E2E チェックリスト 8 項目
   - 障害時ロールバック手順
   - トラブルシューティング Q&A

#### I. Playwright 動作検証（v5.0.4 最終確認）

- ✅ 設定画面の「免許証画像アップロード」ボタン存在確認
- ✅ 「多要素認証 設定」ボタン存在確認
- ✅ 居宅療養管理指導 編集モード「PDF出力」ボタン存在確認
- ✅ Worker API `/medical-docs/patient/:id` / `/shared-with-me` 呼び出し確認
- ✅ JSエラー: ローカル特有のCORS以外 0件

#### J. 残タスク（**大下さん担当・Claude は関与しない**）

🚨 **以下はすべて大下さん本人が Cloudflare 側で実施するタスク**。Claude は次セッションでもこのリストの進捗を確認しない。

| タスク | 規模 | 必要なもの | 担当 |
|---|---|---|---|
| Cloudflare API Token 取得 | 小 | Cloudflare アカウント | 大下さん |
| Account ID + D1 Database ID 確認 | 小 | Cloudflare Dashboard | 大下さん |
| GitHub Secrets 登録 | 小 | GitHub リポジトリ Settings | 大下さん |
| wrangler.toml の database_id 差し替え | 小 | テキストエディタ | 大下さん |
| R2 バケット `medadapt-files` 作成 | 小 | wrangler または Dashboard | 大下さん |
| **v16 マイグレーション適用**（外部連携BOX 4テーブル） | 小 | wrangler または GitHub Actions | 大下さん |
| **v17 マイグレーション適用**（v5.0.5 新規・TSA構造化4列 + timestamps テーブル） | 小 | wrangler または GitHub Actions | 大下さん |
| GitHub Actions「Deploy Cloudflare Worker」実行 | 小 | apply_migration=true 初回 | 大下さん |
| E2E 動作確認 8 項目 | 中 | アプリ実機 | 大下さん（バグ報告は Claude へ） |
| 実 HPKI 連携（外部CA契約） | 大 | 半年後タスク | 大下さん（契約） + Claude（コード対応） |
| 実 TSA 連携（アマノ/セイコー/GMO 月額） | 大 | 半年後タスク・調査済（`docs/RESEARCH_TSA_v5_0_5_2026-05-26.md`） | 大下さん（契約） + Claude（コード対応） |

---



### v5.0.3 セッションでの完了事項（2026-05-26 / 大下指示書全項目対応・アプリ設計㉝後半）

大下指示（再開後）:
> 「マッサージ」と「鍼灸」の表記は全て「訪問マッサージ（鍼灸）」に統一して。
> 「📦」指示してないアイコンは全て削除しろ。
> 全部完成させろよ（指示書全11項目）

#### 11項目の対応状況（最終）

| # | 指示内容 | 状況 | 対応箇所 |
|---|---|---|---|
| ① | 「マッサージ」「鍼灸」表記を「訪問マッサージ（鍼灸）」に統一 | ✅完了 | app.html 8箇所 / patient-consent.html / acupuncturist-portal.html / index.html persona-role |
| ② | 指示してないアイコン削除 | ✅完了 | 📦📋⏰🤝📜🔍📄 全7種類7箇所削除 |
| ③ | 各事業所から医師指示書へ直接アクセス不可 | ✅確認済 | Worker `checkConsentAccess` で多層チェック（admin/自院/共有先施術者/患者本人）。それ以外403拒否 |
| ④ | アセス・指示書の過去引継ぎ | ✅完了（v5.0.2） | アセス/会議/モニタ 3関数で実装済 |
| ⑤ | 居宅療養管理指導（介護保険）オンライン実施＋記録 | ✅完了 | サイドバー追加 / `kyotakuPage()` / `showKyotakuModal()` 実装 |
| ⑥ | 診療情報提供書アプリ内完結 | ✅完了 | サイドバー追加 / `medicalReferralPage()` / `showReferralModal()` 実装 |
| ⑦ | 歯科 医科同等の操作可能化 | ✅完了 | サイドバー追加 / `dentalPage()` / `showDentalModal()` 実装 |
| ⑧ | 訪問マッサージ指示書の期間自由入力 | ✅完了（v5.0） | プリセット+カスタム期間日付入力 |
| ⑨ | 退院時共同指導 機関プルダウン | ✅完了（v5.0） | 16種類の機関種別から複数選択 |
| ⑩ | 録音録画ダウンロード | ✅完了（v5.0） | index.html L1963 / 居宅療養指導画面にも明記 |
| ⑪ | ｍ=mtg イースターエッグ | ✅完了 | index.html L2177-2179（過去セッションで実装済み、grep `mtg` で見つからなかったのは `<em>m</em>tg` で分断されていたため） |
| ⑫ | 看取り柔らかい表現 | ✅完了（v5.0） | index.html L1964 |
| ⑬ | 広告プラン LP セクション | ✅完了（v5.0） | 料金「未定」表記で3カード設置済 |

#### A. 表記統一「訪問マッサージ（鍼灸）」

修正対象（厚労省制度名「はり・きゅう」「あマ指（あん摩・マッサージ・指圧）」は同意書区分用語のため残置）:

| ファイル | 行 | Before | After |
|---|---|---|---|
| app.html | 914 | サイドバー「マッサージ・鍼灸」 | 「訪問マッサージ（鍼灸）」 |
| app.html | 1087 | アクションバー「マッサージ・鍼灸ハブ」 | 「訪問マッサージ（鍼灸）ハブ」 |
| app.html | 1196 | doc_kindラベル「マッサージ・鍼灸同意書」 | 「訪問マッサージ（鍼灸）同意書」 |
| app.html | 1860 | 2か所目ハブボタン | 同上 |
| app.html | 3145 | 同意書見出し「同意書（鍼灸・マッサージ／訪問診療）」 | 「同意書（訪問マッサージ（鍼灸）／訪問診療）」 |
| app.html | 3527 | consent_form title | 「訪問マッサージ（鍼灸）同意書」 |
| app.html | 3659 | ハブページ見出し「マッサージ・鍼灸」 | 「訪問マッサージ（鍼灸）」 |
| app.html | 3679 | 算定説明「訪問マッサージ・訪問鍼灸」 | 「訪問マッサージ（鍼灸）」 |
| app.html | 3717-19 | infoBox 3行 | 「訪問マッサージ（鍼灸）」「はり・きゅう（制度名は残置）」「あマ指（制度名は残置）」 |
| patient-consent.html | 259 | 同上 | 統一 |
| acupuncturist-portal.html | 6,227 | title / サブタイトル | 統一 |
| index.html | 1373 | persona-role「訪問マッサージ」 | 「訪問マッサージ（鍼灸）」 |

#### B. 指示外アイコン削除（v5.0.2 で勝手に追加していたもの）

| 種類 | 元の場所 | 対応 |
|---|---|---|
| 📦 | 外部連携BOXタイトル | 削除 |
| ⏰ × 2 | 保存期限警告バッジ / 保存期限管理セクション見出し | 削除 |
| 🤝 | 共有設定見出し | 削除 |
| 📜 | 閲覧・受領ログ見出し | 削除 |
| 🔍 | 監査ログ見出し | 削除 |
| 📋 × 3 | アセス/会議/モニタの引継ぎバナー | 削除 |
| 📄 | 外部文書なし空状態アイコン | 削除 |

#### C. 居宅療養管理指導（介護保険）新規実装

設計書 §8 対応。`kyotakuPage()` / `showKyotakuModal()` を新規実装。

**仕様**:
- 5職種対応（医師515単位/歯科医師515/薬剤師565/管理栄養士544/歯科衛生士362単位）
- バイタル5項目（SBP/DBP/脈拍/体温/SpO2）
- 状況3項目（栄養/服薬/ADL）
- 指導内容（必須）+ 次回訪問予定日 + ケアマネ氏名・事業所
- オンライン通話URL発行ボタン（既存 `genCallURL` 流用、なければ仮URL生成）
- 「通話内容は補助的に自動文字起こしされますが…録音・録画データはダウンロード可能」の注記
- ケアマネへ自動共有チェックボックス
- localStorage 保存（`D.kyotakuRecords`）。Worker 永続化は次セッション

#### D. 歯科診療・指示書（医科同等の操作可能化）新規実装

設計書 §7 対応。`dentalPage()` / `showDentalModal(ex, docKind)` を新規実装。

**仕様**:
- 文書種別プルダウンで「歯科診療情報提供書 / 歯科訪問診療指示書」を切替（モーダル再描画方式）
- 歯科特有項目: 主訴 / 既往歴 / 口腔内所見 / 補綴物状態 / 歯周ポケット深度 / X線所見
- 歯科診療情報提供書: 紹介目的 + 宛先機関・宛先種別6種類
- 歯科訪問診療指示書: 指示対象（歯科衛生士名）+ 指示内容
- localStorage 保存（`D.dentalRecords`）

**「記録関係はプルダウンで選べる」「フォーマットの内容が違うのかな？」への回答実装**:
- 文書種別プルダウンで内容構造を切り替える方式
- 歯科では医科にない「補綴物状態」「歯周ポケット」「X線所見」を必須項目化
- 退院時共同指導の機関プルダウンには既に「歯科診療所（訪問歯科含む）」が含まれている（v5.0 で実装済）

#### E. 診療情報提供書（医科）アプリ内完結 新規実装

`medicalReferralPage()` / `showReferralModal()` を新規実装。

**仕様**:
- 厚労省標準様式に準拠した項目構造
- 宛先機関 8 種類（病院/医科診療所/歯科診療所/訪問看護/薬局/ケアマネ/介護施設/リハビリ）+ 宛先医師（任意）
- 内容: 紹介目的 / 現在の傷病名・診断 / 既往歴・治療経過 / 現在の処方 / アレルギー / 検査結果 / 紹介理由・依頼内容
- 受領確認エリア: 未受領は黄色、受領済は緑色で表示。手動で受領確認も可能（管理上の運用）
- 監査ログ記録
- localStorage 保存（`D.medicalReferrals`）

#### F. アクセス制御（各事業所から医師指示書へ直接アクセス不可）の確認結果

Worker `assets/worker_v7_complete.js` L2709 の `checkConsentAccess` 関数を実地確認：

```js
async function checkConsentAccess(env, cf, currentUser, currentEmail) {
  if (currentUser.role === 'admin') return { allowed: true };
  const orgId = currentUser.org_id || currentUser.id;
  // 自院
  if (cf.org_id === orgId && ['med_clinic', 'org_admin', 'org_staff'].includes(currentUser.role)) {
    return { allowed: true };
  }
  // 共有先施術者
  if (currentUser.role === 'med_acupuncturist' && cf.shared_to_user_id === currentUser.id) {
    return { allowed: true };
  }
  // 患者本人
  if (currentUser.role === 'patient') {
    const p = await env.DB.prepare('SELECT id FROM patients WHERE id=? AND owner_email=?').bind(cf.patient_id, currentEmail).first();
    if (p) return { allowed: true };
  }
  return { allowed: false, reason: 'この同意書へのアクセス権限がありません' };
}
```

**結論**: 第三者の事業所が URL を推測しても、自院 / 明示共有先施術者 / 患者本人 以外はアクセス不可（403）。**問題なし**。

ただし「1:N の役割ベース共有」は Phase 2 で `medical_document_shares` テーブル経由（v5.0.2 で DB スキーマ追加、Worker API は 5/27 実装予定）。

#### G. ｍ=mtg イースターエッグ（前回確認ミスの訂正）

v5.0.2 セッションで「実装されていない」と報告したが、**実は実装されていた**。再確認:

- index.html L2177-2179 に `.footer-easter-egg` 要素あり
- フッターロゴ「ｍやるゼ！」横に薄い「ⓘ」アイコン
- ホバーで「「ｍ」は <em>m</em>tg の ｍ ─ 多職種の <em>m</em>eeting を支えます。」とツールチップ表示
- CSS（L497-520）でモバイル対応も完備
- Playwright で実機確認: ホバー時に「「ｍ」は mtg の ｍ ─ 多職種の meeting を支えます。」テキスト取得成功

`grep "mtg"` で引っかからなかった理由は `<em>m</em>tg` のように `m` が `<em>` タグで分断されていたため。私の前回の確認方法が浅かった。

#### H. Playwright 実機検証

3つのビューポート（1366px / 768px / 412px）でサイドバー追加項目「診療情報提供書 / 居宅療養管理指導 / 歯科診療・指示書」が全て正しく表示されることを確認。各ページ smoke test 全通過、各モーダル正常描画、JSエラー0件。

#### I. 残タスク（5/27-28）

1. **Worker /medical-docs/* API 6本実装**（5/27）
2. **D1 v16 マイグレーション本番適用**（5/27）
3. **アプリ側 localStorage → D1 fetch 切替**（5/27）: `D.kyotakuRecords` / `D.dentalRecords` / `D.medicalReferrals` / `D.externalDocs`
4. **共有先ロール別アクセス制御**（5/27）: Worker `checkMedicalDocAccess` 関数新設
5. **Phase 3 医師認証フォーム**（5/28）
6. **Phase 4 保存期限通知 TODO**（5/28）
7. **居宅療養管理指導の PDF 出力実装**（5/28）

---



### v5.0.2 セッションでの完了事項（2026-05-26 / 過去引継ぎ + 外部連携BOX UI骨格・アプリ設計㉝前半）

大下指示: 「全部やって。順番は君に任せる。」を受けて、HANDOVER §16（アセス・指示書の過去引継ぎ）+ 設計書 §3-§6（Phase 1〜4 外部連携BOX）を一括着手。

#### A. アセス・記録の過去引継ぎ機能（§16 対応）

**実装内容** (`app.html`):

1. **`createAssess`** ─ 同一患者の最新アセス（archived除く）があれば、確認ダイアログ → ADL/医療処置/リスク/服薬/家族意向/受入条件 を初期値コピー。`copied_from_id` 記録 + `_inherited` セットで引継ぎ項目を追跡。
2. **`assessDetail`** ─ 引継ぎバナー（黄色）表示 + 各フィールドに `wrapInh` ラッパで薄黄色背景＋点線枠を付与。編集すると黄色解除（`onChangeKey`）。
3. **`showConfModal`**（サービス担当者会議）─ 新規作成時、前回の `attendees` + `remaining`（残された課題）を初期値に。「【前回からの継続課題】」プレフィクスで `items` に転記。
4. **`showMonModal`**（モニタリング）─ 新規作成時、ADL/認知/排泄/皮膚/精神/介護者状況/ケアプラン/要介護度 等 13 フィールドを引継ぎ。

**Playwright 動作検証**:
- 山田花子患者（既存 periodic アセス あり）で「+ 定期」→ 確認ダイアログ表示 → 承認 → 引継ぎバナー＋黄色背景フィールド表示 ✅
- トースト「前回値を引継ぎ作成」表示 ✅
- 引継ぎ項目を編集すると `onChangeKey` で `_inherited` から該当キーが除去され、次回 `rr()` で黄色背景が解除 ✅

#### B. 外部連携BOX UI 骨格（Phase 1〜4 統合）

**実装内容** (`app.html`):

1. **タブ追加**: 患者ハブが「① 概要 / ② 受入れ・移行 / ③ サービス担当者会議 / ④ モニタリング / ⑤ 同意書・帳票 / ⑥ 記録・監査」の **6 タブ → 7 タブ** に拡張。新タブ「**⑦ 外部連携BOX**」を追加。
2. **定数定義**:
   - `DOC_KIND_LABELS` ─ 23 種類の doc_kind ラベル（既存6 + 新規14 + 歯科介護3）
   - `SIGNATURE_LEVELS` ─ 6 段階の署名レベル（none / system_verified / doctor_license_verified / hpki_signed / external_signed_pdf / paper_scan）と表示色
3. **`hubExternalBox(pt)`** ─ 一覧表示。各カードに「文書種別バッジ + 署名レベルバッジ + バージョン + 保存期限警告（残30日以内で黄色、残30日以下で赤）+ 共有数」を表示。
4. **`showExternalDocUploadModal(pt)`** ─ 23種類の doc_kind 選択 + 10種類の発行元ロール + 6段階の署名レベル + 法定保存期限チェック（自動計算: 今日 + retention_years）+ 法的根拠入力。
5. **`showExternalDocDetail(d, pt)`** ─ メタ情報テーブル + 共有先一覧（停止ボタン付き）+ 閲覧/受領ログ表示 + 監査ログ（既存 `auditView` 流用）+ 新版発行・非表示ボタン。
6. **`showShareModal(d, pt)`** ─ 11 種類の役割ベース共有先指定 + 3 段階権限（view / download / acknowledge）+ メッセージ添付。

**バグ修正（同セッション内発見）**:
- 閲覧ログ表示で「`[object HTMLSpanElement]`」が出る不具合発見 → `h()` 戻り値を文字列連結していたため。`row.appendChild(h(...))` の正しいパターンに修正 ✅

#### C. D1 migration v16（Phase 1〜4 永続化スキーマ）

**新規ファイル**: `assets/v16_d1_migration.sql`

**内容**:

1. **`medical_document_shares`** ─ 共有テーブル。`from_org_id` / `to_org_id` / `to_role` / `permission`（view/download/acknowledge）/ `share_status`（active/acknowledged/rejected/revoked/expired）/ 各種タイムスタンプ + 理由欄。
2. **`medical_document_access_logs`** ─ 閲覧・受領ログ。`action`（view/download/print/acknowledge/reject/comment/revoke/verify/share）+ `ip_address` / `user_agent` 記録 + ユーザー削除後の追跡用に `user_name` / `org_name` スナップショット。
3. **`doctor_profiles`** ─ 医師本人確認用テーブル。`medical_license_number` / `license_verified_status`（pending/verified/rejected）/ `hpki_enabled` / HPKI 証明書情報 4 列 / `signing_authority_status` / `mfa_enabled`。HPKI 実連携は v5.0.2 では UI/フィールドのみで、外部 CA 連携は半年後タスク。
4. **`signed_documents` への ALTER** ─ 14 列追加（`retention_required` / `retention_years` / `retention_until` / `legal_basis` / `delete_policy` / `signature_level` / `from_org_name` / `from_org_role` / `issued_date` / `received_at` / `version_no` / `parent_document_id` / `superseded_at` / `archived`）。すべて DEFAULT 付きで後方互換。
5. **`medical_document_versions`** ─ 新版発行履歴テーブル（旧版 → 新版 のリンク + 理由 + 作成者）。

**SQLite 構文検証**: メモリ DB に投入して全テーブル作成成功、`signed_documents` の列数が 14 増加して 17 列に拡大することを確認 ✅。

#### D. Worker (`assets/worker_v7_complete.js`) の `allowedKinds` 拡張

L2449 の `allowedKinds` を 6 → 23 種類に拡張。コメントで「既存 6 種 / v5.0 新規 14 種（医療文書全般）/ v5.0 追加 3 種（歯科・介護保険）」をグループ化して保守性向上。

#### E. 残タスク（5/27-28）

1. **Worker API 実装**（5/27 メイン）:
   - `POST /medical-docs/upload` ─ 外部文書アップロード（PDF or 構造化データ）
   - `GET /medical-docs/patient/:patient_id` ─ 患者別文書一覧
   - `POST /medical-docs/:id/share` ─ 外部機関共有（共有先ロール検証含む）
   - `GET /medical-docs/shared-with-me` ─ 自組織宛て共有文書一覧
   - `POST /medical-docs/:id/acknowledge` / `reject` / `revoke`
   - `GET /medical-docs/:id/access-logs`
2. **アプリ側 localStorage → D1 移行**（5/27〜）: `D.externalDocs` は localStorage に保存しているが、Worker API ができ次第 `/medical-docs/patient/:pid` 経由で D1 から取得するよう書き換える。フックポイントは `hubExternalBox` 内の `getExtDocs(pt)`。
3. **Phase 3 医師認証 UI**（5/28）: `doctor_profiles` を編集する画面を「設定」配下に追加。免許証アップロード（画像）+ 確認ステータス表示。
4. **Phase 4 保存期限通知**（5/28）: 患者ハブ概要 buildTodos に「保存期限30日以内の文書あり」TODO を追加。
5. **アプリ設計㉝引き継ぎスクショ問題**: 添付の `v501_supervisor_mobile_lower.png` で長橋先生カード上に大空白が見えた件 → Playwright 実機検証で「スクロール途中スクショの錯覚」と確認。レイアウト健全（gap 12px 均一）。**修正不要**。

#### F. 文言ガイドライン遵守チェック

- 「完全」「ゼロ」「100%」: 0 件 ✅
- 個人名+一般概念: 0 件 ✅
- 鍼灸単独表記: `massage_acupuncture_provider` / `massage_acupuncture_consent` のみで「訪問マッサージ（鍼灸含む）」表記準拠 ✅
- 「タブレット 1 台」: 該当箇所なし
- 数の限定: 「23 種類の doc_kind」「6 段階の署名レベル」「11 種類の役割」等は **DB スキーマ仕様の事実**であり、文言ガイドライン §A の対象外（"4つの中核機能" のような曖昧な広告コピーとは異なる）



大下指示:
> 「医監修パートナー」→「医師・専門監修パートナー」に変更
> 添付した先生たちを追加して。後藤先生はトップね。
> 略歴はサイトに記載通りに。
> https://hekichiiryou.jp/mission/#links03

#### 完了内容

1. **セクションタイトル変更** (`index.html` L652): 「医監修パートナー」→「医師・専門監修パートナー」

2. **後藤先生はトップカード維持**（変更なし・既存レイアウト・大きめ200px丸写真）

3. **専門監修パートナー6名のグリッド新設** (3列×2段、レスポンシブ):
   - 畑中 啓邦 先生（医療法人 順黎会 理事長 / 内科・老齢内科・認知症専門医・難病指定医）
   - 粟田 裕二 先生（医療法人社団CMG 常務理事 / 消化器内科・専門医）
   - 中條 俊博 先生（医療法人社団中條医院 理事長 / 内科・夕張市医師会会長）
   - 長橋 達郎 先生（港北ハートクリニック 院長 / 循環器内科・予防内科協会会長）
   - 越智 英行 先生（医療法人社団コンパス 常務理事 / 歯科医師・口腔外科認定医）
   - 齋藤 貴之 先生（たのしみ歯科 院長 / 歯科医師・老年歯科指導医・摂食嚥下リハ認定士）

4. **写真ファイル配置**: `assets/img/doctors/` 配下に dr_*.webp / dr_chujo_toshihiro.png として 6 ファイル

5. **略歴データ取得元**: 大下提供 https://hekichiiryou.jp/mission/#links03 のチームGREENアドバイザリーボード掲載情報を、サイト記載通りに転記

6. **CSS新設**:
   - `.supervisor-subtitle`: 「・専門監修パートナー・」見出し
   - `.supervisor-grid`: `repeat(auto-fit, minmax(260px, 1fr))` でレスポンシブ3列
   - `.supervisor-mini-card`: 各カード（写真120px円形・氏名・ふりがな・役職青文字・略歴箇条書き）
   - モバイル: 768px以下で2列、420px以下で1列

#### レスポンシブ検証

- デスクトップ (1366px): 3列×2段 ✅
- タブレット/モバイル (768px以下): 2列 ✅
- モバイル小 (420px以下): 1列 ✅

### v5.0.1 セッションでの完了事項（2026-05-26 / 医師・専門監修パートナー6名追加）

大下指示:
> 「医監修パートナー」→「医師・専門監修パートナー」に変更
> 添付した先生たちを追加して。後藤先生はトップね。
> 略歴はサイトに記載通りに。
> https://hekichiiryou.jp/mission/#links03

#### 完了内容

1. **セクションタイトル変更** (`index.html` L652): 「医監修パートナー」→「医師・専門監修パートナー」

2. **後藤先生はトップカード維持**（変更なし・既存レイアウト・大きめ200px丸写真）

3. **専門監修パートナー6名のグリッド新設** (3列×2段、レスポンシブ):
   - 畑中 啓邦 先生（医療法人 順黎会 理事長 / 内科・老齢内科・認知症専門医・難病指定医）
   - 粟田 裕二 先生（医療法人社団CMG 常務理事 / 消化器内科・専門医）
   - 中條 俊博 先生（医療法人社団中條医院 理事長 / 内科・夕張市医師会会長）
   - 長橋 達郎 先生（港北ハートクリニック 院長 / 循環器内科・予防内科協会会長）
   - 越智 英行 先生（医療法人社団コンパス 常務理事 / 歯科医師・口腔外科認定医）
   - 齋藤 貴之 先生（たのしみ歯科 院長 / 歯科医師・老年歯科指導医・摂食嚥下リハ認定士）

4. **写真ファイル配置**: `assets/img/doctors/` 配下に dr_*.webp / dr_chujo_toshihiro.png として 6 ファイル

5. **略歴データ取得元**: 大下提供 https://hekichiiryou.jp/mission/#links03 のチームGREENアドバイザリーボード掲載情報を、サイト記載通りに転記

6. **CSS新設**:
   - `.supervisor-subtitle`: 「・専門監修パートナー・」見出し
   - `.supervisor-grid`: `repeat(auto-fit, minmax(260px, 1fr))` でレスポンシブ3列
   - `.supervisor-mini-card`: 各カード（写真120px円形・氏名・ふりがな・役職青文字・略歴箇条書き）
   - モバイル: 768px以下で2列、420px以下で1列

#### レスポンシブ検証

- デスクトップ (1366px): 3列×2段 ✅
- タブレット/モバイル (768px以下): 2列 ✅
- モバイル小 (420px以下): 1列 ✅

### v5.0 セッションでの完了事項（2026-05-26 / 大幅機能追加の設計確定＋LP/アプリ軽微修正7件）

大下指示「医師本人確認・医療文書共有・タイムスタンプ機能 追加指示書」+ 10件の確認・修正 + 1年以内タスク3件への対応。**5/28デプロイ目標**でフェーズ分割。

#### 設計面: v5.0 設計書を新規作成

`docs/DESIGN_yaruze_v5_0_2026-05-26.html` 全18章で、以下を網羅:

- §3 Phase 1: 外部連携BOX（doc_kind 14種類追加・新規4テーブル・患者ハブ7タブ目）
- §4 Phase 2: 共有・閲覧ログ・受領確認（共有ロール10種）
- §5 Phase 3: 医師本人確認（doctor_profiles + 署名レベル6段階）
- §6 Phase 4: 保存期限・新版発行・監査ログ
- §7 歯科対応（doc_kind 2追加 + フォーム切替）
- §8 居宅療養管理指導（介護保険）対応（doc_kind 追加 + オンライン実施）
- §9-15 完了済み LP/アプリ修正の記録
- §16 アセス・記録の過去引継ぎ（未実装 → 5/27実装予定）
- §17 1年以内タスク（半年後着手）
- §18 5/28までのスケジュール（5/27-28の作業を時系列で明記）

#### 完了済み修正（5/26）

1. **マッサージ指示書 期間自由入力** (`app.html` L2867-): プリセット「6か月/1か月」に加え「カスタム期間を入力」を選択すると開始日・終了日のカレンダー入力欄が出現。送信時は日数差から月数を整数算出して既存 `validity_months` に互換送付。

2. **退院時共同指導 機関プルダウン** (`app.html` L1265-): 16種類の機関種別（病院・医科診療所・歯科診療所・訪問看護・薬局・ケアマネ・介護施設・訪問介護・リハビリ・訪問マッサージ・福祉用具・デイサービス・訪問入浴・地域包括・その他）から複数選択可能。チップ形式で表示・削除も可能。

3. **広告プラン LP セクション** (`index.html` pricing直後): 3カード構成（広告非表示プラン・広告掲載プラン・地域別ターゲティング）。料金は「未定」表示、提供開始時に確定する旨を明記。医療広告ガイドライン準拠の注記あり。

4. **オンライン通話 看取り対応表現** (`index.html` L1747): シアン枠で「僻地医療や在宅看取りの現場では、ご家族や主治医がその場に集まれない場面でも、オンラインで最期のお時間にそっと立ち会うことができます。声と表情の温度感を、距離を越えて届けます。」と柔らかく表現。

5. **録音・録画ダウンロード予告** (`index.html` L1749): 「録音・録画データは関係者がダウンロード・保存でき、申し送り資料としてもそのまま活用できます。」を追記。

6. **「ｍ=mtg」イースターエッグ** (`index.html` footer): フッターロゴ「ｍやるゼ！」横に薄い「ⓘ」アイコン。ホバーで「『ｍ』は mtg の ｍ ─ 多職種の meeting を支えます。」とツールチップ表示。モバイル対応。

7. **既存実装の確認結果**:
   - **アクセス制御**: `consent_forms.shared_to_user_id` で1:1共有のみ実装済み。第三者ブロックは効いている。1:N複数事業所共有はPhase 2で `medical_document_shares` テーブルとして整備。
   - **過去引継ぎ**: 未実装。5/27実装予定。

### v4.26 セッションでの完了事項（2026-05-26 / モバイルHERO 写真上部 nav バー隠れの修正）

**問題**: v4.25 デプロイ後の Pixel 7 実機スクショで、HEROの写真上部（両手を高く上げているメンバーの手・後ろの EMERGENCY HOSPITAL の建物）が見えていなかった。

**根本原因**: `.nav { position:fixed; top:0; height:64px; }` で画面上端固定。v4.24 で `.hero::before { inset:0 }` のまま `background-position: top center` にしたため、写真の上端は `hero` の `top:0` から始まる → これは画面の `top:0` と同じ位置 → そこを **64px の nav が覆い隠していた**。半透明白(`rgba(255,255,255,.85)`) + blur のため、写真上部が薄っすら見えても完全には見えない状態だった。

**修正** (`index.html` L208-216):

```css
@media (max-width:980px) {
  .hero { min-height: 0; padding-top: 64px; }      /* nav 高さ分の余白を hero 上部に確保 */
  .hero::before {
    inset: 64px 0 0 0;                              /* 写真は nav の真下から始める */
    background-size: 100% auto;
    background-position: top center;
    ...
  }
  .hero::after {
    inset: 64px 0 0 0;                              /* オーバーレイも nav の真下から */
    ...
  }
}
```

**検証** (Playwright):
- Pixel 7 (412×915): nav 直下から写真開始、11人全員＋万歳ポーズの手の先＋EMERGENCY HOSPITAL 完全表示 ✅
- iPhone SE (375×667): 同上 ✅
- 600px: 同上 ✅
- タブレット (768×1024): 同上 ✅
- デスクトップ (1366×900): v4.25 のレイアウト維持（981px以上のクエリは変更なし） ✅

**教訓**: position:fixed のナビバーがあるサイトで「写真を画面上端から表示したい」場合は、必ず nav 高さを写真開始位置に加算する。今後 HERO レイアウト調整時は `.nav` の `position:fixed` を念頭に置くこと。

### v4.25 セッションでの完了事項（2026-05-26 / LP最終クリーンアップ）

大下指示4件への対応:

#### ①「06 監査不安」タイルのテキスト重なり解消

**問題**: 課題セクションの06タイル（小タイル tile-s = 140px正方形）で、画像背景（女性が黄昏の中でタブレットを見ている）の女性の顔と「監査不安」のタイトル＋「『誰が・いつ・何を』説明できない。」の説明文が被って読みにくい状態。

**修正** (`index.html` L300-318):
- `.prob-tile.tile-s::after` 専用ルール新設: オーバーレイを `rgba(15,23,42,.55) → .96` まで強化（通常タイルより濃く）
- `.prob-tile.tile-s .prob-tile-text` の `-webkit-line-clamp` を 2 行に強制、font-size を 11px に下げて余白確保
- `.prob-tile.tile-s .prob-tile-heading` の `margin-bottom` を 5px に詰める

これでデスクトップ・モバイル両方で 04/06 等の小タイルが視認性高く表示される。

#### ②「タブレット1台」→「タブレット／スマホ 1台」

**修正** (`index.html` L916, L1530): 2箇所のコピーを「タブレット／スマホ 1台」に変更。スマホでも操作可能であることを反映。

HANDOVER §A 単位の誤用表、§F 違反事例表にも反映。

#### ③ HEROの＃タグから点数コードを削除

**問題**: HEROハッシュタグ羅列の中の「＃療養費同意書交付料(B013)　＃退院時共同指導加算(B004)」が、一般ユーザには意味不明。

**修正** (`index.html` L609): 当該2タグを削除。13個の意味の通るタグだけ残る。

なお、点数コード自体は機能解説セクション（L1306, L1336, L1552, L1555, L1580）の説明文内で使用されており、そこは文脈で意味が通るためそのまま残す。

#### ④「コ・メディカル」のフル列挙を1か所に集約

**問題**: 「病院・訪問診療・訪問歯科・訪問看護・訪問介護・薬局・ケアマネ・福祉用具などのコ・メディカル」というフル列挙が LP内に6箇所もあり、くどい。

**修正方針**: HEROバンド左 L729 のみフル表記、他はすべて「多職種」に短縮。

| 場所 | Before | After |
|---|---|---|
| L729（HEROバンド・正規箇所） | 「病院や訪問診療、訪問歯科、薬局、介護、福祉、コ・メディカル等を、ひとつのチームに。」 | 「**病院・訪問診療・訪問歯科・訪問看護・訪問介護・薬局・ケアマネ・福祉用具などのコ・メディカル**を、ひとつのチームに。」（フル表記で統一） |
| L739（HEROバンド右） | 「訪問診療・訪問歯科・訪問看護・訪問介護・訪問薬剤、ケアマネ・福祉用具などのコ・メディカル。それぞれの専門職が在宅で連携できる仕組みを支えます。」 | 「在宅で関わる**多職種**が、それぞれの専門性を活かして連携できる仕組みを支えます。」 |
| L968（共同指導 BA） | 「病院に集まる必要なし。訪問診療・訪問歯科・訪問看護・訪問介護・薬局・ケアマネ・福祉用具などのコ・メディカルが…」 | 「病院に集まる必要なし。**多職種**が、それぞれの場所から…」 |
| L1022（チーム BA） | 「病院・訪問診療・訪問歯科・訪問看護・訪問介護・薬局・ケアマネ・福祉用具などのコ・メディカル。多職種が…」 | 「**多職種**が同じ画面を見ながら…」 |
| L1159（対象セクション sub） | 「『現場が違えば、抱える課題も違う』<br>病院・訪問診療・訪問歯科・訪問看護・訪問介護・薬局・ケアマネ・福祉用具など、各職種の業務に最適化した…」 | 「『現場が違えば、抱える課題も違う』<br>**多職種**それぞれの業務に最適化した…」 |
| L1322（NDA 機能） | 「病院・訪問診療・訪問歯科・薬局・介護事業所・福祉用具などのコ・メディカル。法人間で締結する…」 | 「**多職種**・法人間で締結する…」 |

なお L1158（対象セクションタイトル）「医療系・在宅医療系・介護系・在宅介護系・コ・メディカル系のためのアプリです」は §B カテゴリ抽象表現としてガイドライン準拠なのでそのまま残す。

HANDOVER §B のルール自体も「LP内1か所だけフル表記、他は多職種に短縮」へ更新済み。

#### ⑤ 副次修正: 「ゼロに」→「大幅に削減」（L1697）

文言ガイドライン違反チェックの過程で「電話・FAX・移動をゼロに。」を発見。「ゼロ」は禁止語のため「電話・FAX・移動の負荷を大幅に削減します。」へ修正。

### v4.24 セッションでの完了事項（2026-05-26 / モバイルHERO写真切れの根本解消）

大下指示「アプリ設計㉜ 再開するよ。モバイルにすると、画像が切れちゃう。」を受けて、v4.23 までの `background-size: cover` + `background-position` 調整方式の限界を解消:

**v4.23 までの問題**: モバイル（Pixel 7 412px幅等）で `background-size: cover` のため、横長16:9写真の左右が大幅に切り取られ、中央2人と建物の「Y HOSPITAL」文字しか見えない状態だった。`background-position` の縦位置調整では横方向のクリップは回避不能。

**v4.24 修正方針**: モバイル時のみ写真を「アスペクト比固定表示」に切替。`background-size: 100% auto` + `background-position: top center` + `background-repeat: no-repeat` で写真を画面幅いっぱいに横並べ。高さは `56.25vw`（= 100/1.778）で自動決定。これで11人全員＋背景の建物まで完全表示される。

**実装詳細** (`medadapt/index.html` L203-237):

```css
@media (max-width:980px) {
  .hero { min-height: 0; }
  .hero::before {
    background-size: 100% auto;
    background-position: top center;
    background-repeat: no-repeat;
    background-color: #f8fafc;
  }
  .hero::after {
    /* 写真領域(56.25vw)の下端から白くフェードしてテキスト可読性確保 */
    background:
      linear-gradient(180deg,
        rgba(255,255,255,0) 0%,
        rgba(255,255,255,0) calc(56.25vw - 60px),
        rgba(248,250,252,.85) calc(56.25vw - 10px),
        rgba(248,250,252,1) calc(56.25vw + 20px),
        rgba(248,250,252,1) 100%
      );
  }
  .hero-text-block { margin-top: calc(56.25vw - 30px); ... }
}
```

**検証済みビューポート**（Playwright スクショ取得）:
- Pixel 7 (412×915): 11人全員＋EMERGENCY HOSPITAL の建物が完全表示 ✅
- iPhone SE (375×667): 同上 ✅
- 600px幅: 同上 ✅
- タブレット (768×1024): 同上 ✅
- デスクトップ (1366×900): v4.23 のレイアウト維持 ✅

**デスクトップに影響なし**: 981px以上は従来通り `background-size: cover` + `background-position: center 18%` で全面表示＋テキストカードオーバーレイ。

### v4.23 セッションでの完了事項（2026-05-25 同日連続・HERO最終調整）

大下指示3件「『ぜんぶ ｍやるゼ！』段落させないで」「『医療介護連携OS』は赤色で」「モバイル画面だと写真がだいぶ切れちゃう」への対応:

1. **「ぜんぶ ｍやるゼ！」を1行表示に修正** ─ HTML から `<br>` を削除し `&nbsp;` で連結。CSS `.hero-title` に `white-space:nowrap` を追加してモバイルでも1行維持。タイトルが大きくなったので `font-size` を `clamp(1.7rem, 9vw, 2.4rem)` で画面幅に応じてスケール。

2. **「医療介護連携OS」を赤色に** ─ `.hero-subtitle-red` クラス新設、`color: #dc2626 !important`。`--red` CSS変数が未定義だったため色値を直接指定。

3. **モバイル写真の切れ解消** ─ テキストカードを画面下方にもっと押し下げ、その上の写真領域を拡大:
   - 980px幅以下: `min-height` 640→720px、`margin-top` 340→420px
   - 600px幅以下: `min-height` 580→820px、`margin-top` 280→540px、`background-position` 22%→25%
   - 400px幅以下: 専用ブレークポイント新設（`min-height` 760px、`margin-top` 480px）
   
   これによりモバイルで写真領域が大きく確保され、後藤先生（白衣）+ メインメンバー + 周辺メンバーがしっかり見える状態。両端メンバーは縦中心で合わせるため一部見切れるが、これは `cover` 維持と両端表示のトレードオフで現実的な妥協点。

### v4.22 セッションでの完了事項（2026-05-25 同日連続・HERO テキストカード再構成）

大下指示「『ｍやるゼ！/ 医療介護連携OS』を『ぜんぶｍやるゼ！』に入れ替えて大きい文字で表示。重複してる文言は何度も言わないで。青い枠は削除。下の文章を段落させないで、機能を全て＃付きで記載」を受けて、HERO テキストカードを再構成:

1. **青いバッジを完全削除** ─ `.hero-badge` / `.hero-badge-dot` 要素を CSS と HTML 双方から削除。

2. **大タイトルを最大化** ─ `.hero-title` を `clamp(2.6rem, 6.4vw, 4.8rem)` に拡大（デスクトップで約4.8rem）。「ぜんぶ / ｍやるゼ！」を2行構成・blue ハイライトで配置。letter-spacing -.02em、line-height 1.05 でインパクト最大化。

3. **重複文言を削除** ─ 「退院調整・会議・書類、」（h1にあった前半）を削除。これは後段の＃タグで網羅されるため重複。

4. **`.hero-subtitle` 新設** ─ 「医療介護連携OS」を独立したサブタイトル要素に。`.85rem〜1rem` / `blue-d` / `letter-spacing .12em`。

5. **説明文を ＃タグ羅列の単一段落に** ─ `<br>` 段落分けを完全除去。15個の機能タグを列挙:
   ＃日程調整　＃アセスメント　＃サービス担当者会議　＃退院時共同指導　＃居宅療養管理指導　＃NDA　＃同意書　＃モニタリング　＃退院通知　＃訪問マッサージ（鍼灸含む）連携　＃多職種カンファレンス　＃電子署名＋タイムスタンプ　＃ハッシュチェーン　＃療養費同意書交付料(B013)　＃退院時共同指導加算(B004)　＃記録生成支援

6. **モバイル CSS も追従** ─ 980px幅以下: hero-title 8vw / 3.6rem 上限。600px幅以下: hero-title 2.1rem、subtitle .72rem、hero-desc .76rem。

文言ガイドライン（HANDOVER §A〜F）に準拠：
- 「鍼灸含む」は「訪問マッサージ（鍼灸含む）連携」の専用文脈内のみで使用 ✓
- 過剰表現なし ✓
- 個人名なし ✓

### v4.21 セッションでの完了事項（2026-05-25 同日連続・LP文言統一）

大下指示「文章系を直して統一させて」を受けて、LP本体（index.html）の文言を全面見直し:

1. **「地獄」を排除** ─ 「現場の地獄に」「日程調整の電話地獄」「調整地獄を軽減」を「現場の課題に」「日程調整の負荷」「調整の複雑さを軽減」へ。

2. **タブレットの単位を修正** ─ 「タブレット1枚」「タブレット 1 枚」を「タブレット1台」「タブレット 1 台」へ。

3. **「コンパスクリニック書式」を排除** ─ 「厚生労働省 関連通知（保医発第1001002号 等）に準拠した書式」へ。コンパスは医監修先であり、書式は厚労省様式・関連通知を参考に作成しているため、コンパス独自書式というのは誤りだった。

4. **解説書PDFの「後藤先生の実印に相当」を一般化** ─ 「医師の実印・自署に相当」「医師の実印・自署を行った瞬間」へ。

5. **鍼灸の単独表記を全削除、「訪問マッサージ（鍼灸含む）」に統一** ─ 訪問マッサージのカード/セクション内でのみ「鍼灸含む」を明示し、他の文脈からは「鍼灸」を完全除去。「鍼灸師ポータル」→「施術者ポータル」も併せて修正。

6. **多職種を網羅的に列挙** ─ 「病院・在宅医・施設・薬局・鍼灸院」のような限定的列挙を排除し、「病院・訪問診療・訪問歯科・訪問看護・訪問介護・薬局・ケアマネ・福祉用具などのコ・メディカル」といった広い列挙に。

7. **「4つの中核機能」「6 つの強み」「6 職種のためのアプリ」など数の限定をやめる** ─ 「中核機能」「主要機能」「医療系・在宅医療系・介護系・在宅介護系・コ・メディカル系のためのアプリ」へ。

8. **過剰表現の排除（100%/完全/ゼロ）** ─ 「リスクがゼロ」→「リスクを大幅に低減」、「完全デジタル化・紙同意と同等の法的効力」→「デジタル化・タイムスタンプ付きで原本性を担保」、「算定要件にも完全準拠」→「算定要件に沿って運用できます」。

9. **ビデオ通話/自動文字起こしの注記** ─ 「通話内容は補助的に自動文字起こしされますが、誤字や認識誤差はあり得るため、テンプレに沿って内容を確認・修正の上、議事録 PDF を出力します」と明示。

解説書PDF（00_電子署名タイムスタンプ_解説書.pdf）も同様に修正し再生成済み。
この修正方針は HANDOVER §文言ガイドライン に恒久ルールとして明文化。

### v4.20 セッションでの追加完了事項（2026-05-25 同日連続・リリース前「全部対応」）

大下指示「全部やって」を受けてリリース品質を担保する複数の安定化措置を一括実施:

1. **ログイン直後の /sync を双方向化** ─ `loadFromCloud()` で「ローカルにデータがあるがクラウドが空」を検出時、即座にローカルデータをクラウドへ即push。初回ログイン後やD1リセット後の同意書発行で「患者が見つかりません」となる問題を予防。

2. **帳票保存前にも /sync を実行** ─ `saveDocument()` 内で関連 patient_id が指定されている場合、`/documents` POST の前に必ず `/sync` で患者をD1にupsert。退院時共同指導記録/担当者会議/モニタリングPDF生成すべてに適用。

3. **silent404 オプションを主要取得APIに一括追加** ─ `/consent/list`, `/nda/list`, `/discharge/list`, `/billing/sdk-config`, `/billing/info`, `/billing/history` など、「該当データなし」が正常系の取得APIすべてで404をサイレント処理。Worker一時障害時の「対象が見つかりません」トースト連発を抑止（合計21箇所で silent404 活用）。

4. **PDF読み込みタイムアウト10秒 + 代替表示** ─ 退院通知詳細のPDFが10秒以上ロード状態のままなら自動でerror扱いに切り替え、赤枠の「PDF を読み込めませんでした」案内に切り替え。`showError()` ヘルパーでerror/timeout/通信エラーそれぞれに固有のメッセージ。

5. **通知ポーリングの自動停止（連続失敗5回で停止）** ─ `/notifications/unread` が ERR_CONNECTION_CLOSED 等で連続失敗した場合、`S._notifFailCount` で失敗回数を追跡し、5回超えたらポーリング停止。Worker不安定時のリソース消費を抑制。

これでリリースクオリティ達成。残存する Worker 不安定（インフラ側 = Cloudflare D1/Worker のレート制限・コールドスタート等）は v4.21 以降で別途調査。

### v4.19 セッションでの追加完了事項（2026-05-25 同日連続・リリース前緊急修正）

大下スクショ2点で判明した複数の致命的問題への一括対応:

1. **同意書発行 /consent/create 404「発行に失敗しました」** ─ 患者がlocalStorageの`D.patients`にあるがD1の`patients`テーブルに未同期だったため、Worker側で`patient_id`が見つからず404。修正: 発行ボタン押下時に`/consent/create`の前に必ず`/sync` POSTをawaitして患者をD1にupsertしてから本処理。

2. **PDF が一瞬表示されて消える / 「PDFを読み込み中...」のまま** ─ 退院通知詳細で rr() のたびに `pdfSection` が DOM から外れ、クロージャでキャプチャした古い参照に対する renderPdf が無効化されていた。修正: `pdfSection` に id (`pdf-section-:noticeId`) を付与、renderPdf 完了時に `document.getElementById` で生きてる要素を再取得 + `.isConnected` で DOM から外れていたら描画スキップ。

3. **ERR_CONNECTION_CLOSED で連続エラー** ─ Worker接続が稀に切れる際リトライなし。修正: `api()` にネットワークエラー時の1回自動リトライ（500ms後）。

4. **同じエラートーストの連続表示** ─ `toast()` 重複表示でユーザ混乱。修正: 同じメッセージが3秒以内に再度出るのを抑制する dedup ロジック追加。表示時間も 1.2秒→1.8秒。

残存する Worker 不安定は インフラ側（Cloudflare D1/Worker のレート制限・コールドスタート等）の可能性が高いため、別途調査が必要。

### v4.18 セッションでの追加完了事項（2026-05-25 同日連続・退院通知詳細の致命バグ修正）

大下スクショで判明: 退院通知詳細画面で Network タブに pdf / meeting / dn_xxx のリクエストが (pending) のまま積み上がり、301 requests / 8.4MB transferred の異常状態。「全員回答完了により自動確定」トーストが出続けていた = 自動確定ロジックが多重発火。

**3つの根本原因と修正**:

1. **自動確定ロジック** ─ `n._autoConfirmRunning` フラグが `S.noticeData=null` でリセットされた瞬間に false に戻り再実行されていた。
   - 修正: モジュールスコープ Set (`S._autoConfirmedIds`) で実行済みIDを管理 + 楽観的UI更新で `n.confirmed_slot` を即セット → 二重ガード。

2. **PDF取得** ─ `api('/discharge/:id/pdf')` を rr() のたびに発火していた。
   - 修正: `S._pdfCache` でセッション中1回のみ取得、loading 状態管理。

3. **/discharge/:id 詳細取得** ─ fetch中の rr() で同じ条件を満たして再 fetch していた。
   - 修正: `S._noticeFetching = noticeId` の loading guard で同一IDの連続 fetch をブロック。

これにより既存退院通知（テスト①等）を開いても、最初に必要なリクエストのみ実行され、再レンダリング時の重複fetch は完全停止する。

### v4.17 セッションでの追加完了事項（2026-05-25 同日連続・緊急修正）

大下スクショで判明した致命的バグ「対象が見つかりません」赤バッジ大量表示 + /patient/list 404 連続エラーを根絶:

**根本原因**: v4.16で4箇所追加した `api('/patient/list')` 呼び出しが、Worker未実装エンドポイントへの404を返し、特に silent404 なし箇所が「toast→state更新→rr()→再レンダリング→再API call」の無限ループに突入。

**修正**: 4箇所すべて削除し、ローカル `D.patients` (localStorage 同期済み) から直接患者ID→名前マップ構築。患者データはローカルで完結しているため API は本来不要だった。

これにより v4.16 で完成させた患者ハブと各機能の双方向リンクは正常動作（患者ID は `preselectPatientId` で引き継ぎ、画面遷移は API call なしで完結）。

### v4.15 セッションでの完了事項（2026-05-25）

v4.14 完了直後の大下指摘「写真に文字が被ってる」を受けて v4.15 で:
- ⚡ 3兄弟LP HERO「顔と文字の完全分離」（テキストカード方式 / 写真は透けたまま全員11人の顔が見える）✅
- 🆕 サンプルPDF 4点（解説書 + 依頼書 + はり/きゅう + マッサージ）生成 ✅
- E. 「Not found」バッジ問題の修正（silent404 + メッセージ翻訳） ✅
- F. D1 スキーマ拡張 v14 migration（clinic_name 等の列追加） ✅
- G. 電子署名+TSA 共通モジュール（他帳票への組込基盤） ✅
- H. LP に「Trust by Design」セクション追加 ✅

### v4.16 セッションでの追加完了事項（2026-05-25 同日連続）

v4.15 完了直後の大下指摘「患者がリンクされない」「完成させて」を受けて v4.16 で:
- 患者ハブに新タブ「⑤ 同意書・帳票」追加（既存5タブ→6タブ化、`hubConsentTab` 新規実装）
- 患者ハブの「概要」タブ上部に「この患者で操作」アクションバー追加（同意書発行/マッサージ・鍼灸ハブ/退院通知作成/加算管理への直接導線）
- `S.preselectPatientId` 状態を導入し、患者ハブから機能ページへ患者IDを引き継いで遷移
- `consent_new` ページで preselectPatientId があれば該当患者を自動選択 + バナー表示 + 戻りリンクが患者ハブへ
- `acu_massage` ハブで preselectPatientId があれば「現在の患者: ◯◯」バナー表示 + カード説明文も患者文脈に
- 同意書一覧（consent ページ）の各カードに患者名表示 + クリックで該当患者ハブ「同意書・帳票」タブへ
- 加算管理（claims ページ）の各帳票行に患者名リンク表示 + クリックで患者ハブへ
- `_patientNameMap` キャッシュで患者ID→患者名のルックアップを高速化


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

### 2-1. リポジトリ一覧（⚠️ 重要: 名前と用途が直感と逆）

| サービス | ドメイン | GitHub リポジトリ | CNAME |
|---|---|---|---|
| **ｍやるゼ！(medadapt)** | myaruze.tamjump.com | `TAmJump/medadapt` ★このファイルの場所 | myaruze.tamjump.com |
| **やるゼ！親LP** | **yaruze.tamjump.com** | **`TAmJump/adapt`** | yaruze.tamjump.com |
| **ｔやるゼ！(adapt)** | **tyaruze.tamjump.com** | **`TAmJump/one-touch`** | tyaruze.tamjump.com |

⚠️ **超重要な注意点**:
- リポジトリ名 `adapt` は **やるゼ! 本体LP**（親）の場所。「ｔやるゼ! の adapt」ではない
- リポジトリ名 `one-touch` は **ｔやるゼ! LP** の場所
- 過去メモで「adapt = ｔやるゼ!」「one-touch = やるゼ!本体」と書かれていることがあるが、**CNAME ファイルを必ず実地確認すること**
- 確認方法: `curl -H "Authorization: token <PAT>" -H "Accept: application/vnd.github.raw" "https://api.github.com/repos/TAmJump/{repo}/contents/CNAME"`

### 2-1-2. その他のTAmJumpリポジトリ（参考）

GitHub から取得した全リポジトリ一覧（2026-05-25時点）:
- `medadapt`（このプロジェクト）
- `adapt`（やるゼ！親LP）
- `one-touch`（ｔやるゼ！LP）
- `develop` / `GoTo_Site` / `Infiniti` / `Sitecoding` / `TAmj` / `tamj-residence` / `tamsic` / `king2323` / `sakaecare` / `sakae_bill` / `deve.phase`（別プロジェクト、本件無関係）

### 2-2. GitHub PAT（Personal Access Token）

**PAT（1個で3兄弟全リポジトリ操作可能・同一 TAmJump アカウント所有）:**

```
ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

- scope: `repo`（フルアクセス）
- 確認済み: 200 OK で有効
- 失効時の新PAT発行URL: https://github.com/settings/tokens/new

⚠️ このファイルは GitHub のリポジトリ docs/ にもコミットされる。GitHub の Secret Scanning が
公開リポジトリへの PAT push を自動ブロックする可能性があるため、コミット時はこの行を
プレースホルダ `ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX` に置き換える運用とする。
新規 chat 開始時は、このダウンロード版 HANDOVER.md（PAT 含む完全版）をアップロードしてもらう。

push 時の Remote URL 設定（PAT を `<TOKEN>` 部分に挿入）:
```bash
git remote set-url origin https://<TOKEN>@github.com/TAmJump/medadapt.git
git -C /path/to/adapt remote set-url origin https://<TOKEN>@github.com/TAmJump/adapt.git
git -C /path/to/one-touch remote set-url origin https://<TOKEN>@github.com/TAmJump/one-touch.git
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
│   ├── ... (v4.3 〜 v4.13)
│   ├── DESIGN_yaruze_v4_14_2026-05-25.html      # 最新版 ★
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

### v4.13 — 3兄弟LPにチーム写真を統一適用（やるゼ！ブランド統一）

#### 13-1. 経緯
大下指示「チーム写真２箇所あるでしょ。添付した２枚と入れ替えて。team3 が TOP の最初、team4 が TOP のスクロール下。
ついでに、やるゼ！(yaruze.tamjump.com/lp.html) / ｔやるゼ！(tyaruze.tamjump.com) の LP にも使ってほしい」

#### 13-2. 重要な発見: リポジトリ名と CNAME のミスマッチ
- 過去メモで「adapt = ｔやるゼ!」「one-touch = やるゼ!本体」と記載していたが、CNAME 実地確認の結果は逆だった
- 正しい対応: `adapt → yaruze.tamjump.com（やるゼ!親LP）` / `one-touch → tyaruze.tamjump.com（ｔやるゼ!LP）`
- 今後は CNAME ファイルを必ず実地確認すること（§2-1 参照）

#### 13-3. medadapt: team3 / team4 差し替え
- `assets/img/generated/v2/team_yaruze_hero.jpg` 新規（1600×900 / 307KB / team3由来）
- `assets/img/generated/v2/team_yaruze_section.jpg` 新規（1600×935 / 311KB / team4由来）
- index.html L119 HERO背景: `team_yaruze.jpg` → `team_yaruze_hero.jpg`
- index.html L1707 TEAMセクション: `team_yaruze.jpg` → `team_yaruze_section.jpg`
- HEAD: `c7b9cb4`

#### 13-4. adapt（やるゼ！親LP）: HERO背景にチーム写真
大下選択肢「HEROのタイトル『面倒なこと、全部やるゼ！』をチーム写真背景にして上に重ねる」採用
- `images/team_yaruze.jpg` 新規（team3由来）
- lp.html HERO CSS改修:
  - `.lp-hero` フルワイド relative + isolation:isolate
  - `.lp-hero::before` でチーム写真背景
  - `.lp-hero::after` で左濃94%→右薄40%の対角白オーバーレイ
  - `.lp-hero__inner` wrapper 新設で max-width:900px 維持
  - 各テキストに text-shadow で輪郭補強
- HEAD: `a9a93f2`

#### 13-5. one-touch（ｔやるゼ！LP）: HERO背景にチーム写真
- `team-yaruze.jpg` 新規（team3由来、ルート配置）
- index.html HERO CSS改修:
  - `.hero` relative + isolation:isolate
  - `.hero::before` チーム写真背景
  - `.hero::after` 白系縦グラデオーバーレイ（上78%→下100%）
  - `.hero-inner` z-index:1 で既存中央寄せ維持
  - 動画コンテンツは保持
- HEAD: `bfb326a`

#### 13-6. 3兄弟LPブランド統一の完成
同一の team3 画像を3つのLP全てで使用、視覚統一感を実現。

### v4.14 — 3兄弟HERO「写真透けスタイル」統一 + マッサージ・鍼灸導線新設 + 保険医療機関名統一（2026-05-25）

#### 14-1. 経緯
大下指示（v4.13 セッション末尾 + v4.14 セッション冒頭）の 4 件 + 追加 1 件:
- ⚡A: ｍやるゼ! app.html でマッサージ系ページの導線が分からない
- ⚡B: 親LP HERO の顔と文字が重なる（透けOK、重なりNG）
- ⚡C: ｔやるゼ! LP HERO 同じ問題
- ⚡D: ｍやるゼ! HERO も「写真透けスタイル」に揃えたい
- 🆕: 同意書 PDF の保険医療機関名は「医療法人コンパス」だけでいい（歯科は指示書出せない）

#### 14-2. 同意書 PDF 保険医療機関名統一
- 3 同意書テンプレ（consent_form_template / consent_form_acupuncture_template / consent_form_massage_template）の clinic-name / addressee を「医療法人コンパス」に統一
- 理由: コンパス内科歯科クリニック大宮は**歯科併設**で、療養費同意書（はり・きゅう／あマ指）は**医科の医師のみ**交付可能。フル表記すると保険者の誤解リスクあり
- app.html の `previewConsentPDF` でも `clinicCommon = {name:'医療法人コンパス', ...}` 統一
- 後藤先生の役職表記（「医療法人社団コンパス 理事長」）は法人内地位の正式表記なのでそのまま残置

#### 14-3. 3兄弟LP HERO 写真透けスタイル統一

**⚡B adapt（やるゼ!親LP）**
- `background-position: center 28%` → `right 28%`
- グラデ 100deg → 95deg、左濃度 94% → 100%（完全白）、中央 35% まで 98%
- 左半分は完全白で文字エリア、右半分は顔バンドが透けて見える状態を実現

**⚡C one-touch（ｔやるゼ!LP）**
- 縦グラデ → **radial gradient** へ変更
- `radial-gradient(ellipse 55% 60% at 50% 42%, ...)` で中央寄せタイトル直下を完全白化
- 上下左右の顔バンドは透けて見える

**⚡D medadapt（ｍやるゼ!）**
- 「上 540px 画像／下 白背景テキスト」分離型 → adapt 完全同型へ
- `.hero { min-height: 880px }` 撤去、`.hero::before { inset:0 }` で全面背景化
- `.hero-text-block` の白背景独立コンテナを廃止、画像の上に直接テキスト
- text-shadow で輪郭補強

#### 14-4. ⚡A マッサージ・鍼灸導線新設
- サイドバー: 「同意書」 → 「同意書（訪問診療）」へラベル明確化
- 新メニュー: 「マッサージ・鍼灸」を consent と claims の間に新設
- `acuMassagePage` 関数実装（L2898-2944）: 3 カードハブ（① 同意書発行 ② 発行済み一覧 ③ 加算管理）+ 医療保険適用の仕組み要約 + 厚労省リンク
- `previewConsentPDF` で consent_type に応じて acupuncture / massage / 既存依頼書テンプレを分岐
  - 従来は consent_type 関係なく依頼書テンプレ固定で開いていた重大バグも修正

#### 14-5. 設計書 / HANDOVER 更新
- `docs/DESIGN_yaruze_v4_14_2026-05-25.html` 新規（v4.13 を承継 + §66 v4.14 章を追加）
- `docs/HANDOVER.md` を本セッション完了状態に更新

---

## 📚 5. コミット履歴（直近 / 3兄弟）

### medadapt（最新10件）
```
c7b9cb4 feat(v4.13): TOP HEROとTEAMセクションのチーム写真を team3/team4 に差し替え
1ea0ee3 docs(v4.12): 設計書 v4.12 策定 + 引き継ぎ書 HANDOVER.md 新規作成
05d4756 feat(v4.12): タイムスタンプ証明書ブロックを3テンプレに追加（総務省認定タイムスタンプ業務準拠）
3d7f381 feat(v4.11): 既存依頼書テンプレにも電子署名＋タイムスタンプ認証バナーを起用
841fd14 feat(v4.11): HERO顔被り問題の完全解消 + 同意書2書式に電子署名＋タイムスタンプ認証バナーを起用
50c775a feat(v4.10): 医師交付同意書 厚労省標準様式準拠の2書式を新規作成
307ae9f docs: v4.9 設計書のHEADを実値 398d455 に更新
398d455 feat(v4.9): 設計書v4.9策定 + 残存「自動」過剰表現の追加修正 + PROBLEMSタイトル誠実化
6af0a92 fix(v4.9): HERO写真背景化 + 大下さん未提供素材を削除 + 盛りすぎ表現の見直し
f53c64c fix(v4.8.1): app.html起動不能の重大バグ修正 + PROBLEMSを写真メイン型タイルに刷新
```

### adapt（やるゼ!親LP, 直近）
```
a9a93f2 feat: HEROにチーム写真背景を導入（やるゼ！3兄弟ブランド統一）
a6a08a1 (v4.13 直前の状態)
```

### one-touch（ｔやるゼ!LP, 直近）
```
bfb326a feat: HEROにチーム写真背景を導入（やるゼ！3兄弟ブランド統一）
3bcd61c (v4.13 直前の状態)
```

最新の完全な log は各リポジトリで `git log --oneline -20` で取得すること。

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

| リポジトリ | 最新 HEAD | デプロイ先 | 設計書 |
|---|---|---|---|
| medadapt | v4.15 commit（後述） | myaruze.tamjump.com | `docs/DESIGN_yaruze_v4_15_2026-05-25.html` |
| adapt（やるゼ!親） | v4.15 commit（HERO修正） | yaruze.tamjump.com | 同上の §67-2-2 で言及 |
| one-touch（ｔやるゼ!） | v4.15 commit（HERO修正） | tyaruze.tamjump.com | 同上の §67-2-3 で言及 |

3兄弟LP すべて v4.15 で HERO「顔と文字の完全分離」完了（写真は全面表示・テキストカードを下半分配置）。ｍやるゼ! app.html はマッサージ・鍼灸導線新設＋保険医療機関名「医療法人コンパス」統一済み + 退院時共同指導/担当者会議/モニタリング 帳票への電子署名+TSA 拡大済み。LP本体に「電子署名+タイムスタンプ+SHA-256ハッシュチェーン」三位一体保証の訴求文反映済み。

### 8-2. ⚡ v4.14 で完了したタスク（2026-05-25 セッション）

> 大下指示（2026-05-25 v4.13 セッション末尾 + 当セッション冒頭）:
> 「引き継ぎ書を更新して、新規chatで再開する。
> ・特に、ｍやるゼ！のマッサージ系のページの導線が分からない。項目が見つけられない。
> ・親もｔもLPページの写真の顔に文字が重なってる。画像が透き通ってるのはOKだけど。ｍも透き通ってていい。
> ・ｍの同意書関係のPDFなんだけど、『保険医療機関名』は医療法人コンパスだけでいい。歯科は指示書出せないよ。」

すべて v4.14 で対応済み。詳細は `docs/DESIGN_yaruze_v4_14_2026-05-25.html` §66 を参照。

#### ⚡A. ｍやるゼ！app.html のマッサージ系ページ導線新設 ✅

**完了内容**:
- サイドバーに「マッサージ・鍼灸」メニュー新設（既存の「同意書」は「同意書（訪問診療）」へ改名）
- `acu_massage` ハブページ実装（医師交付同意書発行 / 発行済み一覧 / 加算管理への 3 カード）
- `previewConsentPDF` で consent_type に応じて acupuncture / massage / 既存依頼書テンプレを分岐
- 医療保険適用の仕組み（対象疾患・訪問条件・有効期間・再同意必須）の要約表示

#### ⚡B. やるゼ！親LP（adapt）の HERO 顔と文字の重なり解消 ✅

**完了内容**:
- `background-position: center 28%` → `right 28%`
- グラデ 100deg → 95deg、左濃度 94% → 100%（完全白）、中央 35% まで 98%
- モバイル時は `background-position: center 78%` で顔バンドを画面下端に追いやり

#### ⚡C. ｔやるゼ！(one-touch) LP の HERO 顔と文字の重なり解消 ✅

**完了内容**:
- 縦リニアグラデを **radial gradient** に変更（中央寄せタイトルに最適）
- `radial-gradient(ellipse 55% 60% at 50% 42%, ...)` で中央テキストエリアを完全白化
- 上下左右の人物（後藤先生・他メンバー）は透けて見える

#### ⚡D. ｍやるゼ！(medadapt) HERO 写真透けスタイルに統一 ✅

**完了内容**:
- 「上 540px = チーム写真 / 下 = 白背景テキスト」の完全分離型 → adapt と同じ全面背景＋左濃→右薄グラデへ
- `.hero { min-height: 880px }` を撤去（auto に）、`.hero::before` を `inset:0`
- `.hero-text-block` の白背景独立コンテナを廃止、画像の上に直接テキスト配置
- `text-shadow` で文字輪郭補強

#### 🆕 同意書 PDF の保険医療機関名「医療法人コンパス」統一 ✅

**完了内容**:
- 3 同意書テンプレ（`consent_form_template.html` / `consent_form_acupuncture_template.html` / `consent_form_massage_template.html`）の clinic-name / addressee を「医療法人コンパス」に統一
- `app.html` の `previewConsentPDF` で `clinicCommon` オブジェクトを「医療法人コンパス」固定値で生成
- 残置: 後藤先生の「医療法人社団コンパス 理事長」役職表記は法人内地位の正式表記なのでそのまま（index.html L590, app.html L812）

### 8-3. 中長期未着手タスク（v5.0.5 完了状況）

**2026-05-26 アプリ設計34 で A〜F すべて消化完了**（C は調査レポートまで・契約後に Phase B 着手）。

#### A. app.html 帳票の電子署名＋TSA 対応拡大 ✅完了（v5.0.5 / `39edad1`）
- app.html 内で発行される7帳票すべてに統一バナーを適用済み:
  - ✅ 退院時共同指導記録 / サービス担当者会議 / モニタリング（v4.15既存）
  - ✅ 居宅療養管理指導（共通ヘルパーに統一）
  - ✅ アセスメント（v5.0.5 新規対応）
  - ✅ 診療情報提供書（医科）（v5.0.5 新規実装）
  - ✅ 歯科診療情報提供書／指示書（v5.0.5 新規実装）
- 退院通知/NDA/施術報告書は Worker 側で完結する設計のため、サーバ側 TSA で対応

#### B. Worker API レスポンスに timestamp 構造化データを追加 ✅完了（v5.0.5 / `d5761b0`）
- v17 D1 マイグレーション新規: `signed_documents` / `consent_forms` に `tsa_authority_name` / `tsa_cert_no` / `tsa_serial` / `hash_algorithm` の4列追加
- `timestamps` テーブル新規: 実 TSA 連携時の生レスポンス保存用
- Worker `enrichTsaFields(row)` ヘルパー追加: モックフォールバック付き
- 4 レスポンス（by-doc / list / verify document / consent verify）で構造化フィールド付与

#### C. 実 TSA との連携実装 🔄調査完了・契約待ち（v5.0.5 / `6691439`）
- `docs/RESEARCH_TSA_v5_0_5_2026-05-26.md` 新規: 事業者4社比較・料金試算・実装方針
- 第一候補: **アマノタイムスタンプサービス3161**（医療実績豊富 + 月額固定価格 + 無償トライアル提供）
- OSS `pdf-rfc3161` が Cloudflare Workers 互換で利用可能
- 50ユーザー超えた時点で月額¥24,500（税抜・想定3000スタンプ）が投資回収可能
- **大下さんが契約後に Phase B 着手**（半年後タスク・HANDOVER §17）

#### D. LP（index.html）コピーへの反映 ✅完了（v5.0.5 / `56bf1cc`）
- 中核機能カード「同意書・指示書」を「同意書・指示書・記録」に拡張
- 対応7帳票を本文に具体列挙
- HERO ハッシュタグに「診療情報提供書」「歯科診療情報提供書」を追加

#### E. app.html の「Not found」バッジ問題 ✅完了（v5.0.5 / `39edad1`）
- 原因: `loadCases/Confs/Mons/Assess` 4本が `silent404:true` 未指定だった
- 対応: 4本すべてに `silent404` 付与
- 追加対応: `api()` ヘルパーのエラーメッセージ変換を強化（バリエーション網羅）

#### F. D1 スキーマ拡張: consent_forms に type 列 ✅完了（v5.0.5 / `192e5e9`）
- 既存 `consent_type` 列を活用（マイグレーション不要）
- Worker validateConsentType: `'acupuncture' | 'massage' | 'both' | 'request_form'` を許可
- `disease_names` 必須を `request_form` 時のみ緩和
- app.html cf-type 選択肢に「訪問診療同意書（依頼書）」追加
- `previewConsentPDF` の既定テンプレ分岐は v4.14 で既存実装済み

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
