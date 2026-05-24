# assets/img/ — 画像素材ディレクトリ

設計書 v4.3（DESIGN_yaruze_v4_3_2026-05-24.html）§48 / §49 に基づく画像保管場所。

## 1. 医監修パートナー写真（§48-4）

| ファイル名 | 内容 | 取得方法 |
|---|---|---|
| `dr_goto_motoharu.jpg` | 後藤基温先生 顔写真（240×240px 正方形・医師白衣 or スクラブ） | 大下から後藤先生に直接依頼・掲載許諾書面を取得 |

**重要**：本人の AI 生成は禁止（§49-1 禁止事項）。実写のみ。

掲載許諾の書面化に必要な項目：
- 掲載媒体：ｍやるゼ！アプリ・LP
- 利用期間：契約継続中
- 利用範囲：index.html / app.html / 同意書 PDF フッタ / 「サービスについて」ページ

写真未取得時は `index.html` の `<img>` タグの `onerror` ハンドラで医師アイコン SVG プレースホルダーが表示される（既に実装済）。

## 2. ChatGPT 生成画像（§49）

設計書 §49-2〜§49-5 のプロンプトで生成した画像はこのディレクトリ配下 `generated/` に保管。

```
assets/img/
├── dr_goto_motoharu.jpg          # 後藤先生写真（実写）
└── generated/                     # ChatGPT 生成画像
    ├── hero_visit_v1.png          # LP ヒーロー候補A（訪問診療）1920×1080
    ├── hero_team_v1.png           # LP ヒーロー候補B（医療チーム連携）1920×1080
    ├── card_discharge_v1.png      # 退院通知カード 1080×1080
    ├── card_nda_v1.png            # NDA カード 1080×1080
    ├── card_consent_v1.png        # 同意書カード 1080×1080
    ├── card_massage_v1.png        # 訪問鍼灸マッサージカード 1080×1080
    ├── icon_discharge_v1.png      # 退院通知アイコン 512×512
    ├── icon_nda_v1.png            # NDA アイコン
    ├── icon_match_v1.png          # マッチングアイコン
    ├── icon_consent_v1.png        # 同意書アイコン
    ├── icon_blockchain_v1.png     # 改ざん防止アイコン
    ├── icon_qr_v1.png             # QR 検証アイコン
    └── ogp_v1.png                 # SNS / OGP 1200×630
```

## 3. 命名規則（§49-6）

```
{用途}_{シーン}_{バリエーション}.png
```

例：
- `hero_visit_v1.png`（LP ヒーロー・訪問診療シーン・バリエーション 1）
- `card_consent_v2.png`（カード・同意書・バリエーション 2）

## 4. 生成手順（§49-7）

1. ChatGPT Plus / GPT-Image 機能を起動
2. 設計書 §49-2〜§49-5 のプロンプトを選択（日本語版 or 英語版）
3. プロンプトを貼り付けて生成実行
4. 気に入った画像を本ディレクトリ（generated/）にダウンロード保存
5. 気に入らなければ修飾語を追加して再生成
6. 承認後、Cloudflare R2 へのアップロードも検討（CDN 配信用）

## 5. 商用利用権利

- ChatGPT / DALL-E 利用規約上、生成画像は商用利用可
- 各生成時に念のため OpenAI 規約の最新版を確認
- 既存有名人・特定ブランド・後藤先生本人を模した顔は生成禁止（§49-1）
