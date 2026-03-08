# MedBridge

**医療介護連携OS**

退院調整・サ担会議・モニタリング。日程調整・アセスメント・通話・記録・同意・監査ログを、1つの接続で完結させる。

## ファイル構成

```
medbridge/
├── index.html   ← LP（サービスサイト）
├── app.html     ← アプリ本体
├── .gitignore
└── README.md
```

## テストアカウント

| プラン | メール | PW |
|--------|--------|-----|
| Free | free@test.com | test1234 |
| Pro | pro@test.com | test1234 |

## 決済リンク設定

`app.html` 冒頭の変数を差し替え：

```javascript
const PAYMENT_URL = '#PAYMENT_LINK_HERE'; // ← Stripe等のリンク
```

## デプロイ

```bash
git init && git add . && git commit -m "init"
git branch -M main
git remote add origin https://github.com/<YOUR_ID>/medbridge.git
git push -u origin main
```

Settings → Pages → Branch: `main` / `/(root)` → Save

## ライセンス

© 2025 MedBridge All rights reserved.
