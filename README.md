---

## ⚙️ 設定ファイル (config.yaml)

担当部署やセキュリティキーワードを組織に合わせてカスタマイズできます。

```yaml
ecosystem_owners:
  golang: "Development Team"
  npm:    "Development Team"
  pypi:   "Development Team"
  maven:  "Development Team"
  cargo:  "Development Team"
  deb:    "Infrastructure Team"
  rpm:    "Infrastructure Team"
  apk:    "Infrastructure Team"

security_keywords:
  - openssl
  - libssl
  - crypto
  - jwt
  - auth
  - tls
  - ssl
```

`config.yaml` が見つからない場合は上記のデフォルト値で動作します。

---

## トリアージロジック

責任部署は以下の優先順位で判定されます。

| 優先順位 | 条件 | 担当 |
|---------|------|------|
| 1 | `security_keywords` に一致するパッケージ名 | `Security CSIRT (High Priority)` |
| 2 | Score ≥ 7.0 または HIGH / CRITICAL | `Security CSIRT (High Priority)` |
| 3 | `ecosystem_owners` に一致するエコシステム | 設定値に従う |
| 4 | 上記以外 | `Security CSIRT (Triage Required)` |

### Severity の決定ルール

OSV API から取得したラベルを優先し、取得できなかった場合のみ CVSSスコアから補完します。

| CVSSスコア | Severity |
|-----------|----------|
| 9.0 以上 | CRITICAL |
| 7.0 – 8.9 | HIGH |
| 4.0 – 6.9 | MEDIUM |
| 0 より大 | LOW |

---

## 📜 ライセンス

[MIT License](./LICENSE)
