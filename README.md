# sbom_manage

**An actionable SBOM management tool** focusing on Responsibility Attribution and decision-making support for security operations.

対応が必要な脆弱性を特定し、組織内の適切な担当者へ自動的に振り分けるSBOM管理CLIツールです。

---

## 主な機能

| 機能 | 詳細 |
|------|------|
| **CycloneDX v1.6 対応** | Syft / Trivy で生成されたJSONを解析 |
| **リアルタイム脆弱性診断** | Google OSV API へ直接照会 |
| **Fixed Version Mapping** | 修正済みバージョンを自動抽出 |
| **Responsible Attribution** | エコシステムとスコアから担当部署を自動判定 |
| **スキャン履歴管理** | 過去のスキャン結果をローカルに蓄積・参照 |
| **対応状況トラッキング** | 脆弱性ごとに open / in-progress / done を管理 |
| **設定ファイル対応** | `config.yaml` で担当部署をコードを触らずに変更可能 |

---

## データ構造 (Core Logic)

```go
type Vulnerability struct {
    Purl           string  // Package URL        パッケージの一意な識別子
    Target         string  // 名前               ソフトウェア/ライブラリ名
    CurrentVersion string  // 現在のVer.         現状の把握
    FixedVersion   string  // 修正済みVer.       修正の目標地点
    Name           string  // CVE-ID             脆弱性識別番号
    Score          float64 // CVSS数値           優先順位の定量的判断
    Severity       string  // 深刻度ラベル       CRITICAL / HIGH / MEDIUM / LOW
    HasPatch       bool    // パッチの有無       即座に対策可能かの判断
    Responsible    string  // 対応責任者         誰が動くべきかの明確化
}
```

---

## ディレクトリ構成

```
sbom_manage/
├── main.go
├── go.mod
├── go.sum
├── config.yaml             # トリアージ設定（担当部署・セキュリティキーワード）
├── testdata/
│   ├── testfailed.json
│   └── cyclonedx_test.json
└── internal/
    ├── compare/
    │   ├── version.go          # semver比較ロジック
    │   └── version_test.go
    ├── config/
    │   ├── config.go           # config.yaml読み込み
    │   └── config_test.go
    ├── model/
    │   └── sbom.go             # コアデータ構造体
    ├── parser/
    │   ├── parser.go           # CycloneDX JSONパーサー
    │   └── parser_test.go
    ├── scanner/
    │   ├── osv.go              # OSV API クライアント
    │   ├── triage.go           # トリアージエンジン
    │   └── triage_test.go
    └── store/
        ├── store.go            # ストアインターフェース・型定義
        ├── filestore.go        # JSONLファイルベース実装（依存ゼロ）
        └── store_test.go
```

---

## 使い方

### 必要環境

- Go 1.22 以上

### インストール

```bash
git clone https://github.com/swd-15/sbom_manage.git
cd sbom_manage
go build -o sbom_manage .
```

### コマンド一覧

```
scan <sbom.json>                          SBOMをスキャンして結果をDBに保存
history                                   過去のスキャン履歴を表示
status                                    全脆弱性の対応状況を表示
status <CVE-ID> <open|in-progress|done>   対応状況を更新
status <CVE-ID> <status> <note>           メモ付きで更新
```

### オプション

```
-config <path>    設定ファイルのパスを指定（デフォルト: ./config.yaml）
-format <format>  出力フォーマット: text / json（デフォルト: text）
-output <path>    JSON出力先ファイルパス（例: -output result.json）
-data <path>      データ保存先ディレクトリ（デフォルト: ~/.sbom_manage）
```

### 実行例

```bash
# スキャン
./sbom_manage scan testdata/testfailed.json

# JSON形式で出力
./sbom_manage -format json -output result.json scan sbom.json

# 設定ファイルを指定してスキャン
./sbom_manage -config /etc/sbom_manage/config.yaml scan sbom.json

# データ保存先を指定してスキャン
./sbom_manage -data /var/sbom_manage scan sbom.json

# 履歴確認
./sbom_manage history

# 対応状況を更新
./sbom_manage status CVE-2021-44228 in-progress "担当者アサイン済み"
./sbom_manage status CVE-2021-44228 done "4.17.21にアップデート完了"

# 全件の対応状況を確認
./sbom_manage status
```

### SBOMの生成方法

```bash
# Syft を使う場合
syft <image or dir> -o cyclonedx-json > sbom.json

# Trivy を使う場合
trivy image --format cyclonedx <image> > sbom.json
```

### テスト

```bash
go test ./...
```

### データの保存先

スキャン履歴と対応状況は `~/.sbom_manage/` に保存されます。

```
~/.sbom_manage/
├── scans.jsonl      # スキャン履歴
└── statuses.jsonl   # 対応状況
```

---

## 設定ファイル (config.yaml)

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

## ライセンス

[MIT License](./LICENSE)
