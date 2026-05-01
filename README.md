# sbom_manage
「今すぐ対応が必要な脆弱性」を特定し、組織内の適切な担当者へ自動的に振り分けるsbom管理ツール。

## 主な機能

- **CycloneDX v1.6準拠**: SyftやTrivyで生成された最新のCycloneDXフォーマットを高速に解析。
- **リアルタイム脆弱性診断 (OSV API連携)**: googleが運営する「OSV (Open Source Vulnerabilities) API」に直接照会。
- **インテリジェント・自動トリアージエンジン**: 深刻度をスコアからも動的補完、設定した基準をもとに責任部署を自動判断。

## データ構造 (Core Logic)

本ツールでは、以下の `Vulnerability` 構造体をコアとしてデータを管理しています。

| フィールド | 説明 | 役割 |
| --- | --- | --- |
| **Purl** | Package URL | パッケージの一意な識別子 |
| **Target** | 名前 | ソフトウェア/ライブラリ名 |
| **CurrentVersion** | 現在のVer. | 現状の把握 |
| **FixedVersion** | 修正済みVer. | 修正の目標地点 |
| **Name** | CVE-ID | 脆弱性識別番号 |
| **Score** | CVSS数値 | 優先順位の定量的判断 |
| **Severity** | 深刻度ラベル | 直感的な通知（High/Lowなど） |
| **HasPatch** | パッチの有無 | 即座に対策可能かの判断 |
| **Responsible** | 対応責任者 | 誰が動くべきかの明確化 |


## 🚀 使い方

### ビルド
Go 1.21 以上が必要です。
```bash
go build -o sbom_manage ./cmd/sbom-cli/main.go
```
### 実行
```bash
./sbom_manage testdata/testfailed.json
```
## 📜 ライセンス

[MIT License](https://www.notion.so/LICENSE)
