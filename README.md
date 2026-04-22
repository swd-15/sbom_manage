# sbom_manage
An actionable SBOM management tool focusing on "Responsibility Attribution" and decision-making support for security operations.

## 主な機能

- **JSON Parser**: Trivy等が出力したJSON形式のSBOMを高速に解析。
- **Fixed Version Mapping**: 脆弱性を解決するために目指すべき「修正済みバージョン」を自動抽出。
- **Responsible Attribution**: パッケージの特性から、対応すべき責任者（開発/インフラ等）を自動判定。

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

## ロードマップ

- [ ]  GoによるJSONパース処理の実装
- [ ]  バージョン比較ロジックの構築
- [ ]  JPCERT/CCのガイドラインに基づく判定ロジックの統合
- [ ]  ターミナルへの構造化出力の実装

## 📜 ライセンス

[MIT License](https://www.notion.so/LICENSE)
