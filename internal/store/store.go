// Package store はスキャン履歴と脆弱性の対応状況をローカルに永続化します。
// デフォルト実装はJSONLファイルベースで、外部依存ゼロで動作します。
package store

import (
	"sbom_manage/internal/model"
	"time"
)

// ScanStatus は脆弱性の対応状況を表記
type ScanStatus string

const (
	StatusOpen       ScanStatus = "open"        // 未対応
	StatusInProgress ScanStatus = "in-progress" // 対応中
	StatusDone       ScanStatus = "done"        // 完了
)

// ScanRecord は1回のスキャン結果を表記
type ScanRecord struct {
	ID        string    `json:"id"`         // スキャンID (タイムスタンプベース)
	ScannedAt time.Time `json:"scanned_at"` // スキャン日時
	Source    string    `json:"source"`     // SBOMファイルパス
	Vulns     []model.Vulnerability `json:"vulns"` // 検出された脆弱性
}

// VulnStatus は脆弱性ごとの対応状況を表記
type VulnStatus struct {
	CveID       string     `json:"cve_id"`
	Status      ScanStatus `json:"status"`
	Responsible string     `json:"responsible"`
	UpdatedAt   time.Time  `json:"updated_at"`
	Note        string     `json:"note"` // 任意のメモ
}

// Store はストレージのインターフェース
type Store interface {
	// スキャン履歴
	SaveScan(record ScanRecord) error
	ListScans() ([]ScanRecord, error)
	GetScan(id string) (*ScanRecord, error)

	// 対応状況
	SetStatus(cveID string, status ScanStatus, note string) error
	GetStatus(cveID string) (*VulnStatus, error)
	ListStatuses() ([]VulnStatus, error)
}
