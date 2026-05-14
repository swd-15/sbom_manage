package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	scansFile    = "scans.jsonl"
	statusesFile = "statuses.jsonl"
)

type FileStore struct {
	mu      sync.Mutex
	dataDir string
}


func NewFileStore(dir string) (*FileStore, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("ストアディレクトリの作成に失敗: %w", err)
	}
	return &FileStore{dataDir: dir}, nil
}

func DefaultStore() (*FileStore, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return NewFileStore(filepath.Join(home, ".sbom_manage"))
}

// --- スキャン履歴 ---

func (s *FileStore) SaveScan(record ScanRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if record.ID == "" {
		record.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	if record.ScannedAt.IsZero() {
		record.ScannedAt = time.Now()
	}

	return s.appendJSONL(scansFile, record)
}

func (s *FileStore) ListScans() ([]ScanRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var records []ScanRecord
	err := s.readJSONL(scansFile, func(data []byte) error {
		var r ScanRecord
		if err := json.Unmarshal(data, &r); err != nil {
			return err
		}
		records = append(records, r)
		return nil
	})
	return records, err
}

func (s *FileStore) GetScan(id string) (*ScanRecord, error) {
	records, err := s.ListScans()
	if err != nil {
		return nil, err
	}
	for i := len(records) - 1; i >= 0; i-- {
		if records[i].ID == id {
			return &records[i], nil
		}
	}
	return nil, fmt.Errorf("スキャンID %q が見つかりません", id)
}

// --- 対応状況 ---

func (s *FileStore) SetStatus(cveID string, status ScanStatus, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 既存のstatusesを読み込んで該当CVEを更新
	var statuses []VulnStatus
	_ = s.readJSONL(statusesFile, func(data []byte) error {
		var vs VulnStatus
		if err := json.Unmarshal(data, &vs); err != nil {
			return err
		}
		// 同じCVE IDは上書きするため古いものは除外
		if vs.CveID != cveID {
			statuses = append(statuses, vs)
		}
		return nil
	})

	statuses = append(statuses, VulnStatus{
		CveID:     cveID,
		Status:    status,
		UpdatedAt: time.Now(),
		Note:      note,
	})

	// 全件を書き直す
	return s.writeJSONL(statusesFile, statuses)
}

func (s *FileStore) GetStatus(cveID string) (*VulnStatus, error) {
	statuses, err := s.ListStatuses()
	if err != nil {
		return nil, err
	}
	for i := len(statuses) - 1; i >= 0; i-- {
		if statuses[i].CveID == cveID {
			return &statuses[i], nil
		}
	}
	return nil, nil // 未登録はnilを返す
}

func (s *FileStore) ListStatuses() ([]VulnStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var statuses []VulnStatus
	err := s.readJSONL(statusesFile, func(data []byte) error {
		var vs VulnStatus
		if err := json.Unmarshal(data, &vs); err != nil {
			return err
		}
		statuses = append(statuses, vs)
		return nil
	})
	return statuses, err
}

// --- 内部ユーティリティ ---

func (s *FileStore) appendJSONL(filename string, v interface{}) error {
	f, err := os.OpenFile(filepath.Join(s.dataDir, filename), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "%s\n", data)
	return err
}

func (s *FileStore) writeJSONL(filename string, records interface{}) error {
	f, err := os.Create(filepath.Join(s.dataDir, filename))
	if err != nil {
		return err
	}
	defer f.Close()

	//json経由でイテレート
	data, err := json.Marshal(records)
	if err != nil {
		return err
	}
	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil {
		return err
	}
	for _, item := range items {
		fmt.Fprintf(f, "%s\n", item)
	}
	return nil
}

func (s *FileStore) readJSONL(filename string, fn func([]byte) error) error {
	path := filepath.Join(s.dataDir, filename)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil // ファイルがない=空のストア
	}
	if err != nil {
		return err
	}

	// 行ごとにパース
	start := 0
	for i, b := range data {
		if b == '\n' {
			line := data[start:i]
			if len(line) > 0 {
				if err := fn(line); err != nil {
					return err
				}
			}
			start = i + 1
		}
	}
	return nil
}
