package store

import (
	"testing"
	"time"

	"sbom_manage/internal/model"
)

func newTestStore(t *testing.T) *FileStore {
	t.Helper()
	s, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	return s
}

// --- スキャン履歴 ---

func TestSaveScan_And_ListScans(t *testing.T) {
	s := newTestStore(t)

	record := ScanRecord{
		ID:        "test-001",
		ScannedAt: time.Now(),
		Source:    "testdata/testfailed.json",
		Vulns: []model.Vulnerability{
			{Name: "CVE-2021-44228", Target: "log4j-core", Score: 10.0, Severity: "CRITICAL"},
		},
	}

	if err := s.SaveScan(record); err != nil {
		t.Fatalf("SaveScan: %v", err)
	}

	records, err := s.ListScans()
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("ListScans count = %d, want 1", len(records))
	}
	if records[0].ID != "test-001" {
		t.Errorf("ID = %q, want %q", records[0].ID, "test-001")
	}
	if len(records[0].Vulns) != 1 {
		t.Errorf("Vulns count = %d, want 1", len(records[0].Vulns))
	}
}

func TestListScans_MultipleRecords(t *testing.T) {
	s := newTestStore(t)

	for i, id := range []string{"scan-1", "scan-2", "scan-3"} {
		err := s.SaveScan(ScanRecord{
			ID:     id,
			Source: "sbom.json",
			Vulns:  []model.Vulnerability{{Name: "CVE-000" + string(rune('0'+i))}},
		})
		if err != nil {
			t.Fatalf("SaveScan %s: %v", id, err)
		}
	}

	records, err := s.ListScans()
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if len(records) != 3 {
		t.Errorf("count = %d, want 3", len(records))
	}
}

func TestGetScan(t *testing.T) {
	s := newTestStore(t)
	s.SaveScan(ScanRecord{ID: "abc", Source: "sbom.json"})

	got, err := s.GetScan("abc")
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if got.ID != "abc" {
		t.Errorf("ID = %q, want %q", got.ID, "abc")
	}
}

func TestGetScan_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.GetScan("nonexistent")
	if err == nil {
		t.Error("expected error for missing scan, got nil")
	}
}

func TestListScans_Empty(t *testing.T) {
	s := newTestStore(t)
	records, err := s.ListScans()
	if err != nil {
		t.Fatalf("ListScans on empty store: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("count = %d, want 0", len(records))
	}
}

// --- 対応状況 ---

func TestSetStatus_And_GetStatus(t *testing.T) {
	s := newTestStore(t)

	if err := s.SetStatus("CVE-2021-44228", StatusOpen, "初回検出"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}

	got, err := s.GetStatus("CVE-2021-44228")
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	if got == nil {
		t.Fatal("GetStatus returned nil")
	}
	if got.Status != StatusOpen {
		t.Errorf("Status = %q, want %q", got.Status, StatusOpen)
	}
	if got.Note != "初回検出" {
		t.Errorf("Note = %q, want %q", got.Note, "初回検出")
	}
}

func TestSetStatus_Update(t *testing.T) {
	s := newTestStore(t)

	s.SetStatus("CVE-2021-44228", StatusOpen, "")
	s.SetStatus("CVE-2021-44228", StatusInProgress, "担当者アサイン済み")
	s.SetStatus("CVE-2021-44228", StatusDone, "パッチ適用完了")

	got, err := s.GetStatus("CVE-2021-44228")
	if err != nil {
		t.Fatalf("GetStatus: %v", err)
	}
	// 最新のステータスが返る
	if got.Status != StatusDone {
		t.Errorf("Status = %q, want %q", got.Status, StatusDone)
	}
}

func TestGetStatus_NotRegistered(t *testing.T) {
	s := newTestStore(t)
	got, err := s.GetStatus("CVE-9999-99999")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 未登録はnilを返す
	if got != nil {
		t.Errorf("expected nil for unregistered CVE, got %+v", got)
	}
}

func TestListStatuses(t *testing.T) {
	s := newTestStore(t)

	s.SetStatus("CVE-2021-44228", StatusOpen, "")
	s.SetStatus("CVE-2022-22965", StatusInProgress, "")
	s.SetStatus("CVE-2021-44228", StatusDone, "完了") // 同一CVEを更新

	statuses, err := s.ListStatuses()
	if err != nil {
		t.Fatalf("ListStatuses: %v", err)
	}
	// CVE-2021-44228は1件に集約
	if len(statuses) != 2 {
		t.Errorf("count = %d, want 2", len(statuses))
	}
}
