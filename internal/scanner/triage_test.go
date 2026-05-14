package scanner

import (
	"testing"

	"sbom_manage/internal/model"
)

func TestTriageVulnerability_HasPatch(t *testing.T) {
	tests := []struct {
		name         string
		fixedVersion string
		wantHasPatch bool
	}{
		{"修正バージョンあり", "4.17.21", true},
		{"修正バージョンなし", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &model.Vulnerability{FixedVersion: tt.fixedVersion}
			TriageVulnerability(v)
			if v.HasPatch != tt.wantHasPatch {
				t.Errorf("HasPatch = %v, want %v", v.HasPatch, tt.wantHasPatch)
			}
		})
	}
}

func TestTriageVulnerability_SeverityFromScore(t *testing.T) {
	tests := []struct {
		name         string
		score        float64
		wantSeverity string
	}{
		{"CRITICAL (9.0以上)", 9.5, "CRITICAL"},
		{"CRITICAL (ちょうど9.0)", 9.0, "CRITICAL"},
		{"HIGH (7.0以上)", 7.5, "HIGH"},
		{"HIGH (ちょうど7.0)", 7.0, "HIGH"},
		{"MEDIUM (4.0以上)", 5.5, "MEDIUM"},
		{"MEDIUM (ちょうど4.0)", 4.0, "MEDIUM"},
		{"LOW (0より大きい)", 2.5, "LOW"},
		{"スコアなし(0)", 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &model.Vulnerability{Score: tt.score}
			TriageVulnerability(v)
			if v.Severity != tt.wantSeverity {
				t.Errorf("Score=%.1f: Severity = %q, want %q", tt.score, v.Severity, tt.wantSeverity)
			}
		})
	}
}

func TestTriageVulnerability_PreservesAPISeverity(t *testing.T) {
	tests := []struct {
		name         string
		apiSeverity  string
		score        float64
		wantSeverity string
	}{
		{"API=MODERATE, Score=8.5", "MODERATE", 8.5, "MODERATE"},

		{"API=CRITICAL, Score=6.0", "CRITICAL", 6.0, "CRITICAL"},

		{"API=空, Score=9.5", "", 9.5, "CRITICAL"},
		{"API=空, Score=7.0", "", 7.0, "HIGH"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &model.Vulnerability{
				Severity: tt.apiSeverity,
				Score:    tt.score,
			}
			TriageVulnerability(v)
			if v.Severity != tt.wantSeverity {
				t.Errorf("Severity = %q, want %q", v.Severity, tt.wantSeverity)
			}
		})
	}
}

func TestTriageVulnerability_Responsible(t *testing.T) {
	tests := []struct {
		name            string
		purl            string
		target          string
		score           float64
		severity        string
		wantResponsible string
	}{
		{"CRITICAL→CSIRT", "pkg:npm/lodash@4.17.20", "", 9.5, "CRITICAL", "Security CSIRT (High Priority)"},
		{"HIGH→CSIRT", "pkg:npm/lodash@4.17.20", "", 8.0, "HIGH", "Security CSIRT (High Priority)"},
		{"スコア8.0→CSIRT", "pkg:npm/lodash@4.17.20", "", 8.0, "", "Security CSIRT (High Priority)"},
		{"npm→Development", "pkg:npm/lodash@4.17.20", "", 5.0, "MEDIUM", "Development Team"},
		{"pypi→Development", "pkg:pypi/django@3.2.0", "", 5.0, "MEDIUM", "Development Team"},
		{"golang→Development", "pkg:golang/github.com/foo/bar@1.0.0", "", 5.0, "MEDIUM", "Development Team"},
		{"deb→Infrastructure", "pkg:deb/ubuntu/openssl@1.1.1k", "", 5.0, "MEDIUM", "Infrastructure Team"},
		{"apk→Infrastructure", "pkg:apk/alpine/busybox@1.34.1", "", 5.0, "MEDIUM", "Infrastructure Team"},
		{"不明→Triage Required", "pkg:unknown/foo@1.0.0", "", 5.0, "MEDIUM", "Security CSIRT (Triage Required)"},
		{"PURL空→Triage Required", "", "", 5.0, "MEDIUM", "Security CSIRT (Triage Required)"},
		{"openssl→CSIRT", "pkg:npm/openssl@1.0.0", "openssl", 5.0, "MEDIUM", "Security CSIRT (High Priority)"},
		{"jwt→CSIRT", "pkg:npm/jwt@1.0.0", "jwt", 5.0, "MEDIUM", "Security CSIRT (High Priority)"},
		{"crypto→CSIRT", "pkg:pypi/crypto@1.0.0", "crypto", 5.0, "MEDIUM", "Security CSIRT (High Priority)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &model.Vulnerability{
				Purl:     tt.purl,
				Score:    tt.score,
				Severity: tt.severity,
				Target:   tt.target,
			}
			TriageVulnerability(v)
			if v.Responsible != tt.wantResponsible {
				t.Errorf("Responsible = %q, want %q", v.Responsible, tt.wantResponsible)
			}
		})
	}
}
