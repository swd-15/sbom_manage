package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// OSV APIのリクエスト構造
type osvRequest struct {
	Purl string `json:"purl"`
}

// OSV APIのレスポンス構造（必要なフィールドを抽出）
type osvResponse struct {
	Vulns []struct {
		ID      string `json:"id"`      // CVE-ID
		Summary string `json:"summary"` // 脆弱性の概要
		Severity []struct {
			Type  string `json:"type"`  // CVSS_V3 
			Score string `json:"score"` // スコア数値
		} `json:"severity"`
		Affected []struct {
			Ranges []struct {
				Type   string `json:"type"`
				Events []map[string]string `json:"events"` // "fixed": "1.2.3" が入る
			} `json:"ranges"`
		} `json:"affected"`
	} `json:"vulns"`
}

func FetchVulnerabilityData(purl string) (fixed string, score float64, cveID string, err error) {
	// APIリクエストの作成
	reqBody, _ := json.Marshal(osvRequest{Purl: purl})

	// タイムアウト設定付きのクライアント
	client := &http.Client{Timeout: 10 * time.Second}

	resp, err := client.Post("https://api.osv.dev/v1/query", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return "", 0, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, "", fmt.Errorf("API error: %s", resp.Status)
	}

	var or osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&or); err != nil {
		return "", 0, "", err
	}

	// 脆弱性が見つからなかった場合
	if len(or.Vulns) == 0 {
		return "", 0, "", nil
	}


	v := or.Vulns[0]
	cveID = v.ID

	// スコアの解析
	for _, sev := range v.Severity {
		if sev.Type == "CVSS_V3" {
			fmt.Sscanf(sev.Score, "%f", &score)
		}
	}

	// 修正バージョンの解析
	for _, aff := range v.Affected {
		for _, r := range aff.Ranges {
			for _, event := range r.Events {
				if f, ok := event["fixed"]; ok {
					fixed = f
					break
				}
			}
		}
	}

	return fixed, score, cveID, nil
}

func FetchFixedVersion(purl string) (string, error) {
	fixed, _, _, err := FetchVulnerabilityData(purl)
	return fixed, err
}
