package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

type osvRequest struct {
	Package struct {
		Purl string `json:"purl"`
	} `json:"package"`
}

type osvResponse struct {
	Vulns []struct {
		ID       string `json:"id"`
		Severity []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		DatabaseSpecific map[string]interface{} `json:"database_specific"`
		Affected []struct {
			Ranges []struct {
				Events []map[string]string `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
	} `json:"vulns"`
}

func FetchVulnerabilityData(purl string) (fixed string, score float64, cveID string, severity string, err error) {
	reqData := osvRequest{}
	reqData.Package.Purl = purl
	reqBody, _ := json.Marshal(reqData)

	req, err := http.NewRequest("POST", "https://api.osv.dev/v1/query", bytes.NewBuffer(reqBody))
	if err != nil {
		return "", 0, "", "", err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, "", "", fmt.Errorf("API error: %s", resp.Status)
	}

	var or osvResponse
	json.NewDecoder(resp.Body).Decode(&or)

	if len(or.Vulns) == 0 {
		return "", 0, "", "", nil
	}

	for _, v := range or.Vulns {
		if cveID == "" { cveID = v.ID }

		// 数値スコアの取得
		for _, sev := range v.Severity {
			if sev.Type == "CVSS_V3" || sev.Type == "CVSS_V2" {
				s, _ := strconv.ParseFloat(sev.Score, 64)
				if s > score { score = s }
			}
		}

		// ラベルの取得とスコア補完
		if sLabel, ok := v.DatabaseSpecific["severity"].(string); ok {
			severity = sLabel
			if score == 0 {
				switch sLabel {
				case "CRITICAL": score = 9.5
				case "HIGH":     score = 8.5
				case "MODERATE", "MEDIUM": score = 5.5
				case "LOW":      score = 2.5
				}
			}
		}


		for _, aff := range v.Affected {
			for _, r := range aff.Ranges {
				for _, event := range r.Events {
					if f, ok := event["fixed"]; ok {
						fixed = f
					}
				}
			}
		}
	}
	return fixed, score, cveID, severity, nil
}
