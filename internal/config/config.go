package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	EcosystemOwners  map[string]string `yaml:"ecosystem_owners"`
	SecurityKeywords []string          `yaml:"security_keywords"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// DefaultConfig はconfig.yamlが見つからない場合のフォールバック
func DefaultConfig() *Config {
	return &Config{
		EcosystemOwners: map[string]string{
			"golang": "Development Team",
			"npm":    "Development Team",
			"pypi":   "Development Team",
			"maven":  "Development Team",
			"cargo":  "Development Team",
			"deb":    "Infrastructure Team",
			"rpm":    "Infrastructure Team",
			"apk":    "Infrastructure Team",
		},
		SecurityKeywords: []string{
			"openssl", "libssl", "crypto", "jwt", "auth", "tls", "ssl",
		},
	}
}
