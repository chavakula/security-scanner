package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	configFileName = ".security-scanner.json"
)

// Config holds all configuration for the scanner.
type Config struct {
	OpenAIKey   string `json:"openai_api_key,omitempty"`
	OpenAIModel string `json:"openai_model,omitempty"`
	NVDKey      string `json:"nvd_api_key,omitempty"`
	GitHubToken string `json:"github_token,omitempty"`
}

// configFilePath returns the path to the config file in the user's home directory.
func configFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, configFileName), nil
}

// Load reads config from the config file and merges with environment variables.
// Environment variables take precedence over file values.
func Load() (*Config, error) {
	cfg := &Config{
		OpenAIModel: "gpt-4",
	}

	// Load from file
	cfgPath, err := configFilePath()
	if err == nil {
		data, err := os.ReadFile(cfgPath)
		if err == nil {
			_ = json.Unmarshal(data, cfg)
		}
	}

	// Environment variables override file config
	if v := os.Getenv("OPENAI_API_KEY"); v != "" {
		cfg.OpenAIKey = v
	}
	if v := os.Getenv("OPENAI_MODEL"); v != "" {
		cfg.OpenAIModel = v
	}
	if v := os.Getenv("NVD_API_KEY"); v != "" {
		cfg.NVDKey = v
	}
	if v := os.Getenv("GITHUB_TOKEN"); v != "" {
		cfg.GitHubToken = v
	}

	return cfg, nil
}

// Save writes the config to the config file.
func Save(cfg *Config) error {
	cfgPath, err := configFilePath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot marshal config: %w", err)
	}

	if err := os.WriteFile(cfgPath, data, 0600); err != nil {
		return fmt.Errorf("cannot write config file: %w", err)
	}

	return nil
}

// Set updates a single config key and saves.
func Set(key, value string) error {
	cfg, err := Load()
	if err != nil {
		return err
	}

	switch key {
	case "openai-key":
		cfg.OpenAIKey = value
	case "openai-model":
		cfg.OpenAIModel = value
	case "nvd-key":
		cfg.NVDKey = value
	case "github-token":
		cfg.GitHubToken = value
	default:
		return fmt.Errorf("unknown config key: %s (valid keys: openai-key, openai-model, nvd-key, github-token)", key)
	}

	return Save(cfg)
}

// Get returns the value of a config key.
func Get(key string) (string, error) {
	cfg, err := Load()
	if err != nil {
		return "", err
	}

	switch key {
	case "openai-key":
		return maskSecret(cfg.OpenAIKey), nil
	case "openai-model":
		return cfg.OpenAIModel, nil
	case "nvd-key":
		return maskSecret(cfg.NVDKey), nil
	case "github-token":
		return maskSecret(cfg.GitHubToken), nil
	default:
		return "", fmt.Errorf("unknown config key: %s", key)
	}
}

// maskSecret masks all but the last 4 characters of a secret.
func maskSecret(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return "****" + s[len(s)-4:]
}
