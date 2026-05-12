package data

import (
	"encoding/json"
	"fmt"
	"os"
	"path"

	"github.com/pkg/errors"
)

type FileIOConfig struct {
	Path         string `json:"path"`
	VariableName string `json:"variableName"`
}

const (
	AllowedDirectoryGBPDatasetsMount      = "/mnt/data"
	AllowedDirectoryGBPNetAppVolumesMount = "/mnt/netapp-volumes"
	AllowedDirectoryLegacyDatasetsMount   = "/domino"
)

var allowedDirectories = []string{
	AllowedDirectoryGBPDatasetsMount,
	AllowedDirectoryGBPNetAppVolumesMount,
	AllowedDirectoryLegacyDatasetsMount,
}

func loadFileIOConfigsFromPath(path string) ([]FileIOConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file config file %q: %w", path, err)
	}
	var configsList []FileIOConfig
	if err := json.Unmarshal(raw, &configsList); err != nil {
		return nil, fmt.Errorf("failed to unmarshal file config: %w", err)
	}
	return configsList, nil
}

// Loads the file upload/download configs from a file and prepares them for flytecopilot
// to use during the upload/download phase.
// This involves:
//  1. Unmarhsalling the configs from the config file path
//  2. Validating each path starts with an allowed prefix
//  3. Relativizing each path with the config directory
func LoadFileIOConfigs(fileIOConfigFilePath string, fileIOConfigDir string) (map[string]FileIOConfig, error) {
	configsList, err := loadFileIOConfigsFromPath(fileIOConfigFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load file config file %q: %w", fileIOConfigFilePath, err)
	}
	configs := make(map[string]FileIOConfig)
	for _, config := range configsList {
		if err := ValidatePath(config.Path, allowedDirectories); err != nil {
			return configs, errors.Wrapf(err, "invalid path: %s", config.Path)
		}
		config.Path = path.Join(fileIOConfigDir, config.Path)
		configs[config.VariableName] = config
	}
	return configs, nil
}
