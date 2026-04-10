package data

import (
	"encoding/json"
	"fmt"
	"os"
	"path"

	"github.com/flyteorg/flyte/flyteidl/gen/pb-go/flyteidl/core"
)

type FileIOConfig struct {
	Path         string `json:"path"`
	VariableName string `json:"variableName"`
}

func LoadFileIOConfigs(fileIOConfigFilePath string, fileIOConfigDir string) (map[string]FileIOConfig, error) {
	raw, err := os.ReadFile(fileIOConfigFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file config file %q: %w", fileIOConfigFilePath, err)
	}
	var configsList []FileIOConfig
	if err := json.Unmarshal(raw, &configsList); err != nil {
		return nil, fmt.Errorf("failed to unmarshal file config: %w", err)
	}
	configs := make(map[string]FileIOConfig)
	for _, config := range configsList {
		config.Path = path.Join(fileIOConfigDir, config.Path)
		configs[config.VariableName] = config
	}
	return configs, nil
}

// For any input/output variables that are missing a FileIOConfig, add it with
// the explicit default path e.g. /execution-vol/flows/workflow/outputs/datasas7bdat
func HydrateInputOutputConfigs(configs map[string]FileIOConfig, vars *core.VariableMap, localDirectoryPath string) map[string]FileIOConfig {
	for varName := range vars.GetVariables() {
		if _, ok := configs[varName]; !ok {
			filename := varName
			configs[varName] = FileIOConfig{
				Path:         path.Join(localDirectoryPath, filename),
				VariableName: varName,
			}
		}
	}
	return configs
}
