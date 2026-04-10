package data

import (
	"os"
	"path"
	"testing"

	"github.com/flyteorg/flyte/flyteidl/gen/pb-go/flyteidl/core"
	"github.com/stretchr/testify/assert"
)

func TestLoadFileIOConfigs(t *testing.T) {
	tmpFolderLocation := ""
	tmpPrefix := "fileconfig_test"
	tmpExecutionVolPrefix := "fileconfig_test_execution_vol"

	tmpDir, err := os.MkdirTemp(tmpFolderLocation, tmpPrefix)
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, os.RemoveAll(tmpDir))
	}()

	tmpExecutionVolDir, err := os.MkdirTemp(tmpFolderLocation, tmpExecutionVolPrefix)
	assert.NoError(t, err)
	defer func() {
		assert.NoError(t, os.RemoveAll(tmpExecutionVolDir))
	}()

	fileIOConfigFilePath := path.Join(tmpDir, "file-config.json")
	fileIOConfigDir := tmpExecutionVolDir

	data := []byte(`[
		{
			"path": "data.sas7bdat",
			"variableName": "data"
		},
		{
			"path": "report.pdf",
			"variableName": "report"
		}
	]`)
	assert.NoError(t, os.WriteFile(fileIOConfigFilePath, data, os.ModePerm)) // #nosec G306

	expectedDataPath := path.Join(tmpExecutionVolDir, "data.sas7bdat")
	expectedDataVariableName := "data"
	expectedReportPath := path.Join(tmpExecutionVolDir, "report.pdf")
	expectedReportVariableName := "report"

	configs, err := LoadFileIOConfigs(fileIOConfigFilePath, fileIOConfigDir)
	assert.NoError(t, err)
	assert.Len(t, configs, 2)
	assert.Equal(t, expectedDataPath, configs["data"].Path)
	assert.Equal(t, expectedDataVariableName, configs["data"].VariableName)
	assert.Equal(t, expectedReportPath, configs["report"].Path)
	assert.Equal(t, expectedReportVariableName, configs["report"].VariableName)
}

func TestHydrateInputOutputConfigs(t *testing.T) {
	for name, tt := range map[string]struct {
		configs            map[string]FileIOConfig
		vars               *core.VariableMap
		localDirectoryPath string
		expectedConfigs    map[string]FileIOConfig
	}{
		"simple config with multiple variables": {
			configs: map[string]FileIOConfig{
				"data": {
					Path:         "/execution-vol/data/quick-start/data.sas7bdat",
					VariableName: "data",
				},
			},
			vars: &core.VariableMap{
				Variables: map[string]*core.Variable{
					"report": {
						Type: &core.LiteralType{
							Type: &core.LiteralType_Simple{
								Simple: core.SimpleType_STRING,
							},
						},
					},
					"summary": {
						Type: &core.LiteralType{
							Type: &core.LiteralType_Simple{
								Simple: core.SimpleType_STRING,
							},
						},
					},
				},
			},
			localDirectoryPath: "/execution-vol/flows/workflow/outputs",
			expectedConfigs: map[string]FileIOConfig{
				"data": {
					Path:         "/execution-vol/data/quick-start/data.sas7bdat",
					VariableName: "data",
				},
				"report": {
					Path:         "/execution-vol/flows/workflow/outputs/report",
					VariableName: "report",
				},
				"summary": {
					Path:         "/execution-vol/flows/workflow/outputs/summary",
					VariableName: "summary",
				},
			},
		},
		"simple config with no variables": {
			configs: map[string]FileIOConfig{
				"data": {
					Path:         "/execution-vol/data/quick-start/data.sas7bdat",
					VariableName: "data",
				},
			},
			vars:               &core.VariableMap{},
			localDirectoryPath: "/execution-vol/flows/workflow/outputs",
			expectedConfigs: map[string]FileIOConfig{
				"data": {
					Path:         "/execution-vol/data/quick-start/data.sas7bdat",
					VariableName: "data",
				},
			},
		},
		"no variables and no configs": {
			configs:            map[string]FileIOConfig{},
			vars:               &core.VariableMap{},
			localDirectoryPath: "/execution-vol/flows/workflow/outputs",
			expectedConfigs:    map[string]FileIOConfig{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			configs := HydrateInputOutputConfigs(tt.configs, tt.vars, tt.localDirectoryPath)
			assert.Equal(t, tt.expectedConfigs, configs)
		})
	}
}
