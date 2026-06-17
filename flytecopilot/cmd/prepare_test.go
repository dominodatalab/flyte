package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/flyteorg/flyte/flytecopilot/data"
)

func TestPrepareOptions_Prepare(t *testing.T) {
	t.Run("GitBased creates GBP directories", func(t *testing.T) {
		volumePath, err := os.MkdirTemp("", "prepare_opts_gbp")
		assert.NoError(t, err)
		defer func() {
			assert.NoError(t, os.RemoveAll(volumePath))
		}()

		t.Setenv("DOMINO_IS_GIT_BASED", "true")

		opts := &PrepareOptions{
			RootOptions:         &RootOptions{},
			executionVolumePath: volumePath,
		}
		assert.NoError(t, opts.Prepare(context.Background()))

		for _, dir := range data.AllowedDirectoriesGBP {
			info, statErr := os.Stat(filepath.Join(volumePath, dir))
			assert.NoError(t, statErr, "expected directory %s to exist", dir)
			assert.True(t, info.IsDir())
		}

		// Legacy-only directories should not be created in git-based mode
		legacyOnly := filepath.Join(volumePath, data.AllowedDirectoryLegacyDatasetsMount)
		_, statErr := os.Stat(legacyOnly)
		assert.True(t, os.IsNotExist(statErr), "expected legacy directory %s to not exist", legacyOnly)
	})

	t.Run("Legacy creates legacy directories", func(t *testing.T) {
		volumePath, err := os.MkdirTemp("", "prepare_opts_legacy")
		assert.NoError(t, err)
		defer func() {
			assert.NoError(t, os.RemoveAll(volumePath))
		}()

		t.Setenv("DOMINO_IS_GIT_BASED", "false")

		opts := &PrepareOptions{
			RootOptions:         &RootOptions{},
			executionVolumePath: volumePath,
		}
		assert.NoError(t, opts.Prepare(context.Background()))

		for _, dir := range data.AllowedDirectoriesLegacy {
			info, statErr := os.Stat(filepath.Join(volumePath, dir))
			assert.NoError(t, statErr, "expected directory %s to exist", dir)
			assert.True(t, info.IsDir())
		}

		// GBP-only directories should not be created in legacy mode
		gbpOnly := filepath.Join(volumePath, data.AllowedDirectoryGBPDatasetsMount)
		_, statErr := os.Stat(gbpOnly)
		assert.True(t, os.IsNotExist(statErr), "expected GBP directory %s to not exist", gbpOnly)
	})

	t.Run("Defaults to legacy when env var is unset or invalid", func(t *testing.T) {
		volumePath, err := os.MkdirTemp("", "prepare_opts_default")
		assert.NoError(t, err)
		defer func() {
			assert.NoError(t, os.RemoveAll(volumePath))
		}()

		// An unparseable value should fall back to the legacy directory layout
		t.Setenv("DOMINO_IS_GIT_BASED", "not-a-bool")

		opts := &PrepareOptions{
			RootOptions:         &RootOptions{},
			executionVolumePath: volumePath,
		}
		assert.NoError(t, opts.Prepare(context.Background()))

		for _, dir := range data.AllowedDirectoriesLegacy {
			info, statErr := os.Stat(filepath.Join(volumePath, dir))
			assert.NoError(t, statErr, "expected directory %s to exist", dir)
			assert.True(t, info.IsDir())
		}

		gbpOnly := filepath.Join(volumePath, data.AllowedDirectoryGBPDatasetsMount)
		_, statErr := os.Stat(gbpOnly)
		assert.True(t, os.IsNotExist(statErr), "expected GBP directory %s to not exist", gbpOnly)
	})
}
