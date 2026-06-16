package data

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrepareDataDirectories(t *testing.T) {
	t.Run("GitBased creates GBP directories only", func(t *testing.T) {
		volumePath, err := os.MkdirTemp("", "prepare_data_gbp")
		assert.NoError(t, err)
		defer func() {
			assert.NoError(t, os.RemoveAll(volumePath))
		}()

		d := Preparer{executionVolumePath: volumePath, isGitBased: true}
		err = d.PrepareDataDirectories(context.Background())
		assert.NoError(t, err)

		for _, dir := range AllowedDirectoriesGBP {
			info, statErr := os.Stat(filepath.Join(volumePath, dir))
			assert.NoError(t, statErr, "expected directory %s to exist", dir)
			assert.True(t, info.IsDir())
		}

		// Legacy-only directories should not be created in git-based mode
		legacyOnly := filepath.Join(volumePath, AllowedDirectoryLegacyDatasetsMount)
		_, statErr := os.Stat(legacyOnly)
		assert.True(t, os.IsNotExist(statErr), "expected legacy directory %s to not exist", legacyOnly)
	})

	t.Run("Legacy creates legacy directories only", func(t *testing.T) {
		volumePath, err := os.MkdirTemp("", "prepare_data_legacy")
		assert.NoError(t, err)
		defer func() {
			assert.NoError(t, os.RemoveAll(volumePath))
		}()

		d := Preparer{executionVolumePath: volumePath, isGitBased: false}
		err = d.PrepareDataDirectories(context.Background())
		assert.NoError(t, err)

		for _, dir := range AllowedDirectoriesLegacy {
			info, statErr := os.Stat(filepath.Join(volumePath, dir))
			assert.NoError(t, statErr, "expected directory %s to exist", dir)
			assert.True(t, info.IsDir())
		}

		// GBP-only directories should not be created in legacy mode
		gbpOnly := filepath.Join(volumePath, AllowedDirectoryGBPDatasetsMount)
		_, statErr := os.Stat(gbpOnly)
		assert.True(t, os.IsNotExist(statErr), "expected GBP directory %s to not exist", gbpOnly)
	})

	t.Run("Removes pre-existing directories for GBP", func(t *testing.T) {
		volumePath, err := os.MkdirTemp("", "prepare_data_remove")
		assert.NoError(t, err)
		defer func() {
			assert.NoError(t, os.RemoveAll(volumePath))
		}()

		// Seed every allowed directory with a stale file to confirm removal
		for _, dir := range AllowedDirectories {
			fullDir := filepath.Join(volumePath, dir)
			assert.NoError(t, os.MkdirAll(fullDir, os.ModePerm))
			assert.NoError(t, os.WriteFile(filepath.Join(fullDir, "stale.txt"), []byte("stale"), os.ModePerm))
		}

		d := Preparer{executionVolumePath: volumePath, isGitBased: true}
		err = d.PrepareDataDirectories(context.Background())
		assert.NoError(t, err)

		// Stale files must be gone even for directories that get recreated
		for _, dir := range AllowedDirectories {
			staleFile := filepath.Join(volumePath, dir, "stale.txt")
			_, statErr := os.Stat(staleFile)
			assert.True(t, os.IsNotExist(statErr), "expected stale file %s to be removed", staleFile)
		}

		// Directories that are only in the remove list (not the create list) should be gone entirely
		removedOnly := filepath.Join(volumePath, AllowedDirectoryWorkflowInputsMount)
		_, statErr := os.Stat(removedOnly)
		assert.True(t, os.IsNotExist(statErr), "expected directory %s to be removed", removedOnly)
	})

	t.Run("Succeeds when directories do not exist", func(t *testing.T) {
		volumePath, err := os.MkdirTemp("", "prepare_data_missing")
		assert.NoError(t, err)
		defer func() {
			assert.NoError(t, os.RemoveAll(volumePath))
		}()

		d := Preparer{executionVolumePath: volumePath, isGitBased: true}
		err = d.PrepareDataDirectories(context.Background())
		assert.NoError(t, err)
	})
}
