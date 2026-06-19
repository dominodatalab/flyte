package data

import (
	"context"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/flyteorg/flyte/flytestdlib/logger"
)

type Preparer struct {
	isGitBased                        bool
	executionVolumeFlowsSubfolderPath string
}

func (p Preparer) PrepareDataDirectories(ctx context.Context) error {
	logger.Infof(ctx, "Preparing data directories for execution volume at [%s]", p.executionVolumeFlowsSubfolderPath)
	defer logger.Infof(ctx, "Exited preparing data directories for execution volume at [%s]", p.executionVolumeFlowsSubfolderPath)
	directoriesToRemove := AllowedDirectories
	var directoriesToCreate []string
	if p.isGitBased {
		directoriesToCreate = AllowedDirectoriesGBP
	} else {
		directoriesToCreate = AllowedDirectoriesLegacy
	}
	for _, path := range directoriesToRemove {
		dir := filepath.Join(p.executionVolumeFlowsSubfolderPath, path)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			logger.Infof(ctx, "Temporary data directory does not exist: %s", dir)
		} else if err != nil {
			return errors.Wrapf(err, "failed to stat temporary data directory: %s", dir)
		} else {
			logger.Infof(ctx, "Removing temporary data directory: %s", dir)
			if err := os.RemoveAll(dir); err != nil {
				return errors.Wrapf(err, "failed to remove temporary data directory: %s", dir)
			}
		}
	}

	for _, path := range directoriesToCreate {
		dir := filepath.Join(p.executionVolumeFlowsSubfolderPath, path)
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return errors.Wrapf(err, "failed to create temporary data directory: %s", dir)
		}
		if err := os.Chmod(dir, os.ModePerm); err != nil {
			return errors.Wrapf(err, "failed to chmod temporary data directory: %s", dir)
		}
		logger.Infof(ctx, "Temporary data directory created: %s", dir)
	}
	return nil
}

func NewPreparer(_ context.Context, executionVolumeFlowsSubfolderPath string, isGitBased bool) Preparer {
	return Preparer{
		executionVolumeFlowsSubfolderPath: executionVolumeFlowsSubfolderPath,
		isGitBased:                        isGitBased,
	}
}
