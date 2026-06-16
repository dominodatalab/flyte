package cmd

import (
	"context"
	"os"
	"strconv"

	"github.com/flyteorg/flyte/flytecopilot/data"
	"github.com/flyteorg/flyte/flytestdlib/logger"
	"github.com/spf13/cobra"
)

type PrepareOptions struct {
	*RootOptions
	executionVolumePath string
}

func (d *PrepareOptions) Prepare(ctx context.Context) error {
	isGitBased, err := strconv.ParseBool(os.Getenv("DOMINO_IS_GIT_BASED"))
	if err != nil {
		isGitBased = false
	}

	p := data.NewPreparer(ctx, d.executionVolumePath, isGitBased)
	err = p.PrepareDataDirectories(ctx)
	if err != nil {
		logger.Errorf(ctx, "Preparing failed, err %s", err)
		return err
	}
	return nil
}

func NewPrepareCommand(opts *RootOptions) *cobra.Command {

	prepareOpts := &PrepareOptions{
		RootOptions: opts,
	}

	// prepareCmd represents the prepare command
	prepareCmd := &cobra.Command{
		Use:   "prepare <opts>",
		Short: "prepares the execution volume for the Flows execution.",
		Long:  `Prepares the execution volume for the Flows execution by creating the necessary temporary Flows data directories.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return prepareOpts.Prepare(context.Background())
		},
	}

	prepareCmd.Flags().StringVarP(&prepareOpts.executionVolumePath, "execution-volume-path", "e", "/execution-vol", "The path to the execution volume.")
	return prepareCmd
}
