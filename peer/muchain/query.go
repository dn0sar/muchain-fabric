package muchain

import (
	"github.com/spf13/cobra"
)

func queryState() *cobra.Command {

	return muchainQueryTxSetStateCmd
}

var muchainQueryTxSetStateCmd = &cobra.Command{
	Use:       "query-state",
	Short:     "Queries the state of a transactions set.",
	Long:      `Queries the state of a transactions set.`,
	ValidArgs: []string{"1"},
	RunE: func(cmd *cobra.Command, args []string) error {
		return muchainQueryTxSetState(cmd, args)
	},
}

func muchainQueryTxSetState(cmd *cobra.Command, args []string) error {
	return nil
}
