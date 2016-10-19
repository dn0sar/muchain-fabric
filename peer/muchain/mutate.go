package muchain

import (
	"fmt"

	"github.com/spf13/cobra"
)

func mutateCmd() *cobra.Command {
	return muchainIssueMutantTxCmd
}

var muchainIssueMutantTxCmd = &cobra.Command{
	Use:       "mutate",
	Short:     fmt.Sprintf("Create a new %s mutant transaction.", muchainFuncName),
	Long:      fmt.Sprintf(`Create a new %s mutant transaction.`, muchainFuncName),
	ValidArgs: []string{"1"},
	RunE: func(cmd *cobra.Command, args []string) error {
		return muchainIssueMutantTx(cmd, args)
	},
}

func muchainIssueMutantTx(cmd *cobra.Command, args []string) error {
	return nil
}
