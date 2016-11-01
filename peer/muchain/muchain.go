package muchain

import (
	"fmt"

	"github.com/op/go-logging"
	"github.com/spf13/cobra"
)

const (
	muchainFuncName = "muchain"
)

var logger = logging.MustGetLogger("muchainCmd")

// Cmd returns the cobra command for Chaincode
func Cmd() *cobra.Command {
	muchainCmd.AddCommand(newSetCmd())
	muchainCmd.AddCommand(mutateCmd())
	muchainCmd.AddCommand(queryState())
	muchainCmd.AddCommand(extendSetCmd())

	return muchainCmd
}

var muchainCmd = &cobra.Command{
	Use:   muchainFuncName,
	Short: fmt.Sprintf("%s specific commands.", muchainFuncName),
	Long:  fmt.Sprintf("%s specific commands.", muchainFuncName),
}
