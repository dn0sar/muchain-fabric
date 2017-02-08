package muchain

import (
	"fmt"

	"github.com/op/go-logging"
	"github.com/spf13/cobra"
	"github.com/hyperledger/fabric/peer/common"
)

const (
	muchainFuncName = "muchain"
)

var logger = logging.MustGetLogger("muchainCmd")

// Cmd returns the cobra command for Muchain
func Cmd() *cobra.Command {
	flags := muchainCmd.PersistentFlags()

	flags.StringVarP(&fabricUsr, "username", "u", common.UndefinedParamValue,
		fmt.Sprint("Username for fabric operations when security is enabled"))

	muchainCmd.AddCommand(newSetCmd())
	muchainCmd.AddCommand(mutateCmd())
	muchainCmd.AddCommand(queryState())
	muchainCmd.AddCommand(extendSetCmd())

	return muchainCmd
}

var (
	fabricUsr string
)

var muchainCmd = &cobra.Command{
	Use:   muchainFuncName,
	Short: fmt.Sprintf("%s specific commands.", muchainFuncName),
	Long:  fmt.Sprintf("%s specific commands.", muchainFuncName),
}
