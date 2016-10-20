package muchain

import (
	"fmt"
	"errors"
	"github.com/spf13/cobra"

	pb "github.com/hyperledger/fabric/protos"
	"github.com/hyperledger/fabric/peer/common"
	"golang.org/x/net/context"
)

func queryState() *cobra.Command {

	return muchainQueryTxSetStateCmd
}

var muchainQueryTxSetStateCmd = &cobra.Command{
	Use:       "query-state 'tx-set-id'",
	Short:     "Queries the state of the transactions set given as argument.",
	Long:      `Queries the state of the transactions set given as argument.`,
	ValidArgs: []string{"1"},
	RunE: func(cmd *cobra.Command, args []string) error {
		return muchainQueryTxSetState(cmd, args)
	},
}

func muchainQueryTxSetState(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return errors.New("Exactly one argument must be provided. The tx set id of the tx set state to query.")
	}

	querySpec := &pb.MutantSpec{
		TxSetID: args[0],
	}

	devopsClient, err := common.GetDevopsClient(cmd)
	if err != nil {
		return fmt.Errorf("Error building the txSet: %s", err)
	}

	resp, err := devopsClient.QueryTxSetState(context.Background(), querySpec)
	if err != nil {
		return fmt.Errorf("Error query the tx set state: %s\n", err)
	}

	if resp.Status != pb.Response_SUCCESS {
		return fmt.Errorf("No error returned while querying the tx set state, but the response status is not successfull. Status: %#v", resp.Status)
	}

	txSetState, err := pb.UnmarshalTxSetStateValue(resp.Msg)
	if err != nil {
		return errors.New("Query successfull, but unable to unmarshal the response.")
	}

	logger.Infof("Successfully queried state. Result:")
	fmt.Println("Nonce:", txSetState.Nonce)
	fmt.Print("Active transaction index: {Block: ",  txSetState.Index.BlockNr, " - Index in block: ", txSetState.Index.InBlockIndex, "}\n")
	fmt.Println("Number of transactions in the set:", txSetState.TxNumber)
	fmt.Println("Map of the transactions belonging to this set at a given block:")
	fmt.Println("Block\t\t\tTransactions")
	for k, v := range txSetState.TxsInBlock {
		fmt.Print(k, "\t\t\t", v, "\n")
	}

	return nil
}
