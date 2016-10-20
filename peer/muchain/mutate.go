package muchain

import (
	"fmt"

	"github.com/spf13/cobra"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/hyperledger/fabric/peer/common"
	"golang.org/x/net/context"
)

func mutateCmd() *cobra.Command {
	muchainIssueMutantTxCmd.Flags().StringVarP(&txSetID, "txsetid", "d", "",
		"The ID of the transactions set that should be mutated.")
	muchainIssueMutantTxCmd.Flags().Uint64VarP(&blockNum, "blocknum", "b", 0,
		"The block (as a positive number) where the new transaction of the set is stored.")
	muchainIssueMutantTxCmd.Flags().Uint64VarP(&index, "index", "i", 0,
		"The index (as a positive number) of the new active transaction (from the transactions belonging to the transactions set declared in the block given with --blocknum).")

	return muchainIssueMutantTxCmd
}

var (
	txSetID string
	blockNum uint64
	index uint64
)

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
	if !cmd.Flag("txsetid").Changed {
		return fmt.Errorf("A valid transactions set id must be provided")
	}
	if !cmd.Flag("blocknum").Changed {
		return  fmt.Errorf("A valid block number must be provided")
	}
	if !cmd.Flag("index").Changed {
		return  fmt.Errorf("A valid index must be provided")
	}

	mutantSpec := &pb.MutantSpec{
		TxSetID: txSetID,
		BlockNum: blockNum,
		Index: index,
	}

	devopsClient, err := common.GetDevopsClient(cmd)
	if err != nil {
		return fmt.Errorf("Error building the txSet: %s", err)
	}

	resp, err := devopsClient.Mutate(context.Background(), mutantSpec)
	if err != nil {
		return fmt.Errorf("Error issuing tx set: %s\n", err)
	}

	if resp.Msg != nil {
		logger.Info("Tx id of the mutant transaction:", string(resp.Msg))
	}

	if resp.Status != pb.Response_SUCCESS {
		return fmt.Errorf("No error returned while issuing the mutant transaction, but the mutation response status was not successful. Status: %#v", resp.Status)
	} else  {
		logger.Infof("Successfully mutated state.")
	}

 	return nil
}
