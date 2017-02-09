package muchain

import (
	"fmt"
	"errors"

	"github.com/spf13/cobra"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/hyperledger/fabric/peer/common"
	"golang.org/x/net/context"
	"github.com/hyperledger/fabric/core/crypto/txset"
	"io/ioutil"
	"github.com/hyperledger/fabric/core"
)

func extendSetCmd() *cobra.Command {
	muchainExtendTxSetCmd.Flags().StringVarP(&txSetId, "name", "n", "",
		"The tx set id to extend.")
	muchainExtendTxSetCmd.Flags().StringVarP(&keyFilePath, "key", "k", "",
		"The path where the seed used to encrypt the transactions in the set will be saved.")
	muchainExtendTxSetCmd.Flags().StringVarP(&setJSONPath, "tx-set-path", "s", "",
		"The file containing the transactions to be added to the set.")

	return muchainExtendTxSetCmd
}

var muchainExtendTxSetCmd = &cobra.Command{
	Use:       "extend",
	Short:     fmt.Sprintf("Extend a previously issued %s transactions set.", muchainFuncName),
	Long:      fmt.Sprintf(`Extend a previously issued %s transactions set.`, muchainFuncName),
	ValidArgs: []string{"path"},
	RunE: func(cmd *cobra.Command, args []string) error {
		return muchainExtendTxSet(cmd, args)
	},
}

// Muchain-related variables.
var (
	txSetId		   string
	keyFilePath	   string
	setJSONPath    string
)

func muchainExtendTxSet(cmd *cobra.Command, args []string) error {
	if !cmd.Flag("key").Changed {
		return fmt.Errorf("A valid path to the key used to encrypt the original set must be provided.")
	}

	if !cmd.Flag("tx-set-path").Changed {
		return fmt.Errorf("A valid path to the transactions to be added to the set must be provided.")
	}

	txSetInputSpec, err := parseFile(setJSONPath)
	if err != nil {
		return err
	}

	seed, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		return err
	}

	// Check that the txSetID is provided if the type is extension
	if !cmd.Flag("name").Changed && txSetInputSpec.SetID == "" {
		return errors.New("Given an extension of a tx set as input, but no tx set id was provided.")
	}

	setToExtend := txSetId
	if setToExtend == "" {
		setToExtend = txSetInputSpec.SetID
	}

	devopsClient, err := common.GetDevopsClient(cmd)
	if err != nil {
		return fmt.Errorf("Error building the txSet: %s", err)
	}

	resp, err := devopsClient.QueryTxSetState(context.Background(), &pb.MutantSpec{TxSetID: setToExtend})
	if err != nil {
		return fmt.Errorf("Unable to retrieve information about the transaction set to extend. Error: %s\n", err)
	}

	if resp.Status != pb.Response_SUCCESS {
		return fmt.Errorf("No error returned while querying the tx set state, but the response status is not successfull. Status: %#v", resp.Status)
	}

	txSetState, err := pb.UnmarshalTxSetStateValue(resp.Msg)
	if err != nil {
		return errors.New("Query successfull, but unable to unmarshal the response.")
	}

	txSpecs, _, err := createTxSpecArray(txSetInputSpec.TxSpecs, 0)
	if err != nil {
		return err
	}
	_, encryptedSpecs, err := txset.EncryptTxSetSpecificationStartingFrom(txSpecs, seed, txSetState.TxNumber)
	if err != nil {
		return err
	}

	if core.SecurityEnabled() {
		seed, err = encryptNonce(seed)
		if err != nil {
			return err
		}
	}

	txSetSpec := &pb.TxSetSpec{
		Type: pb.TxSetSpec_EXTENSION,
		TxSpecs: encryptedSpecs,
		ExtSetID: setToExtend,
		ConfidentialityLevel: pb.ConfidentialityLevel_CONFIDENTIAL,
		Metadata: seed, //TODO: In the shared scenario put only a share of the key and send a different one to every peer
	}

	resp, err = devopsClient.IssueSetExtension(context.Background(), txSetSpec)
	if err != nil {
		return fmt.Errorf("Error extending tx set: %s\n", err)
	}

	if resp.Status != pb.Response_SUCCESS {
		return errors.New("No error returned, but the response was not successfull.")
	}

	logger.Info("Successfully extended transactions set.")
	return err
}