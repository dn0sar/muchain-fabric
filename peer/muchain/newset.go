package muchain

import (
	"fmt"
	"io/ioutil"
	"errors"

	"github.com/spf13/cobra"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/hyperledger/fabric/peer/common"
	"golang.org/x/net/context"
	"github.com/golang/protobuf/proto"
	"os"
	"reflect"
	"github.com/hyperledger/fabric/core/crypto/txset"
	"github.com/hyperledger/fabric/core"
)

func newSetCmd() *cobra.Command {
	muchainIssueTxSetCmd.Flags().StringVarP(&jsonSetPath, "tx-set-path", "s", "",
		"The path to the json file describing the transactions set.")
	muchainIssueTxSetCmd.Flags().StringVarP(&keyOutFilePath, "out", "o", "",
		"The path where the seed used to encrypt the transactions in the set will be saved.")
	muchainIssueTxSetCmd.Flags().BoolVarP(&muchainQueryRaw, "raw", "r", false,
		"If true, output the query value as raw bytes, otherwise format as a printable string")
	muchainIssueTxSetCmd.Flags().BoolVarP(&muchainQueryHex, "hex", "x", false,
		"If true, output the query value byte array in hexadecimal. Incompatible with --raw")

	return muchainIssueTxSetCmd
}

var muchainIssueTxSetCmd = &cobra.Command{
	Use:       "newset",
	Short:     fmt.Sprintf("Create a new %s transactions set.", muchainFuncName),
	Long:      fmt.Sprintf(`Create a new %s transactions set.`, muchainFuncName),
	ValidArgs: []string{"path"},
	RunE: func(cmd *cobra.Command, args []string) error {
		return muchainIssueTxSet(cmd, args)
	},
}

// Muchain-related variables.
var (
	muchainQueryRaw bool
	muchainQueryHex bool
	jsonSetPath		string
	keyOutFilePath	string
)

func muchainIssueTxSet(cmd *cobra.Command, args []string) error {

	if !cmd.Flag("tx-set-path").Changed {
		return fmt.Errorf("A valid transactions set json path must be provided")
	}

	if !cmd.Flag("out").Changed {
		return fmt.Errorf("A valid path to an output file must be provided")
	}

	txSetInputSpec, err := parseFile(jsonSetPath)
	if err != nil {
		return err
	}

	// Check that default index is in range
	if txSetInputSpec.DefaultIndex < 0 || txSetInputSpec.DefaultIndex >= uint64(len(txSetInputSpec.TxSpecs)) {
		return fmt.Errorf("Default index out of range. Index: %d; Set size: %d", txSetInputSpec.DefaultIndex, len(txSetInputSpec.TxSpecs))
	}

	txSpecs, defSpec, err := createTxSpecArray(txSetInputSpec.TxSpecs, txSetInputSpec.DefaultIndex)
	if err != nil {
		return err
	}
	nonce, encryptedSpecs, err := txset.EncryptTxSetSpecification(txSpecs)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(keyOutFilePath, nonce, 0600)
	if err != nil {
		return fmt.Errorf("Unable to save the encryption seed. Err: [%s]", err)
	}

	if core.SecurityEnabled() {
		nonce, err = encryptNonce(nonce)
		if err != nil {
			return err
		}
	}

	txSetSpec := &pb.TxSetSpec{
		Type: pb.TxSetSpec_CREATION,
		TxSpecs: encryptedSpecs,
		DefaultInx: txSetInputSpec.DefaultIndex,
		ConfidentialityLevel: pb.ConfidentialityLevel_CONFIDENTIAL,
		Metadata: nonce, //TODO: In the shared scenario put only a share of the key and send a different one to every peer
	}

	devopsClient, err := common.GetDevopsClient(cmd)
	if err != nil {
		return fmt.Errorf("Error building the txSet: %s", err)
	}

	resp, err := devopsClient.IssueTxSet(context.Background(), txSetSpec)
	if err != nil {
		return fmt.Errorf("Error issuing tx set: %s\n", err)
	}

	if resp.Msg != nil {
		logger.Info("Assigned txSetID:", string(resp.Msg))
	}

	if resp.Status != pb.Response_SUCCESS {
		return errors.New("No error returned, but the response was not successfull.")
	}

	logger.Info("Successfully created transactions set.")

	innerResp := resp.InnerResp
	if defSpec.Action == pb.ChaincodeAction_CHAINCODE_DEPLOY {
		//Default transaction was a deploy transaction, return the deploy specification
		if innerResp.Status != pb.Response_SUCCESS {
			return fmt.Errorf("No error returned, but the deployment of the chaincode was not successfull. Status: %#v", resp.Status)
		}
		if reflect.DeepEqual(innerResp.Msg, resp.Msg) {
			logger.Info("Chaincode successfully deployed.")
			return nil
		}
		chaincodeDeploymentSpec := &pb.ChaincodeDeploymentSpec{}
		err = proto.Unmarshal(innerResp.Msg, chaincodeDeploymentSpec)
		if err != nil {
			return fmt.Errorf("Unable to unmarshal the chaincode deployment specification (%s).", err)
		}
		logger.Infof("Deploy result: %s", chaincodeDeploymentSpec.ChaincodeSpec)
	} else {
		// The default transaction was either a invoke or a query transaction
		if innerResp.Status != pb.Response_SUCCESS {
			return fmt.Errorf("No error returned, but the execution of the default transaction was not successfull. Status: %#v", resp.Status)
		}
		if defSpec.Action == pb.ChaincodeAction_CHAINCODE_INVOKE {
			transactionID := string(innerResp.Msg)
			logger.Infof("Successfully invoked transaction: %s(%s)", defSpec.GetInvocationSpec(), transactionID)
		} else {
			logger.Infof("Successfully queried transaction: %s", defSpec.GetInvocationSpec())
			if innerResp != nil {
				if muchainQueryRaw {
					if muchainQueryHex {
						return errors.New("Options --raw (-r) and --hex (-x) are not compatible\n")
					}
					fmt.Print("Query Result (Raw): ")
					os.Stdout.Write(resp.Msg)
				} else {
					if muchainQueryHex {
						fmt.Printf("Query Result: %x\n", resp.Msg)
					} else {
						fmt.Printf("Query Result: %s\n", string(resp.Msg))
					}
				}
			}
		}
	}

	return err
}