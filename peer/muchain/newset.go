package muchain

import (
	"fmt"
	"io/ioutil"
	"errors"
	"encoding/json"

	"github.com/spf13/cobra"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/hyperledger/fabric/peer/common"
	"golang.org/x/net/context"
	"github.com/golang/protobuf/proto"
	"os"
	"reflect"
)

func newSetCmd() *cobra.Command {
	muchainIssueTxSetCmd.Flags().BoolVarP(&muchainQueryRaw, "raw", "r", false,
		"If true, output the query value as raw bytes, otherwise format as a printable string")
	muchainIssueTxSetCmd.Flags().BoolVarP(&muchainQueryHex, "hex", "x", false,
		"If true, output the query value byte array in hexadecimal. Incompatible with --raw")

	return muchainIssueTxSetCmd
}

var muchainIssueTxSetCmd = &cobra.Command{
	Use:       "newset path/to/json/with/set/specification",
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
)

func muchainIssueTxSet(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return errors.New("Exactly one argument must be provided. The path to the JSON encoding the transaction set specification.")
	}
	txSetInputSpec, err := parseFile(args[0])
	if err != nil {
		return err
	}

	// Check that default index is in range
	if txSetInputSpec.Type == pb.TxSetSpec_CREATION && txSetInputSpec.DefaultIndex < 0 || txSetInputSpec.DefaultIndex >= uint64(len(txSetInputSpec.TxSpecs)) {
		return fmt.Errorf("Default index out of range. Index: %d; Set size: %d", txSetInputSpec.DefaultIndex, len(txSetInputSpec.TxSpecs))
	}

	// Check that the txSetID is provided if the type is extension
	if txSetInputSpec.Type == pb.TxSetSpec_EXTENSION && txSetInputSpec.SetID == "" {
		return errors.New("Given an extension of a tx set as input, but no tx set id was provided.")
	}

	txSpecs, defSpec, err := createTxSpecArray(txSetInputSpec.TxSpecs, txSetInputSpec.DefaultIndex)
	if err != nil {
		return err
	}

	txSetSpec := &pb.TxSetSpec{
		Type: txSetInputSpec.Type,
		TxSpecs: txSpecs,
		DefaultInx: txSetInputSpec.DefaultIndex,
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

func parseFile(path string) (*pb.TxSetInput, error) {
	fileBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Unable to read %s. Error: %s", path, err.Error())
	}

	var txSetInput = &pb.TxSetInput{}
	err = json.Unmarshal(fileBytes, &txSetInput)
	if err != nil {
		return nil, fmt.Errorf("Muchain argument error: %s", err)
	}

	return txSetInput, nil
}

func createTxSpecArray(simpSpecArr []*pb.TxSetInput_SimplifiedSpec, defIndex uint64) ([][]byte, *pb.TxSpec, error) {
	var defSpec *pb.TxSpec
	var txSetSpecArr = make([][]byte, len(simpSpecArr))
	for i, simpSpec := range simpSpecArr {
		var txSpec = &pb.TxSpec{}
		txSpec.Action = simpSpec.Action
		spec := &pb.ChaincodeSpec{
			Type:        simpSpec.Lang,
			ChaincodeID: simpSpec.ChaincodeID,
			CtorMsg:     simpSpec.InputArgs,
		}
		if simpSpec.Action == pb.ChaincodeAction_CHAINCODE_DEPLOY {
			txSpec.Spec = &pb.TxSpec_CodeSpec{CodeSpec: spec}
		} else {
			invocationSpec := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}
			if simpSpec.CustomIDGen != "" {
				invocationSpec.IdGenerationAlg = simpSpec.CustomIDGen
			}
			txSpec.Spec = &pb.TxSpec_InvocationSpec{InvocationSpec: invocationSpec}
		}
		if uint64(i) == defIndex {
			defSpec = txSpec
		}
		marshaledSpec, err := proto.Marshal(txSpec)
		if err != nil {
			return txSetSpecArr, defSpec, fmt.Errorf("Unable to marshal generated txSetSpecification: %s", err)
		}
		txSetSpecArr[i] = marshaledSpec
	}
	return txSetSpecArr, defSpec, nil
}
