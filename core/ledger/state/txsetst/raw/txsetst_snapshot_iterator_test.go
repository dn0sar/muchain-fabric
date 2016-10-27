package raw

import (
	"testing"

	"github.com/hyperledger/fabric/core/db"
	"github.com/hyperledger/fabric/core/ledger/state/txsetst/statemgmt"
	"github.com/hyperledger/fabric/core/ledger/testutil"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/golang/protobuf/proto"
	"strconv"
)

func TestStateSnapshotIterator(t *testing.T) {

	numToInsert := 10
	testDBWrapper.CleanDB(t)
	txSetStRawTestWrapper := newTxSetStRawTestWrapper(t)
	stateTrie := txSetStRawTestWrapper.rawState
	stateDelta := statemgmt.NewTxSetStateDelta()

	randTxSetStVal := make([]*pb.TxSetStateValue, numToInsert + 2)
	for i := 0; i < numToInsert + 2; i++ {
		randTxSetStVal[i] = txSetStRawTestWrapper.CreateRandTxSetStateVal()
	}

	keys := make([]string, numToInsert)
	for i := 0; i < numToInsert; i++ {
		keys[i] = "key" + strconv.Itoa(i + 1)
	}



	// insert keys
	for i, key := range keys {
		stateDelta.Set(key, randTxSetStVal[i], nil)
	}
	stateTrie.PrepareWorkingSet(stateDelta)
	txSetStRawTestWrapper.PersistChangesAndResetInMemoryChanges()
	//check that the key is persisted
	for i, key := range keys {
		testutil.AssertEquals(t, txSetStRawTestWrapper.Get(key), randTxSetStVal[i])
	}

	// take db snapeshot
	dbSnapshot := db.GetDBHandle().GetSnapshot()

	stateDelta1 := statemgmt.NewTxSetStateDelta()
	// delete a few keys
	stateDelta1.Delete("key1", nil)
	stateDelta1.Delete("key3", nil)
	stateDelta1.Delete("key4", nil)
	stateDelta1.Delete("key6", nil)

	// update remaining keys
	stateDelta1.Set("key2", randTxSetStVal[numToInsert], nil)
	stateDelta1.Set("key5", randTxSetStVal[numToInsert + 1], nil)

	stateTrie.PrepareWorkingSet(stateDelta1)
	txSetStRawTestWrapper.PersistChangesAndResetInMemoryChanges()
	//check that the keys are updated
	testutil.AssertNil(t, txSetStRawTestWrapper.Get("key1"))
	testutil.AssertNil(t, txSetStRawTestWrapper.Get("key3"))
	testutil.AssertNil(t, txSetStRawTestWrapper.Get("key4"))
	testutil.AssertNil(t, txSetStRawTestWrapper.Get("key6"))
	testutil.AssertEquals(t, txSetStRawTestWrapper.Get("key2"), randTxSetStVal[numToInsert])
	testutil.AssertEquals(t, txSetStRawTestWrapper.Get("key5"), randTxSetStVal[numToInsert + 1])

	itr, err := newTxSetStateSnapshotIterator(dbSnapshot)
	testutil.AssertNoError(t, err, "Error while getting state snapshot iterator")

	stateDeltaFromSnapshot := statemgmt.NewTxSetStateDelta()
	for itr.Next() {
		txSetID, valueBytes := itr.GetRawKeyValue()
		unmarshalledState := &pb.TxSetStateValue{}
		err := proto.Unmarshal(valueBytes, unmarshalledState)
		testutil.AssertNoError(t, err, "Error while unmarshalling tx set state value")
		t.Logf("key=[%s], value=[%s]", string(txSetID), unmarshalledState.String())
		stateDeltaFromSnapshot.Set(string(txSetID), unmarshalledState, nil)
	}
	testutil.AssertEquals(t, stateDelta, stateDeltaFromSnapshot)
}
