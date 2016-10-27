/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package raw

import (
	"os"
	"testing"

	"github.com/hyperledger/fabric/core/db"
	"github.com/hyperledger/fabric/core/ledger/state/txsetst/statemgmt"
	"github.com/hyperledger/fabric/core/ledger/testutil"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/tecbot/gorocksdb"
	"math/rand"
)

var testDBWrapper = db.NewTestDBWrapper()

type rawTxSetStTestWrapper struct {
	rawState *TxSetStateImpl
	t        *testing.T
}

func newTxSetStRawTestWrapper(t *testing.T) *rawTxSetStTestWrapper {
	return &rawTxSetStTestWrapper{NewTxSetStateImpl(), t}
}

func (rawTxSetStTestWrapper *rawTxSetStTestWrapper) Get(txSetID string) *pb.TxSetStateValue {
	value, err := rawTxSetStTestWrapper.rawState.Get(txSetID)
	testutil.AssertNoError(rawTxSetStTestWrapper.t, err, "Error while getting value")
	rawTxSetStTestWrapper.t.Logf("state value for txSetID=[%s] = [%#v], ", txSetID, value)
	return value
}

func (rawTxSetStTestWrapper *rawTxSetStTestWrapper) PrepareWorkingSetAndComputeCryptoHash(stateDelta *statemgmt.TxSetStateDelta) []byte {
	rawTxSetStTestWrapper.rawState.PrepareWorkingSet(stateDelta)
	cryptoHash, err := rawTxSetStTestWrapper.rawState.ComputeCryptoHash()
	testutil.AssertNoError(rawTxSetStTestWrapper.t, err, "Error while computing crypto hash")
	rawTxSetStTestWrapper.t.Logf("Cryptohash = [%x]", cryptoHash)
	return cryptoHash
}

func (rawTxSetStTestWrapper *rawTxSetStTestWrapper) AddChangesForPersistence(writeBatch *gorocksdb.WriteBatch) {
	err := rawTxSetStTestWrapper.rawState.AddChangesForPersistence(writeBatch)
	testutil.AssertNoError(rawTxSetStTestWrapper.t, err, "Error while adding changes to db write-batch")
}

func (rawTxSetStTestWrapper *rawTxSetStTestWrapper) CreateRandTxSetStateVal() *pb.TxSetStateValue {
	txSetStVal := &pb.TxSetStateValue{
		Nonce: uint64(rand.Uint32()),
		IntroBlock: uint64(rand.Uint32()),
		LastModifiedAtBlock: uint64(rand.Uint32()),
		Index: &pb.TxSetIndex{
			BlockNr: uint64(rand.Uint32()),
			InBlockIndex: uint64(rand.Uint32()),
		},
		TxNumber: uint64(rand.Uint32()),
		TxsInBlock: map[uint64]uint64{
			uint64(rand.Uint32()): uint64(rand.Uint32()),
			uint64(rand.Uint32()): uint64(rand.Uint32()),
		},
	}
	return txSetStVal
}

func (rawTxSetStTestWrapper *rawTxSetStTestWrapper) PersistChangesAndResetInMemoryChanges() {
	writeBatch := gorocksdb.NewWriteBatch()
	defer writeBatch.Destroy()
	rawTxSetStTestWrapper.AddChangesForPersistence(writeBatch)
	testDBWrapper.WriteToDB(rawTxSetStTestWrapper.t, writeBatch)
	rawTxSetStTestWrapper.rawState.ClearWorkingSet(true)
}

func TestMain(m *testing.M) {
	testutil.SetupTestConfig()
	os.Exit(m.Run())
}