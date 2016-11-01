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
	"github.com/hyperledger/fabric/core/db"
	"github.com/hyperledger/fabric/core/ledger/state"
	"github.com/tecbot/gorocksdb"
)

// StateSnapshotIterator implements the interface 'statemgmt.StateSnapshotIterator'
type StateSnapshotIterator struct {
	dbItr *gorocksdb.Iterator
	firstEl bool
}

func newTxSetStateSnapshotIterator(snapshot *gorocksdb.Snapshot) (*StateSnapshotIterator, error) {
	dbItr := db.GetDBHandle().GetTxSetStateCFSnapshotIterator(snapshot)
	dbItr.SeekToFirst()
	return &StateSnapshotIterator{dbItr, true}, nil
}

func (snapshotItr *StateSnapshotIterator) Valid() bool {
	return snapshotItr.dbItr.Valid()
}

// Next - see interface 'statemgmt.StateSnapshotIterator' for details
func (snapshotItr *StateSnapshotIterator) Next() bool {
	if snapshotItr.firstEl {
		snapshotItr.firstEl = false
	} else {
		snapshotItr.dbItr.Next()
	}
	return snapshotItr.dbItr.Valid()
}

// GetRawKeyValue - see interface 'statemgmt.StateSnapshotIterator' for details
func (snapshotItr *StateSnapshotIterator) GetRawKeyValue() ([]byte, []byte) {

	// making a copy of key-value bytes because, underlying key bytes are reused by itr.
	// no need to free slices as iterator frees memory when closed.
	keyBytes := stcomm.Copy(snapshotItr.dbItr.Key().Data())
	valueBytes := stcomm.Copy(snapshotItr.dbItr.Value().Data())
	return keyBytes, valueBytes
}

// Close - see interface 'statemgmt.StateSnapshotIterator' for details
func (snapshotItr *StateSnapshotIterator) Close() {
	snapshotItr.dbItr.Close()
}