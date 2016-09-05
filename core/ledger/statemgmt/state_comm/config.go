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

package state_comm

import (
	"fmt"
	"sync"

	"github.com/spf13/viper"
	"github.com/op/go-logging"
)

var conf_logger = logging.MustGetLogger("state-conf")

var configMap = make(map[string]*loadConfEl)
var confMapLock = sync.Mutex{}


type ConfigurationData struct {
	StateImplName    string
	StateImplConfigs map[string]interface{}
	DeltaHistorySize int
}

type loadConfEl struct {
	once sync.Once
	confData ConfigurationData
}

func GetConfig(stateKind string, defImpl interface{}, validValues ...interface{}) *ConfigurationData {
	checkMapSafe(stateKind)
	configMap[stateKind].once.Do(func() { loadConfig(stateKind, defImpl, validValues...) })
	return &configMap[stateKind].confData
}

func checkMapSafe(stateKind string) {
	confMapLock.Lock()
	defer confMapLock.Unlock()
	if  _ , exists := configMap[stateKind]; !exists {
		configMap[stateKind] = &loadConfEl{}
	}
}

func loadConfig(stateSpec string, defImpl interface{}, validValues ...interface{}) {
	conf_logger.Info("Loading configurations...")

	data := &configMap[stateSpec].confData

	data.StateImplName = viper.GetString("ledger." + stateSpec + ".dataStructure.name")
	data.StateImplConfigs = viper.GetStringMap("ledger." + stateSpec + ".dataStructure.configs")
	data.DeltaHistorySize = viper.GetInt("ledger." + stateSpec + ".deltaHistorySize")
	if len(data.StateImplName) == 0 {
		data.StateImplName = defImpl.(string)
		data.StateImplConfigs = nil
	} else {
		valid := false
		for _, validName := range validValues {
			if data.StateImplName == validName.(string) {
				valid = true
			}
		}
		if !valid {
			panic(fmt.Errorf("Error during initialization of state implementation. State data structure '%s' is not valid.", data.StateImplName))
		}
	}
	if data.DeltaHistorySize < 0 {
		panic(fmt.Errorf("Delta history size must be greater than or equal to 0. Current value is %d.", data.DeltaHistorySize))
	}
	conf_logger.Infof("Configurations loaded for %s. implName=[%s], implConfigs=%s, deltaHistorySize=[%d]",
		stateSpec, data.StateImplName, data.StateImplConfigs, data.DeltaHistorySize)
}
