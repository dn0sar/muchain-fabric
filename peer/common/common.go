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

package common

import (
	"fmt"
	"errors"
	"github.com/spf13/cobra"
	"os"
	"io/ioutil"
	"github.com/spf13/viper"
	"github.com/hyperledger/fabric/peer/util"

	"github.com/hyperledger/fabric/core/peer"
	pb "github.com/hyperledger/fabric/protos"
	"github.com/hyperledger/fabric/core"
	"github.com/op/go-logging"
)

// UndefinedParamValue defines what undefined parameters in the command line will initialise to
const UndefinedParamValue = ""

var logger = logging.MustGetLogger("main")

// GetDevopsClient returns a new client connection for this peer
func GetDevopsClient(cmd *cobra.Command) (pb.DevopsClient, error) {
	clientConn, err := peer.NewPeerClientConnection()
	if err != nil {
		return nil, fmt.Errorf("Error trying to connect to local peer: %s", err)
	}
	devopsClient := pb.NewDevopsClient(clientConn)
	return devopsClient, nil
}

func SetSecurityParams(user string, spec *pb.ChaincodeSpec) (*pb.ChaincodeSpec, error){
	// If security is enabled, add client login token
	if core.SecurityEnabled() {
		if user == UndefinedParamValue {
			return spec, errors.New("Must supply username for chaincode when security is enabled")
		}

		// Retrieve the CLI data storage path
		// Returns /var/openchain/production/client/
		localStore := util.GetCliFilePath()

		// Check if the user is logged in before sending transaction
		if _, err := os.Stat(localStore + "loginToken_" + user); err == nil {
			logger.Infof("Local user '%s' is already logged in. Retrieving login token.\n", user)

			// Read in the login token
			token, err := ioutil.ReadFile(localStore + "loginToken_" + user)
			if err != nil {
				panic(fmt.Errorf("Fatal error when reading client login token: %s\n", err))
			}

			// Add the login token to the chaincodeSpec
			spec.SecureContext = string(token)

			// If privacy is enabled, mark chaincode as confidential
			if viper.GetBool("security.privacy") {
				logger.Info("Set confidentiality level to CONFIDENTIAL.\n")
				spec.ConfidentialityLevel = pb.ConfidentialityLevel_CONFIDENTIAL
			}
		} else {
			// Check if the token is not there and fail
			if os.IsNotExist(err) {
				return spec, fmt.Errorf("User '%s' not logged in. Use the 'peer network login' command to obtain a security token.", user)
			}
			// Unexpected error
			panic(fmt.Errorf("Fatal error when checking for client login token: %s\n", err))
		}
	} else {
		if user != UndefinedParamValue {
			logger.Warning("Username supplied but security is disabled.")
		}
		if viper.GetBool("security.privacy") {
			panic(errors.New("Privacy cannot be enabled as requested because security is disabled"))
		}
	}
	return spec, nil
}
