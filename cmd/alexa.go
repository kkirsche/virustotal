// Copyright © 2016 Kevin Kirsche <kev.kirsche@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// alexaCmd represents the alexa command
var alexaCmd = &cobra.Command{
	Use:   "alexa",
	Short: "Retrieve Alexa Domain Information",
	Long: `Retrieve Alexa Domain Information for domains.

virustotal domain alexa (-g) -a {{ api_key }} -d {{ domains }}
`,
	Run: func(cmd *cobra.Command, args []string) {
		responses := retrieveDomainInformation()

		for _, resp := range responses {
			if resp.AlexaDomainInfo == "" {
				continue
			}

			if !grepable {
				printString("Alexa Domain Info", resp.AlexaDomainInfo)
			} else {
				fmt.Println(resp.AlexaDomainInfo)
			}
		}
	},
}

func init() {
	domainCmd.AddCommand(alexaCmd)

	alexaCmd.Flags().BoolVarP(&grepable, "grep", "g", false, "Make the output grepable")
}
