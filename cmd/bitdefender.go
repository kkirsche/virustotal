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

// bitdefenderCmd represents the bitdefender command
var bitdefenderCmd = &cobra.Command{
	Use:   "bitdefender",
	Short: "Retrieve BitDefender Category",
	Long: `Retrieve BitDefender Category

virustotal domain bitdefender (-g) -a {{ api_key }} -d {{ domains }}
`,
	Run: func(cmd *cobra.Command, args []string) {
		responses := retrieveDomainInformation()

		for _, resp := range responses {
			if resp.AlexaDomainInfo == "" {
				continue
			}

			if !grepable {
				printString("BitDefender Category", resp.BitDefenderCategory)
			} else {
				fmt.Println(resp.BitDefenderCategory)
			}
		}
	},
}

func init() {
	domainCmd.AddCommand(bitdefenderCmd)

	bitdefenderCmd.PersistentFlags().BoolVarP(&grepable, "grep", "g", false, "Make the output grepable")
}
