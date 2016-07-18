// Copyright © 2016 Kevin Kirsche <kevin.kirsche@verizon.com> <kev.kirsche@gmail.com>
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

// verboseCmd represents the verbose command
var verboseCmd = &cobra.Command{
	Use:   "verbose",
	Short: "Print VirusTotal verbose message",
	Long: `Print VirusTotal verbose message

virustotal domain verbose (-g) -a {{ api_key }} -d {{ domain }}
`,
	Run: func(cmd *cobra.Command, args []string) {
		responses := retrieveDomainInformation()

		for _, resp := range responses {
			if resp.VerboseMsg == "" {
				continue
			}

			if !grepable {
				printString("Verbose Message", resp.VerboseMsg)
			} else {
				fmt.Println(resp.VerboseMsg)
			}
		}
	},
}

func init() {
	domainCmd.AddCommand(verboseCmd)

	verboseCmd.Flags().BoolVarP(&grepable, "grep", "g", false, "Make the output grepable")
}
