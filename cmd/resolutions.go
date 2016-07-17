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

// resolutionsCmd represents the resolutions command
var resolutionsCmd = &cobra.Command{
	Use:   "resolutions",
	Short: "Print the IP Address resolutions of the domains",
	Long: `Print the IP Address resolutions of the domains

virustotal domain resolutions (-g) -a {{ api_key }} -d {{ domains }}
`,
	Run: func(cmd *cobra.Command, args []string) {
		responses := retrieveDomainInformation()

		for _, resp := range responses {
			if len(resp.Resolutions) == 0 {
				continue
			}

			if !grepable {
				printResolutions("Resolutions", resp.Resolutions)
			} else {
				for _, resolution := range resp.Resolutions {
					fmt.Printf("\tIP Address:\t\t%s\n", resolution.IPAddress)
					fmt.Printf("\tLast Resolved:\t\t%s\n", resolution.LastResolved)
				}
			}
		}
	},
}

func init() {
	domainCmd.AddCommand(resolutionsCmd)

	resolutionsCmd.PersistentFlags().BoolVarP(&grepable, "grep", "g", false, "Make the output grepable")
}
