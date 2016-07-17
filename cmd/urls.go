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

// urlsCmd represents the urls command
var urlsCmd = &cobra.Command{
	Use:   "urls",
	Short: "Print the detected URLs of the domains",
	Long: `Print the detected URLs of the domains

virustotal domain urls (-g) -a {{ api_key }} -d {{ domains }}
`,
	Run: func(cmd *cobra.Command, args []string) {
		responses := retrieveDomainInformation()

		for _, resp := range responses {
			if len(resp.DetectedURLs) == 0 {
				continue
			}

			if !grepable {
				printDetectedURLs("Detected URLs", resp.DetectedURLs)
			} else {
				for _, url := range resp.DetectedURLs {
					fmt.Printf("\tPositives:\t%d\n", url.Positives)
					fmt.Printf("\tScan Date:\t%s\n", url.ScanDate)
					fmt.Printf("\tTotal:\t\t%d\n", url.Total)
					fmt.Printf("\tURL:\t\t%s\n", url.URL)
				}
			}
		}
	},
}

func init() {
	domainCmd.AddCommand(urlsCmd)

	urlsCmd.PersistentFlags().BoolVarP(&grepable, "grep", "g", false, "Make the output grepable")
}
