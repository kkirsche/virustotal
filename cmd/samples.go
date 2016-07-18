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

// samplesCmd represents the samples command
var samplesCmd = &cobra.Command{
	Use:   "samples",
	Short: "Print Undetected Download and Referrer Samples",
	Long: `Print Undetected Download and Referrer Samples

virustotal domain samples (-g) -a {{ api_key }} -d {{ domain }}
`,
	Run: func(cmd *cobra.Command, args []string) {
		responses := retrieveDomainInformation()

		for _, resp := range responses {
			if !grepable {
				printDownloadSamples("Undetected Download Samples", resp.UndetectedDownloadedSamples)
				printReferrerSamples("Undetected Referrer Samples", resp.UndetectedReferrerSamples)
			} else {
				for _, sample := range resp.UndetectedDownloadedSamples {
					if sample == (UndetectedDownloadSample{}) {
						continue
					}
					fmt.Printf("%s\t%d\t%s\t%d\n", sample.Date, sample.Positives, sample.Sha256, sample.Total)
				}

				for _, sample := range resp.UndetectedReferrerSamples {
					if sample == (UndetectedReferrerSample{}) {
						continue
					}

					fmt.Printf("%d\t%s\t%d\n", sample.Positives, sample.Sha256, sample.Total)
				}
			}
		}
	},
}

func init() {
	domainCmd.AddCommand(samplesCmd)

	samplesCmd.Flags().BoolVarP(&grepable, "grep", "g", false, "Make the output grepable")
}
