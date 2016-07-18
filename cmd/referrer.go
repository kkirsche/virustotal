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

// referrerCmd represents the referrer command
var referrerCmd = &cobra.Command{
	Use:   "referrer",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		responses := retrieveDomainInformation()

		for _, resp := range responses {
			if !grepable {
				printReferrerSamples("Undetected Referrer Samples", resp.UndetectedReferrerSamples)
			} else {
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
	samplesCmd.AddCommand(referrerCmd)

	referrerCmd.Flags().BoolVarP(&grepable, "grep", "g", false, "Make the output grepable (Tab separated — Positives | SHA-256 | Total)")
}
