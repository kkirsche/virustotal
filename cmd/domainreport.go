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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	domains []string

	outputJSON  bool
	ouptutHuman bool

	grepable bool
)

// DetectedURL is a sub-struct of DomainReportResult
type DetectedURL struct {
	Positives int    `json:"positives"`
	ScanDate  string `json:"scan_date"`
	Total     int    `json:"total"`
	URL       string `json:"url"`
}

// UndetectedDownloadSample is a sub-struct of DomainReportResult
type UndetectedDownloadSample struct {
	Date      string `json:"date"`
	Positives int    `json:"positives"`
	Sha256    string `json:"sha256"`
	Total     int    `json:"total"`
}

// UndetectedReferrerSample is a sub-struct of DomainReportResult
type UndetectedReferrerSample struct {
	Positives int    `json:"positives"`
	Sha256    string `json:"sha256"`
	Total     int    `json:"total"`
}

// Resolution is a sub-struct of DomainReportResult
type Resolution struct {
	IPAddress    string `json:"ip_address"`
	LastResolved string `json:"last_resolved"`
}

// WebutationInfo is a sub-struct of DomainReportResult
type WebutationInfo struct {
	AdultContent string `json:"Adult content"`
	SafetyScore  int    `json:"Safety score"`
	Verdict      string `json:"Verdict"`
}

// WebOfTrustInfo is a sub-struct of DomainReportResult
type WebOfTrustInfo struct {
	ChildSafety       string `json:"Child safety"`
	Privacy           string `json:"Privacy"`
	Trustworthiness   string `json:"Trustworthiness"`
	VendorReliability string `json:"Vendor reliability"`
}

// DomainReportResult is the result that is received after requesting a
// domain report from VirusTotal's public API.
type DomainReportResult struct {
	AlexaDomainInfo              string         `json:"Alexa domain info"`
	BitDefenderCategory          string         `json:"BitDefender category"`
	TrendMicroCategory           string         `json:"TrendMicro category"`
	WOTDomainInfo                WebOfTrustInfo `json:"WOT domain info"`
	WebsenseThreatSeekerCategory string         `json:"Websense ThreatSeeker category"`
	WebutationDomainInfo         WebutationInfo `json:"Webutation domain info"`
	Categories                   []string       `json:"categories"`
	JSON                         string
	DetectedURLs                 []DetectedURL              `json:"detected_urls"`
	DomainSiblings               []string                   `json:"domain_siblings"`
	Resolutions                  []Resolution               `json:"resolutions"`
	ResponseCode                 int                        `json:"response_code"`
	Subdomains                   []string                   `json:"subdomains"`
	UndetectedDownloadedSamples  []UndetectedDownloadSample `json:"undetected_downloaded_samples"`
	UndetectedReferrerSamples    []UndetectedReferrerSample `json:"undetected_referrer_samples"`
	VerboseMsg                   string                     `json:"verbose_msg"`
	Whois                        string                     `json:"whois"`
	WhoisTimestamp               float64                    `json:"whois_timestamp"`
}

// domainCmd represents the scanurl command
var domainCmd = &cobra.Command{
	Use:   "domain",
	Short: "Retrieve informaiton about a domain",
	Long: `Retrieve all information a domain in human readable or JSON format.

Example:

virustotal domain -a {{ api_key }} -d {{ domain(s) }}
`,
	Run: func(cmd *cobra.Command, args []string) {
		responses := retrieveDomainInformation()

		for _, resp := range responses {
			if outputJSON {
				fmt.Println(resp.JSON)
			}

			if ouptutHuman || outputJSON == false {
				printString("Alexa Domain Info", resp.AlexaDomainInfo)
				printString("BitDefender Category", resp.BitDefenderCategory)
				printStringSlice("Categories", resp.Categories)
				printDetectedURLs("Detected URLs", resp.DetectedURLs)
				printStringSlice("Domain Siblings", resp.DomainSiblings)
				printResolutions("Resolutions", resp.Resolutions)
				printResponseCode("Response Code", resp.ResponseCode)
				printStringSlice("Subdomains", resp.Subdomains)
				printString("TrendMicro Category", resp.TrendMicroCategory)
				printDownloadSamples("Undetected Download Samples", resp.UndetectedDownloadedSamples)
				printReferrerSamples("Undetected Referrer Samples", resp.UndetectedReferrerSamples)
				printString("Verbose Message", resp.VerboseMsg)
				printWOT("Web of Trust Domain Information", resp.WOTDomainInfo)
				printString("Websense ThreatSeeker Category", resp.WebsenseThreatSeekerCategory)
				printStringSlice("Whois", strings.Split(resp.Whois, "\n"))
			}
		}
	},
}

func printString(title, value string) {
	if value != "" {
		fmt.Println(title + ":")
		fmt.Printf("\t%s\n", value)
	}
}

func printResponseCode(title string, code int) {
	var meaning string
	switch code {
	case 1:
		meaning = "Present and Retrieved"
	case 0:
		meaning = "Not Found"
	case -1:
		meaning = "Unexpected Error"
	case -2:
		meaning = "Queued for Analysis"
	default:
		meaning = "Unknown"
	}
	fmt.Printf("%s:\t%d (%s)\n", title, code, meaning)
}

func printStringSlice(title string, values []string) {
	if len(values) > 0 {
		fmt.Println(title + ":")
		for _, value := range values {
			fmt.Printf("\t%s\n", strings.TrimSpace(value))
		}
	}
}

func printDetectedURLs(title string, urls []DetectedURL) {
	if len(urls) > 0 {
		fmt.Println(title + ":")
		for _, url := range urls {
			fmt.Printf("\tPositives:\t%d\n", url.Positives)
			fmt.Printf("\tScan Date:\t%s\n", url.ScanDate)
			fmt.Printf("\tTotal:\t\t%d\n", url.Total)
			fmt.Printf("\tURL:\t\t%s\n", url.URL)
		}
	}
}

func printWOT(title string, wot WebOfTrustInfo) {
	if (WebOfTrustInfo{}) != wot {
		fmt.Println(title + ":")
		fmt.Printf("\tChild Safety:\t\t%s\n", wot.ChildSafety)
		fmt.Printf("\tPrivacy:\t\t%s\n", wot.Privacy)
		fmt.Printf("\tTrustworthiness:\t%s\n", wot.Trustworthiness)
		fmt.Printf("\tVendor Reliability:\t%s\n", wot.VendorReliability)
	}
}

func printResolutions(title string, resolutions []Resolution) {
	if resolutions != nil {
		fmt.Println(title + ":")
		for _, resolution := range resolutions {
			fmt.Printf("\tIP Address:\t\t%s\n", resolution.IPAddress)
			fmt.Printf("\tLast Resolved:\t\t%s\n", resolution.LastResolved)
		}
	}
}

func printDownloadSamples(title string, downloadSamples []UndetectedDownloadSample) {
	if downloadSamples != nil {
		fmt.Println(title + ":")
		for _, sample := range downloadSamples {
			fmt.Printf("\tDate:\t%s\n", sample.Date)
			fmt.Printf("\tPositives:\t%d\n", sample.Positives)
			fmt.Printf("\tSHA-256:\t%s\n", sample.Sha256)
			fmt.Printf("\tTotal:\t%d\n", sample.Total)
		}
	}
}

func printReferrerSamples(title string, referrerSamples []UndetectedReferrerSample) {
	if referrerSamples != nil {
		fmt.Println(title + ":")
		for _, sample := range referrerSamples {
			fmt.Printf("\tPositives:\t%d\n", sample.Positives)
			fmt.Printf("\tSHA-256:\t%s\n", sample.Sha256)
			fmt.Printf("\tTotal:\t%d\n", sample.Total)
		}
	}
}

func retrieveDomainInformation() (responses []*DomainReportResult) {
	vtURL := "https://www.virustotal.com/vtapi/v2/domain/report"

	client := &http.Client{}

	for _, domain := range domains {
		req, err := http.NewRequest("GET", vtURL, nil)
		if err != nil {
			logrus.WithError(err).Errorln("Failed to generate new request.")
			continue
		}

		q := req.URL.Query()
		q.Add("apikey", apiKey)
		q.Add("domain", strings.TrimSpace(domain))
		req.URL.RawQuery = q.Encode()

		resp, err := client.Do(req)
		if err != nil {
			logrus.WithError(err).Fatal("Received error while retrieving report.")
			continue
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logrus.WithError(err).Fatal("Received error while reading response body.")
			continue
		}

		var domResp DomainReportResult
		err = json.Unmarshal(body, &domResp)
		if err != nil {
			logrus.WithError(err).Errorln("Failed to parse VirusTotal response")
			continue
		}

		domResp.JSON = string(body)

		responses = append(responses, &domResp)
	}

	return responses
}

func init() {
	RootCmd.AddCommand(domainCmd)

	domainCmd.PersistentFlags().StringSliceVarP(&domains, "domain", "d", []string{}, "Provide the domain which you would like information about.")
	domainCmd.Flags().BoolVarP(&outputJSON, "output-json", "j", false, "Output JSON instead of human readable.")
	domainCmd.Flags().BoolVarP(&ouptutHuman, "output-human", "u", false, "Output in human readable format.")
}
