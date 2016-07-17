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
	domain      string
	outputJSON  bool
	ouptutHuman bool
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
	AlexaDomainInfo              string                     `json:"Alexa domain info"`
	BitDefenderCategory          string                     `json:"BitDefender category"`
	TrendMicroCategory           string                     `json:"TrendMicro category"`
	WOTDomainInfo                WebOfTrustInfo             `json:"WOT domain info"`
	WebsenseThreatSeekerCategory string                     `json:"Websense ThreatSeeker category"`
	WebutationDomainInfo         WebutationInfo             `json:"Webutation domain info"`
	Categories                   []string                   `json:"categories"`
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

// domainReportCmd represents the scanurl command
var domainReportCmd = &cobra.Command{
	Use:   "domainreport",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		vtURL := "https://www.virustotal.com/vtapi/v2/domain/report"

		client := &http.Client{}

		req, err := http.NewRequest("GET", vtURL, nil)
		if err != nil {
			logrus.WithError(err).Errorln("Failed to generate new request.")
		}

		q := req.URL.Query()
		q.Add("apikey", apiKey)
		q.Add("domain", domain)
		req.URL.RawQuery = q.Encode()

		resp, err := client.Do(req)
		if err != nil {
			logrus.WithError(err).Fatal("Received error while retrieving report.")
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			logrus.WithError(err).Fatal("Received error while reading response body.")
		}

		var respStruct DomainReportResult
		err = json.Unmarshal(body, &respStruct)
		if err != nil {
			logrus.WithError(err).Errorln("Failed to parse VirusTotal response")
		}

		if outputJSON {
			fmt.Println(string(body))
		}

		if ouptutHuman || outputJSON == false {
			printString("Alexa Domain Info", respStruct.AlexaDomainInfo)
			printString("BitDefender Category", respStruct.BitDefenderCategory)
			printStringSlice("Categories", respStruct.Categories)
			printDetectedURLs("Detected URLs", respStruct.DetectedURLs)
			printStringSlice("Domain Siblings", respStruct.DomainSiblings)
			printResolutions("Resolutions", respStruct.Resolutions)
			printResponseCode("Response Code", respStruct.ResponseCode)
			printStringSlice("Subdomains", respStruct.Subdomains)
			printString("TrendMicro Category", respStruct.TrendMicroCategory)
			printDownloadSamples("Undetected Download Samples", respStruct.UndetectedDownloadedSamples)
			printReferrerSamples("Undetected Referrer Samples", respStruct.UndetectedReferrerSamples)
			printString("Verbose Message", respStruct.VerboseMsg)
			printWOT("Web of Trust Domain Information", respStruct.WOTDomainInfo)
			printString("Websense ThreatSeeker Category", respStruct.WebsenseThreatSeekerCategory)
			printStringSlice("Whois", strings.Split(respStruct.Whois, "\n"))
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

func init() {
	RootCmd.AddCommand(domainReportCmd)

	domainReportCmd.PersistentFlags().StringVarP(&domain, "domain", "d", "", "Provide the domain which you would like information about.")
	domainReportCmd.PersistentFlags().BoolVarP(&outputJSON, "output-json", "j", false, "Output JSON instead of human readable.")
	domainReportCmd.PersistentFlags().BoolVarP(&ouptutHuman, "output-human", "u", false, "Output in human readable format.")
}
