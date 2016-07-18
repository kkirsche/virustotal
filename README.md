# virustotal
Golang based virus total command line tool

## Usage

### Domain Report

Example of `{{ domain }}` is `virustotal.com`

#### Help

		virustotal {{ optional subcommand(s) }} --help
		virustotal {{ optional subcommand(s) }} -h

#### Full Domain Report

		virustotal domain --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain -a {{ api_key }} -d "{{ domain }}"
		virustotal domain --api-key "{{ api_key}}" --domain "{{ domain }}" --output-json
		virustotal domain -a "{{ api_key }}" -d "{{domain}}" -j

#### Alexa Domain Information

		virustotal domain alexa --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain alexa -a "{{ api_key }}" -a "{{ domain }}"
		virustotal domain alexa --grep --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain alexa -g -a "{{ api_key }}" -a "{{ domain }}"

#### BitDefender Category

		virustotal domain bitdefender --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain bitdefender -a "{{ api_key }}" -a "{{ domain }}"
		virustotal domain bitdefender --grep --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain bitdefender -g -a "{{ api_key }}" -a "{{ domain }}"

## Undetected Download Samples

		virustotal domain samples download --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain samples download -a "{{ api_key }}" -a "{{ domain }}"
		virustotal domain samples download --grep --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain samples download -g -a "{{ api_key }}" -a "{{ domain }}"

#### Undetected Referrer Samples

		virustotal domain samples referrer --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain samples referrer -a "{{ api_key }}" -a "{{ domain }}"
		virustotal domain samples referrer --grep --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain samples referrer -g -a "{{ api_key }}" -a "{{ domain }}"

#### IP Resolutions for Domain Name(s)

		virustotal domain resolutions --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain resolutions -a "{{ api_key }}" -a "{{ domain }}"
		virustotal domain resolutions --grep --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain resolutions -g -a "{{ api_key }}" -a "{{ domain }}"

#### Undetected Referrer and Download Samples

		virustotal domain samples --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain samples -a "{{ api_key }}" -a "{{ domain }}"
		virustotal domain samples --grep --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain samples -g -a "{{ api_key }}" -a "{{ domain }}"

#### Subdomains and Sibling Domains

		virustotal domain subdomains --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain subdomains -a "{{ api_key }}" -a "{{ domain }}"
		virustotal domain subdomains --grep --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain subdomains -g -a "{{ api_key }}" -a "{{ domain }}"

#### TrendMicro Category

		virustotal domain trendmicro --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain trendmicro -a "{{ api_key }}" -a "{{ domain }}"
		virustotal domain trendmicro --grep --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain trendmicro -g -a "{{ api_key }}" -a "{{ domain }}"

#### Detected URLs

		virustotal domain urls --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain urls -a "{{ api_key }}" -a "{{ domain }}"
		virustotal domain urls --grep --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain urls -g -a "{{ api_key }}" -a "{{ domain }}"

#### Verbose Message (Was Domain Found on VirusTotal?)

		virustotal domain verbose --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain verbose -a "{{ api_key }}" -a "{{ domain }}"
		virustotal domain verbose --grep --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain verbose -g -a "{{ api_key }}" -a "{{ domain }}"

#### Domain Whois

		virustotal domain whois --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain whois -a "{{ api_key }}" -a "{{ domain }}"
		virustotal domain whois --grep --api-key "{{ api_key }}" --domain "{{ domain }}"
		virustotal domain whois -g -a "{{ api_key }}" -a "{{ domain }}"
