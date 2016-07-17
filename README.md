# virustotal
Golang based virus total command line tool

## Usage

### Domain Report

#### Human Readable
```
~/g/s/g/k/virustotal git:master ❯❯❯ virustotal domainreport -a {{ api_key }} -d "verizonenterprise.com"    ✱
Alexa Domain Info:
	verizonenterprise.com is one of the top 100,000 sites in the world
BitDefender Category:
	computersandsoftware
Categories:
	computersandsoftware
	business and economy
Detected URLs:
	Positives:	1
	Scan Date:	2014-07-02 12:31:24
	Total:		53
	URL:		http://verizonenterprise.com/
Resolutions:
	IP Address:		164.109.37.225
	Last Resolved:		2013-11-11 00:00:00
	IP Address:		216.178.234.114
	Last Resolved:		2016-06-30 00:00:00
Response Code:	1 (Present and Retrieved)
Subdomains:
	pmo.verizonenterprise.com
	uswebmail.verizonenterprise.com
	mcrtest.verizonenterprise.com
	mcrncrweb01.gslb.verizonenterprise.com
	mcrload.verizonenterprise.com
	mcrdevia.verizonenterprise.com
	mcrcuaia.verizonenterprise.com
	mcramsweb02.verizonenterprise.com
	mcramsia.verizonenterprise.com
	identityportal.verizonenterprise.com
	icp2.verizonenterprise.com
	gridwideportal.verizonenterprise.com
	cdcvoicecallback.gslb.verizonenterprise.com
	callrec.gslb.verizonenterprise.com
	callbackdirecttest01.gslb.verizonenterprise.com
	caeddvoicecallback.gslb.verizonenterprise.com
	analytics.verizonenterprise.com
	insite.verizonenterprise.com
	cmsvoicecallback.verizonenterprise.com
	news.verizonenterprise.com
	sso.verizonenterprise.com
	securityblog.verizonenterprise.com
	www.verizonenterprise.com
TrendMicro Category:
	business economy
Undetected Download Samples:
	Date:	2015-09-08 08:23:06
	Positives:	0
	SHA-256:	8e63d299076d245650e041bbb5d1edd4aefff8ed04bb81553dfbb325deb66938
	Total:	57
Undetected Referrer Samples:
	Positives:	0
	SHA-256:	d224975fc00ad3741cba46b888afa32db564d5fb5d2a3795dc0debbd39f8c7d0
	Total:	55
	Positives:	0
	SHA-256:	5931b7fd592a5b02ef75423e52874dfd434e8ecdea00ac3abd536cc3b62f7109
	Total:	55
	Positives:	0
	SHA-256:	42c4d0c6253b0c3f4566247f28cfd04151a24189076ed10d169bdeb1551a8694
	Total:	55
	Positives:	0
	SHA-256:	273ec39ae50443be65080067264b07367c74a20ccca6831f71a2bfe9d2df1f6c
	Total:	57
	Positives:	0
	SHA-256:	d5b3f49065e342d687988b3ce1fb61bc69196edc50e34cc4dae18507400edef4
	Total:	56
	Positives:	0
	SHA-256:	fbe7461e33c2c8c0d6f513a90e81df78a986de9c39bb4b15853568eec097d0f7
	Total:	55
	Positives:	0
	SHA-256:	604ff6b98ad5f415c330e1bbf41bda2d74e9fc58d506c0027644bc4de5f21b0b
	Total:	56
	Positives:	0
	SHA-256:	e7203ca76a2a4c034cd353994420fde787557d556f05145bde4e8be224352e72
	Total:	56
	Positives:	0
	SHA-256:	fc0343f02f3369294e7281271bde847b55a3b462f8922d15c03e55fd1d67ce70
	Total:	56
	Positives:	0
	SHA-256:	fc7cdcd2c64d5aa4cc6333a39a7c5365d7fa91a33e04ee49e43afcc03addaf39
	Total:	57
	Positives:	0
	SHA-256:	d9155e512c4d6d066c9375032413f66bd1cea7dc31a4236750344641fca19ea8
	Total:	57
	Positives:	0
	SHA-256:	339b964c84c44217562f64bd79c8707170385f4439d5ee6ab8890e4bac494617
	Total:	57
	Positives:	0
	SHA-256:	f5ca4a96a9947c6c5129aad2da072ee9c1135bce7e790d57c7b14fb10683f923
	Total:	57
	Positives:	0
	SHA-256:	5fb1df35d668aad61cf01b7c70a6107486dbad728ab9a3771e633ec16231e478
	Total:	57
	Positives:	0
	SHA-256:	9acbadf4ff9df6830b5fcb28f36e208bc4164b1f9796bb384d693764cbd53e60
	Total:	56
	Positives:	0
	SHA-256:	6c9afeb5c820ed7b69d6762368f38e8b0e2597f63e70e9fbd5d82bb56f580b34
	Total:	54
	Positives:	0
	SHA-256:	dbaf102c6606f0dc51605c99e086584244f87d41022ad5b8cc332580c8160f50
	Total:	56
	Positives:	0
	SHA-256:	e670dc16fe6fea27f4ba4ba95181906c41e9a189a92f160b66d66ba7a7d17abf
	Total:	55
	Positives:	0
	SHA-256:	2510aba201cfb35f6b2b14946f0b60f1fb644ff8e0ec277caf5f8bc306741cff
	Total:	54
	Positives:	0
	SHA-256:	16140013e3b5e607c584cff70c17e9c14e3733186d332b9f68b3bab9b8b2247d
	Total:	52
	Positives:	0
	SHA-256:	cdc964b1c4a91b3481b4909140e58cfa06a15896afb88a201ec500187b32254b
	Total:	56
	Positives:	0
	SHA-256:	0adfc0d860d9d5d88fa1ec0df2673d68aab5e616cb806995eca7e2ac7e8ea5ab
	Total:	56
	Positives:	0
	SHA-256:	968d0f2aaa166037422d0ac8124f0ce904f6669b60ae00ff861f6e403b2afa03
	Total:	56
	Positives:	0
	SHA-256:	89dd5ec14ee4680f768ea8e434fd530082edeb6af4b42abaff072a2efcac44e8
	Total:	56
	Positives:	0
	SHA-256:	1a8d492340e6cc4ded648d5652d32165571ffdd810f67cecb35676bb782063dc
	Total:	57
	Positives:	0
	SHA-256:	67fd290866499a8a6b4bb6ca80d73202b147c7f715ef5542cde4e508a7e89c8b
	Total:	57
	Positives:	0
	SHA-256:	ab676a4255f42f9a3cd25fc8e7e62847615b3bc5d14326a06b4c47abc5d55e71
	Total:	57
	Positives:	0
	SHA-256:	49378f46922671e3ad7eb8b3b4112cbb8b875166e2be94bc5cc2d869ae4244c0
	Total:	56
	Positives:	0
	SHA-256:	90f2691699797b6390dfa3e14dbcfbfb8a2735946c386da6f68f19abc5bd35f6
	Total:	54
	Positives:	0
	SHA-256:	e9d4135568b76c7173de56eb37808b58dbc8680e003a028a843e782915968b7b
	Total:	54
	Positives:	0
	SHA-256:	91f73635d89fa532ff65a1ada686926a60784e6e9b70d8189b9d69bfc38c51a5
	Total:	54
Verbose Message:
	Domain found in dataset
Web of Trust Domain Information:
	Child Safety:		Excellent
	Privacy:		Excellent
	Trustworthiness:	Excellent
	Vendor Reliability:	Excellent
Websense ThreatSeeker Category:
	business and economy
Whois:
	Domain Name: VERIZONENTERPRISE.COM
	Registrar: MARKMONITOR INC.
	Sponsoring Registrar IANA ID: 292
	Whois Server: whois.markmonitor.com
	Referral URL: http://www.markmonitor.com
	Name Server: AUTH-NS1.VERIZONBUSINESS.COM
	Name Server: AUTH-NS2.VERIZONBUSINESS.COM
	Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
	Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
	Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
	Updated Date: 10-feb-2015
	Creation Date: 14-mar-2000
	Expiration Date: 14-mar-2017

	Domain Name: verizonenterprise.com
	Registry Domain ID: 22395586_DOMAIN_COM-VRSN
	Registrar WHOIS Server: whois.markmonitor.com
	Registrar URL: http://www.markmonitor.com
	Updated Date: 2015-08-10T04:00:16-0700
	Creation Date: 2000-03-14T00:00:00-0800
	Registrar Registration Expiration Date: 2017-03-14T00:00:00-0700
	Registrar: MarkMonitor, Inc.
	Registrar IANA ID: 292
	Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
	Registrar Abuse Contact Phone: +1.2083895740
	Domain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)
	Domain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)
	Domain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)
	Registry Registrant ID:
	Registrant Name: Verizon Trademark Services LLC
	Registrant Organization: Verizon Trademark Services LLC
	Registrant Street: 1320 North Court House Road
	Registrant City: Arlington
	Registrant State/Province: VA
	Registrant Postal Code: 22201
	Registrant Country: US
	Registrant Phone: +1.7033513164
	Registrant Phone Ext:
	Registrant Fax: +1.7033513669
	Registrant Fax Ext:
	Registrant Email: domainlegalcontact@verizon.com
	Registry Admin ID:
	Admin Name: Domain Administrator
	Admin Organization: Verizon Trademark Services LLC
	Admin Street: 1320 North Court House Road
	Admin City: Arlington
	Admin State/Province: VA
	Admin Postal Code: 22201
	Admin Country: US
	Admin Phone: +1.7033513164
	Admin Phone Ext:
	Admin Fax: +1.7033513669
	Admin Fax Ext:
	Admin Email: domainlegalcontact@verizon.com
	Registry Tech ID:
	Tech Name: Domain Technician
	Tech Organization: Verizon
	Tech Street: 1320 North Court House Road
	Tech City: Arlington
	Tech State/Province: VA
	Tech Postal Code: 22201
	Tech Country: US
	Tech Phone: +1.7033513164
	Tech Phone Ext:
	Tech Fax: +1.7033513669
	Tech Fax Ext:
	Tech Email: sysmgr@verizon.com
	Name Server: auth-ns2.verizonbusiness.com
	Name Server: auth-ns1.verizonbusiness.com
	DNSSEC: unsigned

	https://www.icann.org/resources/pages/epp-status-codes-2014-06-16-en
  ```

#### JSON

```
~/g/s/g/k/virustotal git:master ❯❯❯ virustotal domainreport -a {{ api_key}} -d "verizonenterprise.com" -j
{"BitDefender category": "computersandsoftware", "undetected_referrer_samples": [{"positives": 0, "total": 55, "sha256": "d224975fc00ad3741cba46b888afa32db564d5fb5d2a3795dc0debbd39f8c7d0"}, {"positives": 0, "total": 55, "sha256": "5931b7fd592a5b02ef75423e52874dfd434e8ecdea00ac3abd536cc3b62f7109"}, {"positives": 0, "total": 55, "sha256": "42c4d0c6253b0c3f4566247f28cfd04151a24189076ed10d169bdeb1551a8694"}, {"positives": 0, "total": 57, "sha256": "273ec39ae50443be65080067264b07367c74a20ccca6831f71a2bfe9d2df1f6c"}, {"positives": 0, "total": 56, "sha256": "d5b3f49065e342d687988b3ce1fb61bc69196edc50e34cc4dae18507400edef4"}, {"positives": 0, "total": 55, "sha256": "fbe7461e33c2c8c0d6f513a90e81df78a986de9c39bb4b15853568eec097d0f7"}, {"positives": 0, "total": 56, "sha256": "604ff6b98ad5f415c330e1bbf41bda2d74e9fc58d506c0027644bc4de5f21b0b"}, {"positives": 0, "total": 56, "sha256": "e7203ca76a2a4c034cd353994420fde787557d556f05145bde4e8be224352e72"}, {"positives": 0, "total": 56, "sha256": "fc0343f02f3369294e7281271bde847b55a3b462f8922d15c03e55fd1d67ce70"}, {"positives": 0, "total": 57, "sha256": "fc7cdcd2c64d5aa4cc6333a39a7c5365d7fa91a33e04ee49e43afcc03addaf39"}, {"positives": 0, "total": 57, "sha256": "d9155e512c4d6d066c9375032413f66bd1cea7dc31a4236750344641fca19ea8"}, {"positives": 0, "total": 57, "sha256": "339b964c84c44217562f64bd79c8707170385f4439d5ee6ab8890e4bac494617"}, {"positives": 0, "total": 57, "sha256": "f5ca4a96a9947c6c5129aad2da072ee9c1135bce7e790d57c7b14fb10683f923"}, {"positives": 0, "total": 57, "sha256": "5fb1df35d668aad61cf01b7c70a6107486dbad728ab9a3771e633ec16231e478"}, {"positives": 0, "total": 56, "sha256": "9acbadf4ff9df6830b5fcb28f36e208bc4164b1f9796bb384d693764cbd53e60"}, {"positives": 0, "total": 54, "sha256": "6c9afeb5c820ed7b69d6762368f38e8b0e2597f63e70e9fbd5d82bb56f580b34"}, {"positives": 0, "total": 56, "sha256": "dbaf102c6606f0dc51605c99e086584244f87d41022ad5b8cc332580c8160f50"}, {"positives": 0, "total": 55, "sha256": "e670dc16fe6fea27f4ba4ba95181906c41e9a189a92f160b66d66ba7a7d17abf"}, {"positives": 0, "total": 54, "sha256": "2510aba201cfb35f6b2b14946f0b60f1fb644ff8e0ec277caf5f8bc306741cff"}, {"positives": 0, "total": 52, "sha256": "16140013e3b5e607c584cff70c17e9c14e3733186d332b9f68b3bab9b8b2247d"}, {"positives": 0, "total": 56, "sha256": "cdc964b1c4a91b3481b4909140e58cfa06a15896afb88a201ec500187b32254b"}, {"positives": 0, "total": 56, "sha256": "0adfc0d860d9d5d88fa1ec0df2673d68aab5e616cb806995eca7e2ac7e8ea5ab"}, {"positives": 0, "total": 56, "sha256": "968d0f2aaa166037422d0ac8124f0ce904f6669b60ae00ff861f6e403b2afa03"}, {"positives": 0, "total": 56, "sha256": "89dd5ec14ee4680f768ea8e434fd530082edeb6af4b42abaff072a2efcac44e8"}, {"positives": 0, "total": 57, "sha256": "1a8d492340e6cc4ded648d5652d32165571ffdd810f67cecb35676bb782063dc"}, {"positives": 0, "total": 57, "sha256": "67fd290866499a8a6b4bb6ca80d73202b147c7f715ef5542cde4e508a7e89c8b"}, {"positives": 0, "total": 57, "sha256": "ab676a4255f42f9a3cd25fc8e7e62847615b3bc5d14326a06b4c47abc5d55e71"}, {"positives": 0, "total": 56, "sha256": "49378f46922671e3ad7eb8b3b4112cbb8b875166e2be94bc5cc2d869ae4244c0"}, {"positives": 0, "total": 54, "sha256": "90f2691699797b6390dfa3e14dbcfbfb8a2735946c386da6f68f19abc5bd35f6"}, {"positives": 0, "total": 54, "sha256": "e9d4135568b76c7173de56eb37808b58dbc8680e003a028a843e782915968b7b"}, {"positives": 0, "total": 54, "sha256": "91f73635d89fa532ff65a1ada686926a60784e6e9b70d8189b9d69bfc38c51a5"}], "whois_timestamp": 1467410563.3152499, "WOT domain info": {"Vendor reliability": "Excellent", "Child safety": "Excellent", "Trustworthiness": "Excellent", "Privacy": "Excellent"}, "Webutation domain info": {"Verdict": "safe", "Adult content": "no", "Safety score": 100}, "undetected_downloaded_samples": [{"date": "2015-09-08 08:23:06", "positives": 0, "total": 57, "sha256": "8e63d299076d245650e041bbb5d1edd4aefff8ed04bb81553dfbb325deb66938"}], "resolutions": [{"last_resolved": "2013-11-11 00:00:00", "ip_address": "164.109.37.225"}, {"last_resolved": "2016-06-30 00:00:00", "ip_address": "216.178.234.114"}], "subdomains": ["pmo.verizonenterprise.com", "uswebmail.verizonenterprise.com", "mcrtest.verizonenterprise.com", "mcrncrweb01.gslb.verizonenterprise.com", "mcrload.verizonenterprise.com", "mcrdevia.verizonenterprise.com", "mcrcuaia.verizonenterprise.com", "mcramsweb02.verizonenterprise.com", "mcramsia.verizonenterprise.com", "identityportal.verizonenterprise.com", "icp2.verizonenterprise.com", "gridwideportal.verizonenterprise.com", "cdcvoicecallback.gslb.verizonenterprise.com", "callrec.gslb.verizonenterprise.com", "callbackdirecttest01.gslb.verizonenterprise.com", "caeddvoicecallback.gslb.verizonenterprise.com", "analytics.verizonenterprise.com", "insite.verizonenterprise.com", "cmsvoicecallback.verizonenterprise.com", "news.verizonenterprise.com", "sso.verizonenterprise.com", "securityblog.verizonenterprise.com", "www.verizonenterprise.com"], "TrendMicro category": "business economy", "categories": ["computersandsoftware", "business and economy"], "domain_siblings": [], "whois": "   Domain Name: VERIZONENTERPRISE.COM\n   Registrar: MARKMONITOR INC.\n   Sponsoring Registrar IANA ID: 292\n   Whois Server: whois.markmonitor.com\n   Referral URL: http://www.markmonitor.com\n   Name Server: AUTH-NS1.VERIZONBUSINESS.COM\n   Name Server: AUTH-NS2.VERIZONBUSINESS.COM\n   Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\n   Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n   Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\n   Updated Date: 10-feb-2015\n   Creation Date: 14-mar-2000\n   Expiration Date: 14-mar-2017\n\nDomain Name: verizonenterprise.com\nRegistry Domain ID: 22395586_DOMAIN_COM-VRSN\nRegistrar WHOIS Server: whois.markmonitor.com\nRegistrar URL: http://www.markmonitor.com\nUpdated Date: 2015-08-10T04:00:16-0700\nCreation Date: 2000-03-14T00:00:00-0800\nRegistrar Registration Expiration Date: 2017-03-14T00:00:00-0700\nRegistrar: MarkMonitor, Inc.\nRegistrar IANA ID: 292\nRegistrar Abuse Contact Email: abusecomplaints@markmonitor.com\nRegistrar Abuse Contact Phone: +1.2083895740\nDomain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)\nDomain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)\nDomain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)\nRegistry Registrant ID: \nRegistrant Name: Verizon Trademark Services LLC\nRegistrant Organization: Verizon Trademark Services LLC\nRegistrant Street: 1320 North Court House Road\nRegistrant City: Arlington\nRegistrant State/Province: VA\nRegistrant Postal Code: 22201\nRegistrant Country: US\nRegistrant Phone: +1.7033513164\nRegistrant Phone Ext: \nRegistrant Fax: +1.7033513669\nRegistrant Fax Ext: \nRegistrant Email: domainlegalcontact@verizon.com\nRegistry Admin ID: \nAdmin Name: Domain Administrator\nAdmin Organization: Verizon Trademark Services LLC\nAdmin Street: 1320 North Court House Road\nAdmin City: Arlington\nAdmin State/Province: VA\nAdmin Postal Code: 22201\nAdmin Country: US\nAdmin Phone: +1.7033513164\nAdmin Phone Ext: \nAdmin Fax: +1.7033513669\nAdmin Fax Ext: \nAdmin Email: domainlegalcontact@verizon.com\nRegistry Tech ID: \nTech Name: Domain Technician\nTech Organization: Verizon\nTech Street: 1320 North Court House Road\nTech City: Arlington\nTech State/Province: VA\nTech Postal Code: 22201\nTech Country: US\nTech Phone: +1.7033513164\nTech Phone Ext: \nTech Fax: +1.7033513669\nTech Fax Ext: \nTech Email: sysmgr@verizon.com\nName Server: auth-ns2.verizonbusiness.com\nName Server: auth-ns1.verizonbusiness.com\nDNSSEC: unsigned\n\n https://www.icann.org/resources/pages/epp-status-codes-2014-06-16-en", "Alexa domain info": "verizonenterprise.com is one of the top 100,000 sites in the world", "response_code": 1, "verbose_msg": "Domain found in dataset", "Websense ThreatSeeker category": "business and economy", "detected_urls": [{"url": "http://verizonenterprise.com/", "positives": 1, "total": 53, "scan_date": "2014-07-02 12:31:24"}]}
```
