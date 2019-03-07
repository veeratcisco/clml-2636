#
# This is sample code to understand how API works...
# Released under License https://developer.cisco.com/site/license/cisco-sample-code-license/
#
#
import requests
from requests.auth import HTTPBasicAuth
import ConfigParser
import os
import sys
import dns.resolver

# Specify the config file to read from
configFile = 'api.cfg'

# Read the config file to get settings
config = ConfigParser.RawConfigParser()
config.read(configFile)

# Threat Grid configuration
TGapiKey = config.get('ThreatGrid', 'apiKey')
TGapiKey = str.rstrip(TGapiKey)

hostName = config.get('ThreatGrid', 'hostName')
hostName = str.rstrip(hostName)

# Virustotal Configuration
VTKey = config.get('VirusTotal', 'apiKey')
VTKey = str.rstrip(VTKey)

# Investigate Configuration
UIToken = config.get('Investigate', 'token')
UIToken = str.rstrip(UIToken)

# Validate a parameter was provited
if len(sys.argv) < 2:
    sys.exit('Usage:\n %s IOC' % sys.argv[0])

# Domain Example:
# high.expbas.net
domain = sys.argv[1]


# Investigate Query
UIURL = 'https://investigate.api.umbrella.com/domains/categorization/{}?showLabels'.format(domain)

UIHeaders = {'Authorization': 'Bearer ' + UIToken}
UIQuery = requests.get(UIURL, headers=UIHeaders).json()

print 'Cisco Umbrella Investigate:'

UIStatus = UIQuery[domain]['status']
print '  Status:',
if UIStatus == -1:
	print 'Malicious'
elif UIStatus == 1:
	print 'Safe'
elif UIStatus == 0:
	print 'No Status'

securityCategories = UIQuery[domain]['security_categories']
if len(securityCategories) > 0:
	print '  Security Categories:'
	for category in securityCategories:
		print '    {}'.format(category)


print '\r'

# TG Query
print '\r'
TGURL = 'https://panacea.threatgrid.com/api/v2/search/submissions?state=succ&q={}&api_key={}'.format(domain,TGapiKey)
TGQuery = requests.get(TGURL).json()

TGHighScore = 0

items = TGQuery['data']['items']
for sample in items:
    threat_score = sample['item']['analysis']['threat_score']
    if threat_score > TGHighScore:
    	TGHighScore = threat_score

TGTotal = TGQuery ['data']['current_item_count']

print 'Cisco Threat Grid has {} samples with this IP, the highest score is: {}'.format(TGTotal,TGHighScore)
