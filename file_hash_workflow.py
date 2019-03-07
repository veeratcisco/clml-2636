#
# This is sample code to understand how API works...
# Released under License https://developer.cisco.com/site/license/cisco-sample-code-license/
#
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

# Validate a parameter was provited
if len(sys.argv) < 2:
    sys.exit('Usage:\n %s IOC' % sys.argv[0])

MD5 = ''
SHA256 = sys.argv[1]

# VT Query
params = {'apikey': VTKey, 'resource': SHA256}
headers = {"Accept-Encoding": "gzip, deflate"}

VTURL = 'https://www.virustotal.com/vtapi/v2/file/report'
VTQuery = requests.get(VTURL, params=params, headers=headers).json()

MD5 = VTQuery['md5']

print 'Virus Total Engine Convictions: {} of {}'.format(VTQuery['positives'],VTQuery['total'])

#TG Query
TGURL = 'https://panacea.threatgrid.com/api/v2/search/submissions?state=succ&q={}&api_key={}'.format(SHA256,TGapiKey)
#print TGURL
TGQuery = requests.get(TGURL).json()

TGHighScore = 0

items = TGQuery['data']['items']
for sample in items:
    threat_score = sample['item']['analysis']['threat_score']
    if threat_score > TGHighScore:
    	TGHighScore = threat_score

TGTotal = TGQuery ['data']['current_item_count']

#for ged in items:
#     behave = sample['item']['analysis']['behaviors']
     

print 'Threat Grid has seen this file {} times, the highest score is: {}'.format(TGTotal,TGHighScore)