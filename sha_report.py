#
# This is sample code to understand how API works...
# Released under License https://developer.cisco.com/site/license/cisco-sample-code-license/
#
import threatgrid
import umbrella
import sys
import json
import pprint
import ConfigParser
import os
import dns.resolver

if len(sys.argv) == 2:
    sha_256 = sys.argv[1]
    print "ready to go! Getting your report for file: {}...".format(sha_256)
elif len(sys.argv) < 2:
    print "please pass the sha 256 of the file as an agrument"
    sys.exit()
else:
    print "I can only accept one argument, the sha 256 of a file"
    sys.ext()


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

# Investigate Configuration
UIToken = config.get('Investigate', 'token')
UIToken = str.rstrip(UIToken)

# enter api credentials for the corresponding accounts
token = UIToken
api_key = TGapiKey

# intialize both investigate and threatgrid objects
umbrella_investigate = umbrella.investigate(token)
threatgrid_api = threatgrid.tg_account(api_key)

# step one query threatgrid for the sha_256 and extract relevant information
# important info is sample id
# import info is threat_score

samples = threatgrid_api.get("/search/submissions?q={}".format(sha_256))
# dictionary of the samples with their scores and behaviors

#print json.dumps(samples, indent=4, sort_keys=True)
sample_ids = {}
behaviors = []
for sample in samples['data']['items']:
    sample_ids[sample["item"]["sample"]] = sample["item"]["analysis"]["threat_score"]
    for behavior in sample["item"]["analysis"]["behaviors"]:
        behaviors.append(behavior["title"])

# Prepare TG report to screen with average score after number of runs and behavior
behaviors = set(behaviors)

num_of_runs = len(sample_ids)
total = 0
sample_string = ""
for sample, score in sample_ids.iteritems():
    total = total + score
    sample_string = "{}{},".format(sample_string,sample)
average = total/num_of_runs

print "Sample was run {} times and results in an average score of {}".format (num_of_runs, average)
print "Behavior of sample:"
for value in behaviors:
    print value
sample_string = sample_string[:-1]
#print sample_string
# now that we got everything from TG lets take the samples and seach them for all domains
domains = threatgrid_api.get("/samples/feeds/domains?sample={}&after=2017-2-2".format(sample_string))
#build a list of domains for Umbrella
domain_list = []
ip_list = []
for domain in domains["data"]["items"]:
    if domain["relation"] == "dns-lookup":
        for item in domain["data"]["answers"]:
            domain_list.append(domain["domain"])
            ip_list.append(item)

print "\nAssociated domains:\n"
print "\n".join(domain_list)
print "\n samples made outbound connections on following IPs:\n"
print "\n".join(ip_list)
print "Building list for Umbrella"

domain_cat = umbrella_investigate.post("/domains/categorization", domain_list)
#print  domain_cat
for domain, report in domain_cat.iteritems():
    if report["status"] == -1 :
        print "Domain {} scored {} and is blackisted on Umbrella".format(domain, report["status"])
    if report["status"] == 1:
        print "Umbrella Found Domain to Safe!"
    if report["status"] == 0:
        print "Domain {} is un-catgorized and requires further analysis, security report as follows:".format(domain)
        sec_report = umbrella_investigate.get("/security/name/{}".format(domain))
        print json.dumps(sec_report, indent=4, sort_keys=True)
