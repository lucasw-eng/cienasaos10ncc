#! /usr/bin/env python3
#
# Prompts for username and password and connects to the specified 
# device and displays their capabilities.
#
#
# $ ./test01 <hostname>

import sys, os, warnings, getpass, json
warnings.simplefilter("ignore", DeprecationWarning)
from cienasaos10ncc import saos10_netconf

def get_capabilities(host, user, password):
	test = saos10_netconf.SAOS10NETCONFDriver(host, user, password)
	test.open()
	print(json.dumps(test.get_classifiers(),indent=4,sort_keys=True))
	test.create_classifier("TEST-C",True,[1],[3000],"false")
	print(json.dumps(test.get_classifiers(),indent=4,sort_keys=True))
	print(json.dumps(test.get_forwarding_domains(),indent=4,sort_keys=True))
	test.create_forwarding_domain("TEST-FD", "vpls")
	print(json.dumps(test.get_forwarding_domains(),indent=4,sort_keys=True))
	print(json.dumps(test.get_flow_points(),indent=4,sort_keys=True))
	test.create_flow_point("TEST-FP","TEST-FD",10,"TEST-C")
	print(json.dumps(test.get_flow_points(),indent=4,sort_keys=True))
	test.delete_flow_point("TEST-FP")
	print(json.dumps(test.get_flow_points(),indent=4,sort_keys=True))
	test.delete_forwarding_domain("TEST-FD")
	print(json.dumps(test.get_forwarding_domains(),indent=4,sort_keys=True))
	test.delete_classifier("TEST-C")
	print(json.dumps(test.get_classifiers(),indent=4,sort_keys=True))
	test.close()

if __name__ == '__main__':
	user = input("Username:")
	passwd = getpass.getpass("Password for " + user + ":")
	get_capabilities(sys.argv[1], user, passwd)

