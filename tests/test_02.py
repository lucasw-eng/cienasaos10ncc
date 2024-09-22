#! /usr/bin/env python3
#
# Prompts for username and password and connects to the specified 
# device and displays their capabilities.
#
#
# $ ./test02 <hostname>

import sys, os, warnings, getpass, json
warnings.simplefilter("ignore", DeprecationWarning)
from cienasaos10ncc import saos10_netconf

def get_capabilities(host, user, password):
	test = saos10_netconf.SAOS10NETCONFDriver(host, user, password)
	test.open()
	print(json.dumps(test.get_ip_interfaces(),indent=4,sort_keys=True))
	test.close()

if __name__ == '__main__':
	user = input("Username:")
	passwd = getpass.getpass("Password for " + user + ":")
	get_capabilities(sys.argv[1], user, passwd)

