#! /usr/bin/env python
#
# Prompts for username and password and connects to the specified 
# device and displays their capabilities.
#
#
# $ ./test03 <hostname>

import sys, os, warnings, getpass, json
#warnings.simplefilter("ignore", DeprecationWarning)
from cienasaos10ncc import saos10_netconf
from pprint import pprint

def get_capabilities(host, user, password):
	netconf_session = saos10_netconf.SAOS10NETCONFDriver(host, user, password)
	netconf_session.open()
	ettps = netconf_session.get_ettps()
	netconf_session.close()
	return ettps

if __name__ == '__main__':
	user = input("Username:")
	passwd = getpass.getpass("Password for " + user + ":")
	return_data = get_capabilities(sys.argv[1], user, passwd)
	print(return_data)
