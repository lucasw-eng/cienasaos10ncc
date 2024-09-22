#! /usr/bin/env python
#
# Prompts for username and password and connects to the specified 
# device and displays their capabilities.
#
#
# $ ./mac_test <hostname> <forwarding_domain>

import sys, os, warnings, getpass, json
warnings.simplefilter("ignore", DeprecationWarning)
from cienasaos10ncc import saos10_netconf
from pprint import pprint

def get_MACS(host, forwarding_domain, user, password):
	netconf_session = saos10_netconf.SAOS10NETCONFDriver(host, user, password)
	netconf_session.open()
	mac_fdbs = netconf_session.get_MAC_entries(forwarding_domain)
	netconf_session.close()
	return mac_fdbs

if __name__ == '__main__':
	user = input("Username:")
	passwd = getpass.getpass("Password for " + user + ":")
	return_data = get_MACS(sys.argv[1], sys.argv[2], user, passwd)
	print(return_data)
