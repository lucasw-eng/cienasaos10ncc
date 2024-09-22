#! /usr/bin/env python
#
# Prompts for username and password and connects to the specified 
# device and displays their capabilities.
#
#
# $ ./test01 <hostname>

import sys, os, warnings, getpass, json
warnings.simplefilter("ignore", DeprecationWarning)
from cienasaos10ncc import saos10_netconf
from pprint import pprint

def get_capabilities(host, user, password):
	netconf_session = saos10_netconf.SAOS10NETCONFDriver(host, user, password)
	netconf_session.open()
	logical_ports = netconf_session.get_logical_ports()
	print(logical_ports)
	netconf_session.create_aggregation("BE5")
	netconf_session.configure_aggregation_interface("5","TEST-AGGREGATION")
	netconf_session.add_aggregation_member("BE5","5")
	logical_ports = netconf_session.get_logical_ports()
	print(logical_ports)
	netconf_session.remove_aggregation_member("BE5","5")
	netconf_session.delete_aggregation("BE5")
	logical_ports = netconf_session.get_logical_ports()
	print(logical_ports)
	netconf_session.close()

if __name__ == '__main__':
	user = input("Username:")
	passwd = getpass.getpass("Password for " + user + ":")
	return_data = get_capabilities(sys.argv[1], user, passwd)
	print(return_data)
