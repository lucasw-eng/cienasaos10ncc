from __future__ import unicode_literals

# import stdlib
import re
import copy
import difflib
import logging
import urllib.parse as urlparse
import xmltodict

# import third party lib
from ncclient import manager
from ncclient.xml_ import to_ele
from ncclient.operations.rpc import RPCError
from ncclient.operations.errors import TimeoutExpiredError
from lxml import etree as ETREE
from lxml.etree import XMLSyntaxError
from jinja2 import Environment, FileSystemLoader

# Import local modules
from cienasaos10ncc import constants as C

logger = logging.getLogger(__name__)

class SAOS10NETCONFDriver():
	""" CIENA SAOS10 NETCONF driver class """

	def __init__(self, hostname, username, password, timeout=60, optional_args=None):
		""" 
		Initialize SAOS 10 driver.

		optional_args:
			* config_log (True/False): lock configuration DB after the 
				connection is established.
			* port (int): custom port
			* key_file (string): SSH key file path
		"""
		self.hostname = hostname
		self.username = username
		self.password = password
		self.timeout = timeout
		self.pending_changes = False
		self.replace = False
		self.locked = False
		if optional_args is None:
			optional_args = {}

		self.port = optional_args.get("port", 22)
		self.lock_on_connect = optional_args.get("config_lock", False)
		self.key_file = optional_args.get("key_file", None)
		#self.config_encoding = optional_args.get("config_encoding", "cli")

		self.platform = "saos10_netconf"
		self.device = None
		self.module_set_ns = []

		self.templateLoader = FileSystemLoader(searchpath="../templates/")
		self.env = Environment(loader = self.templateLoader)

	def open(self):
		"""Open the connection with the device."""
		try:
			self.device = manager.connect(
				host=self.hostname,
				port=self.port,
				ssh_config=True,
				username=self.username,
				password=self.password,
				key_filename=self.key_file,
				device_params={'name':'default'},
				timeout=self.timeout
			)
			if self.lock_on_connect:
				self._lock()
		except Exception as conn_err:
			logger.error(conn_err.args[0])
			print("Connection Error\n")

	def close(self):
		"""Close the connection."""
		logger.debug("Closed connection with device %s" % (self.hostname))
		self._unlock()
		self.device.close_session()

	def _lock(self):
		"""Lock the config DB."""
		if not self.locked:
			self.device.lock()
			self.locked = True

	def _unlock(self):
		"""Unlock the config DB."""
		if self.locked:
			self.device.unlock()
			self.locked = False

	def _find_txt(self, xml_tree, path, default=None, namespaces=None):
		"""
		Extract the text value from a leaf in an XML tree using XPath.

		Will return a default value if leaf path not matched.
		:param xml_tree: the XML Tree object. <type'lxml.etree._Element'>.
		:param path: XPath to be applied in order to extract the desired data.
		:param default: Value to be returned in case of a no match.
		:param namespaces: namespace dictionary.
		:return: a str value or None if leaf path not matched.
		"""
		value = None
		xpath_applied = xml_tree.xpath(path, namespaces=namespaces)
		if xpath_applied:
			if not len(xpath_applied[0]):
				if xpath_applied[0].text is not None:
					value = xpath_applied[0].text.strip()
				else:
					value = ""
		else:
			value = default

		return value

	def _check_response(self, rpc_obj, snippet_name):
		#log.debug("RPCReply for %s is %s" % (snippet_name, rpc_obj.xml))
		xml_str = rpc_obj.xml
		if "<ok/>" in xml_str:
			#log.info("%s successful" % snippet_name)
			return True
		else:
			#log.error("Cannot successfully execute: %s" % snippet_name)
			return False

	def get_server_capabilities(self):
		for cap in self.device.server_capabilities:
			print("Capability:", cap)
			cap_parsed = urlparse.parse_qs(urlparse.urlparse(cap).query)
			if 'module' in cap_parsed:
				module_name = cap_parsed['module'][0]
			else:
				module_name = cap
			print("Retrieving module:", module_name)
			try:
				r = self.device.get_schema(identifier=module_name)
			except Exception as exc:
				print("Failed, doing next..")
				continue

			dx = r._data

			try:
				with open("%s.yang" % module_name, "w") as f:
					f.write(dx)
			except Exception as exc:
				print("CRAAAAAAAAAAAAAAP", exc)
				continue
		return None

	def get_facts(self):
		"""Return facts of the device."""
		facts = {
			"vendor": "Ciena",
			"os_version": "",
			"hostname": "",
			"uptime": -1,
			"serial_number": "",
			"fqdn": "",
			"model": "",
			"interface_list": [],
		}
		interface_list = []

		facts_rpc_reply = self.device.dispatch(to_ele(C.FACTS_RPC_REQ)).xml
		# Converts string to etree
		result_tree = ETREE.fromstring(bytes(facts_rpc_reply, encoding='utf8'))

		# Retrieves hostname
		hostname = self._find_txt(
			result_tree, 
			".//system:system/system:config/system:hostname",
			default="",
			namespaces=C.NS
		)
		facts['hostname'] = hostname
		return facts
	
	def get_ettps(self):
		#Return all ETTP details on the device.
		ettps = {}
		rpc_reply = self.device.get(filter=("subtree",C.ETTPS_RPC_REQ_FILTER)).xml
		# Converts string to etree
		print(rpc_reply)
		result_tree = ETREE.fromstring(bytes(rpc_reply, encoding='utf8'))
		ettp_xpath = ".//interfaces:interfaces/"

		for port in result_tree.xpath(ettp_xpath + "/interfaces:interface", default="", namespaces=C.NS):
			#test = ETREE.tostring(port,encoding="unicode")
			#print(test)
			ettp_name = self._find_txt(port, "./interfaces:name", default="", namespaces=C.NS)
			admin_status = self._find_txt(port, "./interfaces:admin-status", default="", namespaces=C.NS)
			ettps[ettp_name] = []
			for port_state in result_tree.xpath(ettp_xpath + "/interfaces:state", default="", namespaces=C.NS):
				ifindex = self._find_txt(port_state, "./interfaces:ifindex", default="", namespaces=C.NS)
				oper_status = self._find_txt(port_state, "./interfaces:oper-status", default="", namespaces=C.NS)
				last_change = self._find_txt(port_state, "./interfaces:last-change", default="", namespaces=C.NS)
				ettps[ettp_name].append(
					{
					"ifindex": ifindex,
					"oper-status": oper_status,
					"last-change": last_change
					}
				)

		for port_config in result_tree.xpath(ettp_xpath + "/interfaces:config", default="", namespaces=C.NS):
			name = self._find_txt(port_config, "./interfaces:name", default="", namespaces=C.NS)
			# Admin Status is a boolean need to modify _find_txt to account for that.
			admin_status = self._find_txt(port_config, "./interfaces:admin-status", default="", namespaces=C.NS)
			mtu = self._find_txt(port_config, "./interfaces:mtu", default="", namespaces=C.NS)
			description = self._find_txt(port_config, "./interfaces:description", default="", namespaces=C.NS)
			vrf_name = self._find_txt(port_config, "./interfaces:vrfName", default="", namespaces=C.NS)
			ettps[name].append(
				{
				"admin-status": admin_status,
				"mtu": mtu,
				"description": description,
				"vrf": vrf_name
				}
			)

		return ettps

	def get_logical_ports(self):
		#Return all logical port details on the device.
		#init result dict
		logical_ports = {}

		rpc_reply = self.device.get(filter=("subtree",C.LOGICALPORTS_RPC_REQ_FILTER)).xml
		# Converts string to etree
		result_tree = ETREE.fromstring(bytes(rpc_reply, encoding='utf8'))

		lgps_xpath = ".//logical-ports:logical-ports/"

		for port in result_tree.xpath(lgps_xpath + "/logical-ports:logical-port", default="", namespaces=C.NS):
			port_name = self._find_txt(port, "./logical-ports:name", default="", namespaces=C.NS)
			port_admin_state = self._find_txt(port, "./logical-ports:admin-state", default="", namespaces=C.NS)
			port_binding = self._find_txt(port, "./logical-ports:binding", default="", namespaces=C.NS)
			port_mtu = self._find_txt(port, "./logical-ports:mtu", default="", namespaces=C.NS)
			port_description = self._find_txt(port, "./logical-ports:description", default="", namespaces=C.NS)
			# Assign values to the dictionary.
			logical_ports[port_name] = []
			logical_ports[port_name].append(
				{
				"admin-state": port_admin_state,
				"binding": port_binding,
				"mtu": port_mtu,
				"description": port_description
				}
			)
		return logical_ports
    
	def get_forwarding_domains(self):
		""" Return all configured forwarding domains on the device."""
		#init result dict
		forwarding_domains = {}

		rpc_reply = self.device.get(filter=("subtree",C.FDS_RPC_REQ_FILTER)).xml
		# Converts string to etree
		result_tree = ETREE.fromstring(bytes(rpc_reply, encoding='utf8'))

		fds_xpath = ".//fds:fds/"

		for fd in result_tree.xpath(fds_xpath + "/fds:fd", default="", namespaces=C.NS):
			# Parsed return data into variables
			fd_name = self._find_txt(fd, "./fds:name", default="", namespaces=C.NS)
			mode = self._find_txt(fd, "./fds:mode", default="", namespaces=C.NS)
			# Create entry if it doesn't exist in the return dictionary.
			if fd_name not in forwarding_domains.keys():
				forwarding_domains[fd_name] = []
			# Assign values to the dictionary.
			forwarding_domains[fd_name].append(
				{
				"fd-name": fd_name, 
				"mode": mode
				}
			)
		# Return the results found.
		return forwarding_domains

	def get_flow_points(self):
		"""Return all configured flow points on the device."""
		# init result dict
		flow_points = {}

		rpc_reply = self.device.get(filter=("subtree",C.FPS_RPC_REQ_FILTER)).xml
		# Converts string to etree
		result_tree = ETREE.fromstring(bytes(rpc_reply, encoding='utf8'))

		fps_xpath = ".//fps:fps/"

		for fp in result_tree.xpath(fps_xpath + "/fps:fp", default="", namespaces=C.NS):
			fp_name = self._find_txt(fp, "./fps:name", default="", namespaces=C.NS)
			fd_name = self._find_txt(fp, "./fps:fd-name", default="", namespaces=C.NS)
			logical_port = self._find_txt(fp, "./fps:logical-port", default="", namespaces=C.NS)
			mtu_size = int(self._find_txt(fp, "./fps:mtu-size", default="", namespaces=C.NS))
			classifier_list = self._find_txt(fp, "./fps:classifier-list", default="", namespaces=C.NS)
			pfg_group = self._find_txt(fp, "./fps:pfg-group", default="", namespaces=C.NS)
			if fp_name not in flow_points.keys():
				flow_points[fp_name] = []
			flow_points[fp_name].append(
				{
				"fd-name": fd_name, 
				"logical-port": logical_port,
				"mtu-size": mtu_size,
				"classifier-list": classifier_list,
				"pfg-group": pfg_group
				}
			)
		return flow_points

	def get_classifiers(self):
		"""Return all configured classifiers on the device."""
		# init result dict
		classifiers = {}

		rpc_reply = self.device.get(filter=("subtree",C.CLASSIFIERS_RPC_REQ_FILTER)).xml
		#Converts string to etree
		result_tree = ETREE.fromstring(bytes(rpc_reply, encoding='utf8'))
		#print(rpc_reply)

		classifiers_xpath = ".//classifiers:classifiers/"

		for classifier in result_tree.xpath(classifiers_xpath + "/classifiers:classifier", default="", namespaces=C.NS):
			classifier_name = self._find_txt(classifier, "./classifiers:name", default="", namespaces=C.NS)
			if classifier_name not in classifiers.keys():
				classifiers[classifier_name] = []
			vlan_tag = {}
			untagged_frames = False
			filter_parameter = ""
			logical_not = ""
			for child in classifier:
				if (child.tag == "{urn:ciena:params:xml:ns:yang:ciena-pn::ciena-mef-classifier}filter-entry"):
					for filter_entry in child:
						if (filter_entry.tag == "{urn:ciena:params:xml:ns:yang:ciena-pn::ciena-mef-classifier}filter-parameter"):
							filter_parameter = filter_entry.text
						elif (filter_entry.tag == "{urn:ciena:params:xml:ns:yang:ciena-pn::ciena-mef-classifier}logical-not"):
							logical_not = filter_entry.text
						elif (filter_entry.tag == "{urn:ciena:params:xml:ns:yang:ciena-pn::ciena-mef-classifier}untagged-exclude-priority-tagged"):
							untagged_frames = True
						else:
							tag = ""
							tpid = ""
							vlan_id = ""
							for vtags in filter_entry:
								if (vtags.tag == "{urn:ciena:params:xml:ns:yang:ciena-pn::ciena-mef-classifier}tag"):
									tag = vtags.text
									if tag not in vlan_tag.keys():
										vlan_tag[tag] = []
								elif (vtags.tag == "{urn:ciena:params:xml:ns:yang:ciena-pn::ciena-mef-classifier}tpid"):
									tpid = vtags.text
								else:
									vlan_id = vtags.text
									vlan_tag[tag].append(
										{
										"tag": tag,
										"tpid":tpid,
										"vlan-id":vlan_id
										}
									)
			classifiers[classifier_name].append(
				{
				"name": classifier_name,
				"filter_parameter": filter_parameter,
				"logical_not":logical_not,
				"untagged_frames":untagged_frames,
				"vtags":vlan_tag
				}
			)
		return classifiers

	def get_MAC_entries(self,fd_name: str) ->dict:
		""" Returns all MAC Address entries in the MAC table
			for a given forwarding domain.
		"""
		mac_database = {}
		sub_tree = C.FDBS_RPC_REQ_FILTER.format(name=fd_name)
		rpc_reply = self.device.get(filter=("subtree",sub_tree)).xml
		# Converts string to etree
		result_tree = ETREE.fromstring(bytes(rpc_reply, encoding='utf8'))

		mac_dbs_xpath = ".//fdbs-state:fdbs-state/"

		for fdb in result_tree.xpath(mac_dbs_xpath + "/fdbs-state:fdb", default="", namespaces=C.NS):
			# Parsed return data into variables
			fd_name = self._find_txt(fdb, "./fdbs-state:name", default="", namespaces=C.NS)
			mac_learn_count = self._find_txt(fdb, "./fdbs-state:mac-learn-count", default="", namespaces=C.NS)
			absent_mac_learn_count = self._find_txt(fdb, "./fdbs-state:absent-mac-learn-count", default="", namespaces=C.NS)
			# Create entry if it doesn't exist in the return dictionary.
			if fd_name not in mac_database.keys():
				mac_database[fd_name] = []
			for mac_entry in result_tree.xpath(mac_dbs_xpath + "/fdbs-state:mac-entry", default="", namespaces=C.NS):
				mac_address = self._find_txt(mac_entry, "./fdbs-state:mac-address", default="", namespaces=C.NS)
				flow_point = self._find_txt(mac_entry, "./fdbs-state:flow-point", default="", namespaces=C.NS)
				mac_learn_type = self._find_txt(mac_entry, "./fdbs-state:mac-learn-type", default="", namespaces=C.NS)
				mac_database[fd_name].append (
					{
					"mac-address": mac_address,
					"flow-point": flow_point,
					"mac-learn-type": mac_learn_type
					}
				)
		return mac_database

	def get_g8032_rings(self) ->dict:
		"""Returns all G8032 Logical Ring Instances found on the system.
		:return Will return a dictionary of all G8032 Logical Rings.
		"""
		g8032_logical_rings = {}
		rpc_reply = self.device.get(filter=("subtree",C.G8032_LR_RPC_REQ_FILTER)).xml
		temp_dict = xmltodict.parse(rpc_reply)
		temp_dict = temp_dict["rpc-reply"]["data"]
		if "g8032-ring" in temp_dict["g8032-rings-state"].keys():
			g8032_logical_rings[temp_dict["g8032-rings-state"]["g8032-ring"]["ring-name"]] = {}
			g8032_logical_rings[temp_dict["g8032-rings-state"]["g8032-ring"]["ring-name"]]["erp_instances"] = []
			# Must first test to see if any ERP Instances are found.
			if temp_dict["g8032-rings-state"]["g8032-ring"]["erp-instances"] is not None:
				for key,value in temp_dict["g8032-rings-state"]["g8032-ring"]["erp-instances"].items():
					erp_name = value["instance-name"]
					erp_state = value["erps-instance-status"]
					erp_number_of_switchovers = value["number-of-switchovers"]
					# Dictionary to contain all G.8032 Ports
					erp_ports = {}
					erp_ports['port0'] = []
					erp_ports['port1'] = []
					for port_keys, ports in value["ports"].items():
						# For Loop returns a List not a dictionary object so indexes will be integers.
						erp_ports[ports[0]["port-id"]].append(
							{
								"port_status": ports[0]["erps-instance-port-status"],
								"port_state": ports[0]["port-state"]["#text"].replace("g8032:",""),
								"raps_statistics": {
									"rx-raps-fs": ports[0]["raps-statistics"]["rx-raps-fs"],
            		                "rx-raps-nr": ports[0]["raps-statistics"]["rx-raps-nr"],
            		                "rx-raps-nrrb": ports[0]["raps-statistics"]["rx-raps-nrrb"],
            		                "rx-raps-sf": ports[0]["raps-statistics"]["rx-raps-sf"],
            		                "tx-raps-fs": ports[0]["raps-statistics"]["tx-raps-fs"],
            		                "tx-raps-nr": ports[0]["raps-statistics"]["tx-raps-nr"],
            		                "tx-raps-nrrb": ports[0]["raps-statistics"]["tx-raps-nrrb"],
            		                "tx-raps-sf": ports[0]["raps-statistics"]["tx-raps-sf"]
								}
							}
						)
						erp_ports[ports[1]["port-id"]].append(
							{
								"port_status": ports[1]["erps-instance-port-status"],
								"port_state": ports[1]["port-state"]["#text"].replace("g8032:",""),
								"raps_statistics": {
									"rx-raps-fs": ports[1]["raps-statistics"]["rx-raps-fs"],
            		                "rx-raps-nr": ports[1]["raps-statistics"]["rx-raps-nr"],
            		                "rx-raps-nrrb": ports[1]["raps-statistics"]["rx-raps-nrrb"],
            		                "rx-raps-sf": ports[1]["raps-statistics"]["rx-raps-sf"],
            		                "tx-raps-fs": ports[1]["raps-statistics"]["tx-raps-fs"],
            		                "tx-raps-nr": ports[1]["raps-statistics"]["tx-raps-nr"],
            		                "tx-raps-nrrb": ports[1]["raps-statistics"]["tx-raps-nrrb"],
            		                "tx-raps-sf": ports[1]["raps-statistics"]["tx-raps-sf"]
								}
							}
						)
					g8032_logical_rings[temp_dict["g8032-rings-state"]["g8032-ring"]["ring-name"]]["erp_instances"].append(
						{
							"name": erp_name,
							"state": erp_state,
							"number of switch overs": erp_number_of_switchovers,
							"erp_ports": erp_ports
						}
					)
		return g8032_logical_rings

	def get_system_state(self) -> dict:
		""" Returns the full system state of the device (motd,cpu,memory,disk,etc..)
		
		:return Will return a dictionary of all system state data.
		"""
		system_state = {}

		rpc_reply = self.device.get(filter=("subtree",C.SYSTEM_STATE_RPC_REQ_FILTER)).xml
		print(rpc_reply) #Used for debugging purposes
		#Converts string to etree

		return system_state

	def get_system_config(self) -> dict:
		""" Returns the full system state of the device (motd,cpu,memory,disk,etc..)
		
		:return Will return a dictionary of all system state data.
		"""
		system_config = {}
		rpc_reply = self.device.get(filter=("subtree",C.SYSTEM_CONFIG_RPC_REQ_FILTER)).xml
		print(rpc_reply) #Used for debugging purposes
		#Converts string to etree
		return system_config

	def get_system_macs(self) -> dict:
		""" Returns the full system state of the device (motd,cpu,memory,disk,etc..)
		
		:return Will return a dictionary of all system state data.
		"""
		system_macs = {}
		rpc_reply = self.device.get(filter=("subtree",C.SYSTEM_MACS_RPC_REQ_FILTER)).xml
		print(rpc_reply) #Used for debugging purposes
		#Converts string to etree
		return system_macsc

	def get_ip_interfaces(self) -> dict:
		""" Returns a list of IP interfaces and their state from the device.

		:return Will return a dictionary of all IP interface details.
		"""
		ip_interfaces = {}
		rpc_reply = self.device.get(filter=("subtree",C.IP_INTERFACES_REQ_FILTER)).xml
		result_tree = ETREE.fromstring(bytes(rpc_reply, encoding='utf8'))

		interfaces_xpath = ".//interfaces:interfaces/"

		for interface in result_tree.xpath(interfaces_xpath + "/interfaces:interface", default="", namespaces=C.NS):
			# Reset variables
			interface_mtu = "";
			interface_description = "";
			interface_admin_status = "";
			interface_vrf = ""
			interface_oper_status = ""
			interface_last_change = ""
			interface_mac = ""
			interface_dhcpv4 = ""
			interface_dhcpv4_prefix = ""
			interface_dhcpv4_client = ""
			interface_dhcpv6_client = ""
			interface_ipv4_ip = ""
			interface_ipv4_prefix = ""
			interface_ipv4_origin = ""
			interface_in_octets = ""
			interface_out_octets = ""
			interface_in_packets = ""
			interface_out_packets = ""
			interface_in_dropped_pkts = ""
			interface_name = interface.find('interfaces:name', C.NS).text.strip()
			config_node = interface.find('interfaces:config', C.NS)
			state_node = interface.find('interfaces:state', C.NS)
			ipv4_node = interface.find('ipv4:ipv4', C.NS)
			for child_node in config_node:
				if child_node.tag == "{http://openconfig.net/yang/interfaces}mtu":
					interface_mtu = child_node.text.strip()
				elif child_node.tag == "{http://openconfig.net/yang/interfaces}description":
					interface_description = child_node.text.strip()
				elif child_node.tag == "{http://ciena.com/ns/yang/ciena-openconfig-interfaces}admin-status":
					interface_admin_status = child_node.text.strip()
				elif child_node.tag == "{http://ciena.com/ns/yang/ciena-openconfig-interfaces}vrfName":
					interface_vrf = child_node.text.strip()
			for child_node in state_node:
				if child_node.tag == "{http://openconfig.net/yang/interfaces}oper-status":
					interface_oper_status = child_node.text.strip()
				elif child_node.tag == "{http://openconfig.net/yang/interfaces}last-change":
					interface_last_change = child_node.text.strip()
				elif child_node.tag == "{http://ciena.com/ns/yang/ciena-openconfig-interfaces}mac-address":
					interface_mac = child_node.text.strip()
				elif child_node.tag == "{http://ciena.com/ns/yang/ciena-openconfig-interfaces}dhcp-v4-ip":
					interface_dhcpv4 = child_node.text.strip()
				elif child_node.tag == "{http://ciena.com/ns/yang/ciena-openconfig-interfaces}dhcp-v4-prefix-length":
					interface_dhcpv4_prefix = child_node.text.strip()
				elif child_node.tag == "{http://ciena.com/ns/yang/ciena-openconfig-interfaces}dhcp-v4-client":
					interface_dhcpv4_client = child_node.text.strip()
				elif child_node.tag == "{http://ciena.com/ns/yang/ciena-openconfig-interfaces}dhcp-v6-client":
					interface_dhcpv6_client = child_node.text.strip()
				elif child_node.tag == "{http://openconfig.net/yang/interfaces}counters":
					for counter_nodes in child_node:
						if counter_nodes.tag == "{http://openconfig.net/yang/interfaces}in-octets":
							interface_in_octets = counter_nodes.text.strip()
						elif counter_nodes.tag == "{http://openconfig.net/yang/interfaces}out-octets":
							interface_out_octets = counter_nodes.text.strip()
						elif counter_nodes.tag == "{http://ciena.com/ns/yang/ciena-openconfig-interfaces}in-pkts":
							interface_in_packets = counter_nodes.text.strip()
						elif counter_nodes.tag == "{http://ciena.com/ns/yang/ciena-openconfig-interfaces}out-pkts":
							interface_out_packets = counter_nodes.text.strip()
						elif counter_nodes.tag == "{http://ciena.com/ns/yang/ciena-openconfig-interfaces}in-dropped-pkts":
							interface_in_dropped_pkts = counter_nodes.text.strip()
			if ipv4_node is not None:
				for addresses_node in ipv4_node:
					for address_node in addresses_node:
						for address_child_nodes in address_node:
							if address_child_nodes.tag == "{http://ciena.com/ns/yang/ciena-openconfig-if-ip}state":
								for state_address_nodes in address_child_nodes:
									if state_address_nodes.tag == "{http://ciena.com/ns/yang/ciena-openconfig-if-ip}ip":
										interface_ipv4_ip = state_address_nodes.text.strip()
									elif state_address_nodes.tag == "{http://ciena.com/ns/yang/ciena-openconfig-if-ip}prefix-length":
										interface_ipv4_prefix = state_address_nodes.text.strip()
									elif state_address_nodes.tag == "{http://ciena.com/ns/yang/ciena-openconfig-if-ip}origin":
										interface_ipv4_origin = state_address_nodes.text.strip()	
			ip_interfaces[interface_name] = {
				"MTU": interface_mtu,
				"DESCRIPTION": interface_description,
				"MAC": interface_mac,
				"ADMIN-STATUS": interface_admin_status,
				"OPERATING-STATUS": interface_oper_status,
				"LAST-CHANGE": interface_last_change,
				"VRF": interface_vrf,
				"DHCPv4-IP": interface_dhcpv4,
				"DHCPv4-PREFIX": interface_dhcpv4_prefix,
				"DHCPv4-CLIENT-STATUS": interface_dhcpv4_client,
				"DHCPv6-CLIENT-STATUS": interface_dhcpv6_client,
				"COUNTERS": {
					"IN-OCTETS": interface_in_octets,
					"OUT-OCTETS": interface_out_octets,
					"IN-PKTS": interface_in_packets,
					"OUT-PKTS": interface_out_packets,
					"IN-DROPPED-PKTS": interface_in_dropped_pkts
				},
				"IPv4-IP": interface_ipv4_ip,
				"IPv4-PREFIX": interface_ipv4_prefix,
				"IPv4-ORIGIN": interface_ipv4_origin
			}
		return ip_interfaces

	def create_classifier(self, name: str, tagged: bool, 
		vlan_tags: "list of integers", vlan_ids: "list of vlan_ids (integers)", untagged_priority_bit: str) -> bool:
		""" Create a new classifier on SAOS10.
		
		:param name: The name of the classifier
		:param tagged: boolean True if it's an untagged classifier, false if tagged
		:param vlan_tags: A list of vlan tags. Pass empty if untagged classifier
		:param vlan_ids: A list of vlan id's. Pass empty if untagged classifier
		:param untagged_priority_bit "true or false"
		:return Will return True on Success and False on Failure.
		"""
		#try:
		if tagged:
			for index,tag in enumerate(vlan_tags):
				classifier_template = self.env.get_template("classifier.xml")
				classifier_rendered = classifier_template.render(
					C_DELETE=False,
					CLASSIFIER_NAME=name,
					TAGGED=tagged,
					VLAN_TAG=tag,
					VLAN_ID=vlan_ids[index],
					UNTAGGED_PRIORITY_BIT=untagged_priority_bit
				)
				rpc_reply = self.device.edit_config(target="running", config=classifier_rendered, default_operation = "merge")
				if not self._check_response(rpc_reply, "CREATE_TAGGED_CLASSIFIER"):
					return False
		else:
			classifier_template = self.env.get_template("classifier.xml")
			classifier_rendered = classifier_template.render(
				C_DELETE=False,
				CLASSIFIER_NAME=name,
				TAGGED=tagged,
				VLAN_TAG=1,
				VLAN_ID=0,
				UNTAGGED_PRIORITY_BIT=untagged_priority_bit
			)
			rpc_reply = self.device.edit_config(target="running", config=classifier_rendered, default_operation = "merge")
			if not self._check_response(rpc_reply, "CREATE_TAGGED_CLASSIFIER"):
				return False
		return True

	def create_forwarding_domain(self, name: "str", mode: str) -> bool:
		""" Create a forwarding domain on SAOS10

		:param name: The name of the forwarding domain
		:param mode: One of the following (evpn-vpls, evpn-vpws, fxc, tdm-vpws, vlan, vpls, vpws)
		:return Will return True on Success and False on Failure.
		"""
		fd_template = self.env.get_template("forwarding_domain.xml")
		fd_rendered = fd_template.render(
			FD_DELETE=False,
			FD_NAME=name,
			FD_MODE=mode
		)
		rpc_reply = self.device.edit_config(target="running", config=fd_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "CREATE_FORWARDING_DOMAIN"):
			return False
		return True

	def create_aggregation(self, name: str) -> bool:
		""" Create an aggregation on SAOS10

		:param name: The name of the LACP aggregation to build
		:return Will return True on Success and False on Failure.
		"""
		aggregation_template = self.env.get_template("aggregation_interface.xml")
		aggregation_rendered = aggregation_template.render(
			AGG_DELETE=False,
			AGG_NAME=name
		)
		rpc_reply = self.device.edit_config(target="running", config=aggregation_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "CREATE_AGGREGATION_INTERFACE"):
			return False
		return True

	def configure_aggregation_interface (self, interface_name: str, interface_description: str) -> bool:
		""" Create an aggregation on SAOS10

		:param interface_name: The interface to configure LACP parameters.
		:param interface_description: The description to set on the interface
		:return Will return True on Success and False on Failure.
		"""
		configure_aggregation_interface = self.env.get_template("interface_aggregation_config.xml")
		configure_aggregation_interface_rendered = configure_aggregation_interface.render(
			INT_NAME=interface_name,
			INT_DESCRIPTION=interface_description
		)
		rpc_reply = self.device.edit_config(target="running", config=configure_aggregation_interface_rendered, default_operation="merge")
		if not self._check_response(rpc_reply, "CONFIGURE_AGGREGATION_INTERFACE"):
			return False
		return True

	def add_aggregation_member(self, name: str, interface_name: str) -> bool:
		""" Add an interface to an aggregation port on SAOS10

		:param name: The name of the aggregation to add the interface to.
		:param interface_name: The name of the interface that will be added to the aggregation.
		:return Will return True on success and False on failure.
		"""
		add_aggregation_template = self.env.get_template("add_aggregation_member.xml")
		add_aggregation_rendered = add_aggregation_template.render(
			AGG_NAME=name,
			MEMBOR_REMOVE=False,
			PORT=interface_name
		)
		rpc_reply = self.device.edit_config(target="running", config=add_aggregation_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "ADD_AGGREGATION_INTERFACE"):
			return False
		return True

	def create_flow_point(self, name: str, forwarding_domain: str, logical_port: str, classifier_list: str) -> bool:
		""" Creates a flow point on SAOS10.

		:param name: The name of the flow-point being created
		:param forwarding_domain: The forwarding domain the flow_point will attach to
		:param logical_port: The physical interface the flow point is attached to
		:param classifier_list: The classifiers the flow point matches
		:return Will return True on Success and False on Failure.
		"""
		fp_template = self.env.get_template("flow_point.xml")
		fp_rendered = fp_template.render(
			FP_DELETE=False,
			FP_NAME=name,
			FD_NAME=forwarding_domain,
			LOGICAL_PORT=logical_port,
			CLASSIFIER_NAME=classifier_list
		)
		rpc_reply = self.device.edit_config(target="running", config=fp_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "CREATE_FLOW_POINT"):
			return False
		return True

	def add_egress_transform_flow_point(self, name: str, vlan_tag: int, action: str, vlan_id: int) -> bool:
		""" Modifies a flow_point and adds an egress_l2_transform modifier

		:param name: The name of the flow_point
		:param push_vid: The vlan to push onto frames egressing out of the flow_point
		:return Will return True on Success and False on Failure.
		"""
		egress_l2_transform_template = self.env.get_template("egress_l2_transform.xml")
		egress_l2_rendered = egress_l2_transform_template.render(
			FP_NAME=name,
			VLAN_TAG=vlan_tag,
			action=action,
			VLAN_ID=vlan_id
		)
		rpc_reply = self.device.edit_config(target="running", config=egress_l2_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "ADD_EGRESS_L2_TRANSFORM"):
			return False
		return True

	def add_ingress_transform_flow_point(self, name: str, vlan_tag: int, action: str, vlan_id: int) -> bool:
		""" Modifies a flow_point and adds an ingress_l2_transform modifier

		:param name: The name of the flow_point
		:param vlan-tag: The vlan tag position to modify 1 being the outer most
		:param action: The action to perform (push,stamp, or pop)
		:param vlan_id: The vlan id to push/stamp, if pop action this should be '0'
		:return Will return True on Success and False on Failure.
		"""
		ingress_l2_transform_template = self.env.get_template("ingress_l2_transform.xml")
		ingress_l2_rendered = ingress_l2_transform_template.render(
			FP_NAME=name,
			VLAN_TAG=vlan_tag,
			action=action,
			VLAN_ID=vlan_id
		)
		rpc_reply = self.device.edit_config(target="running", config=ingress_l2_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "ADD_INGRESS_L2_TRANSFORM"):
			return False
		return True

	def create_l3_interface(self, name: str, fd_name: str, ip_address: str, prefix_length: str, vrf_name: str="default") -> bool:
		""" Create an L3 data interface 

		:param name: The name of the L3 interface
		:param fd_name: The name of the forwarding domain the L3 interface will be attached to
		:param vrf_name: The name of the VRF the L3 interface will be attached to. Default is 'default'
		:param ip_address: The IP address associated with the L3 interface
		:param prefix_length: The prefix length of the IP address in CIDR notation
		:return Will return True on success and False on failure.
		"""
		l3_interface_template = self.env.get_template("interfaces.xml")
		l3_interface_rendered = l3_interface_template.render(
			INTERFACE_NAME=name,
			FD_NAME=fd_name,
			VRF_NAME=vrf_name,
			IP_ADDRESS=ip_address,
			PREFIX_LENGTH=prefix_length
		)
		rpc_reply = self.device.edit_config(target="running", config=l3_interface_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "CREATE L3 INTERFACE"):
			return False
		return True

	def create_loopback_interface(self, name: str, ip_address: str, prefix_length: int=32, vrf_name: str="default") -> bool:
		""" Create a Loopback interface

		:param name: The name of the loopback interface
		:param ip_address: The IP Address for the loopback
		:param prefix_length: The prefix length in cidr notation for the IP address (default: 32)
		:return Will return True on success and False on failure.
		"""
		loopback_interface_template = self.env.get_template("loopback.xml")
		loopback_interface_rendered = loopback_interface_template.render(
			LOOPBACK_NAME=name,
			VRF_NAME=vrf_name,
			IP_ADDRESS=ip_address,
			PREFIX_LENGTH=prefix_length
		)
		rpc_reply = self.device.edit_config(target="running", config=loopback_interface_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "CREATE LOOPBACK INTERFACE"):
			return False
		return True

	def configure_authentication_group(self, name: str, server_list: "List of server IP addresses", secret_key: str,
		auth_port: int=1812, acct_port: int=1813, retransmit_interval: int=3, server_type: str="RADIUS") -> bool:
		""" Performs all the necessary steps to create an authentication group and attached
			servers to the group.

		:param name: The name of the server group
		:param type: The type of server (RADIUS, TACACS, RADSEC ; default: RADIUS)
		:param server_list: A list of server IP's or FQDN's
		:param auth_port: The authentication port to use (default: )
		:param acct_port: The accounting port to use (default: )
		:param retransmit_interval: The maximum number of retries 0-3 (default: 3)
		:param secret_key: The password/key to use to authorize requests to the server
		:return Will return True on Success and False on failure.
		"""
		# First create the server group
		server_group_template = self.env.get_template("server_group.xml")
		server_group_rendered = server_group_template.render(
			GROUP_NAME=name,
			GROUP_TYPE=server_type,
		)
		rpc_reply = self.device.edit_config(target="running", config=server_group_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "CREATE SERVER GROUP"):
			return False
		# Now add the servers to the group
		add_server_group_template = self.env.get_template("add_server_to_server_group.xml")
		add_server_group_rendered = add_server_group_template.render(
			GROUP_NAME=name,
			SERVER_LIST=server_list,
		)
		rpc_reply = self.device.edit_config(target="running", config=add_server_group_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "ADD SERVER TO GROUP"):
			return False
		# Now configure the servers with the radius key and ports to use
		config_server_group_template = self.env.get_template("config_server.xml")
		config_server_group_rendered = config_server_group_template.render(
			GROUP_NAME=name,
			SERVER_LIST=server_list,
			SERVER_TYPE=server_type.lower(),
			ACCT_PORT=acct_port,
			AUTH_PORT=auth_port,
			RETRANSMIT_ATTEMPTS=retransmit_interval,
			SECRET_KEY=secret_key
		)
		rpc_reply = self.device.edit_config(target="running", config=config_server_group_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "CONFIGURE SERVERS"):
			return False
		return True

	def set_authentication_method(self, method_list: list[str]) -> bool:
		""" Set the authentication method configuration

		:param method_list: A list of strings containing the different authentication method (MUST MATCH SERVER GROUP Names or default alias's)
		:return Will return True on Success and False on failure.
		"""
		auth_method_template = self.env.get_template("authentication_method.xml")
		auth_method_rendered = auth_method_template.render(
			AUTHENTICATION_METHOD=method_list
		)
		rpc_reply = self.device.edit_config(target="running", config=auth_method_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "SET AUTHENTICATION METHOD"):
			return False
		return True

	def enable_g8032(self) -> bool:
		""" Enabled G8032 and configured notifications

		:return Will return True on Success and False on Failure.
		"""
		g8032_conf = C.ENABLE_G8032
		rpc_reply = self.device.edit_config(target = "running", config = g8032_conf, default_operation = "merge")
		if not self._check_response(rpc_reply, "ENABLE_G8032"):
			return False
		return True

	def create_g8032_logicalRing(self, name: str, ring_id: int, port0: int, port1: int) -> bool:
		""" Creates a G8032 Logical Ring

		:param name: The name of the Logical Ring
		:param port0: The west port of the Logical Ring
		:param port1: The east port of the Logical Ring
		:return Will return True on Success and False on Failure
		"""
		g8032_conf = C.CREATE_G8032_LOGICAL_RING % (name, ring_id, port0, port1)
		rpc_reply = self.device.edit_config(target="running", config=g8032_conf, default_operation = "merge")
		if not self._check_response(rpc_reply, "CREATE_G8032_LOGICAL_RING"):
			return False
		return True

	def create_g8032_virtualRing(self, lr_name: "Logical Ring Name", vr_name: "Virtual Ring Name", raps_vid: int, 
		raps_lvl: int, data_members: "comma separated string of virtual switch names", rpl_port0: str, rpl_port1: str) -> bool:
		""" Creates a G8032 Logical Ring

		:param lr_name: The name of the Logical Ring
		:param vr_name: The name of the Virtual Ring 
		:param raps_vid: The vlan id for RAPS communication
		:param raps_lvl: The RAPS level settings (default '2')
		:param data_members: A comma separated string of virtual switch names that will be protected by the ring
		:param rpl_port0: Either none,rpl_owner, or
		:param rpl_port1: Either none,rpl_owner, or
		:return Will return True on Success and False on Failure
		"""
		g8032_conf = C.CREATE_G8032_VIRTUAL_RING % (lr_name, vr_name, raps_vid, raps_lvl, data_members, rpl_port0, rpl_port1)
		rpc_reply = self.device.edit_config(target="running", config=g8032_conf, default_operation = "merge")
		if not self._check_response(rpc_reply, "CREATE_G8032_LOGICAL_RING"):
			return False
		return True

	def create_isis_instance(self, tag: str, net_id: str, passive_interface: str, level_type: str="level-1", 
		segment_routing: bool=True) -> bool:
		""" Create an ISIS Instance 

		:param tag The instance tag for the ISIS process
		:param net_id The NET ID for the ISIS process
		:param level_type The ISIS area type either level-1,level-2, or level-1-2 (default: level-1)
		:param passive_interface Add a single interface into the ISIS process in passive mode
		:param segment_routing True if this ISIS instance should have SR enabled False otherwise (default: True)
		:param router_id The router id to use for the MPLE-TE/SR ISIS process.
		:param lower_bound The SRGB lower bound for ISIS-SR labels (default: 16000)
		:param upper_bound The SRGB upper bound for ISIS-SR labels (default: 23999)
		:return Will return True on Success and False on Failure
		"""
		isis_instance_template = self.env.get_template("isis_instance.xml")
		isis_instance_rendered = isis_instance_template.render(
			OPERATION_DELETE=False,
			INSTANCE_TAG=tag,
			NET_ID=net_id,
			LEVEL_TYPE=level_type,
			PASSIVE_INTERFACE=passive_interface,
			SR=segment_routing
		)
		rpc_reply = self.device.edit_config(target="running", config=isis_instance_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "CREATING ISIS INSTANCE"):
			return False
		return True

	def add_isis_interface(self, tag: str, interface_name: str, interface_type: str="point-to-point", level_type: str="level-1", 
		hold_down_timer: str="infinite", authentication: bool=False, password: str="") -> bool:
		""" Enable ISIS peering on an interface

		:param tag The instance tag for the ISIS process
		:param interface_name The interface to enable ISIS on
		:param interface_type Specify network type (broadcast, unicast, point-to-point ; default: point-to-point)
		:param level_type The ISIS level type (default: level-1)
		:return Will return True on Success and False on Failure
		"""
		isis_interface_template = self.env.get_template("isis_interface.xml")
		isis_interface_rendered = isis_interface_template.render(
			OPERATION_DELETE=False,
			INSTANCE_TAG=tag,
			INTERFACE_NAME=interface_name,
			INTERFACE_TYPE=interface_type,
			LEVEL_TYPE=level_type,
			HOLD_DOWN_TIMER=hold_down_timer,
			AUTHENTICATION=authentication,
			PASSWORD=password
		)
		rpc_reply = self.device.edit_config(target="running", config=isis_interface_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "ADD ISIS INSTANCE"):
			return False
		return True

	def create_bgp_instance(self, asn: str, router_id: str) -> bool:
		""" Create a BGP Instance

		:param asn: The autonomous system number for the BGP instance
		:param router_id: The router identifier to use for BGP
		:return Will return True on success and False on failure.
		"""
		bgp_instance_template = self.env.get_template("bgp.xml")
		bgp_instance_rendered = bgp_instance_template.render(
			OPERATION_DELETE=False,
			ASN=asn,
			ROUTER_ID=router_id
		)
		rpc_reply = self.device.edit_config(target="running", config=bgp_instance_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "CREATE BGP INSTANCE"):
			return False
		return True

	def add_bgp_peer(self, asn: str, router_id: str, peer_address: str, remote_as: str, rr_client: bool=True, update_source_interface: str="loopback1") -> bool:
		""" Add a BGP Peer to an existing BGP Process

		:param asn: The autonomous system number for the BGP instance
		:param router_id: The router identifier to use for BGP
		:param peer_address: The IP address of the BGP peer
		:param remote_as: The peer's ASN
		:param rr_client: Whether the peer is a route reflector client.
		:param update_source_interface: The interface to use for update messages (default: loopback1)
		:return Will return True on success and False on failure.
		"""
		bgp_peer_template = self.env.get_template("bgp_peer_evpn.xml")
		bgp_peer_rendered = bgp_peer_template.render(
			OPERATION_DELETE=False,
			RR_client=rr_client,
			ASN=asn,
			ROUTER_ID=router_id,
			PEER_ADDRESS=peer_address,
			REMOTE_AS=remote_as,
			UPDATE_SOURCE_INTERFACE=update_source_interface
		)
		rpc_reply = self.device.edit_config(target="running", config=bgp_peer_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "ADD BGP PEER"):
			return False
		return True

	def create_evpn_instance(self, evpn_instance_id: int, forwarding_domain: str, local_service_id: int, 
		remote_service_id: int, route_target: str, custom_rd: bool=False, rd_value: str="") -> bool:
		""" Creates an EVPN Instance

		:param evpn_instance_id: The EVPN instance identifier
		:param forwarding_domain: The forwarding domain the EVPN instance will attach to
		:param local_service_id: The local service identifier to use for this instance
		:param remote_service_id: The remote service identier for this instance
		:param route_target: The route target to use for this service
		:param custom_rd: Specifies whether a custom RD will be defined or not (default: False)
		:param rd_value: If custom_rd is set then the evpn instance will use this value for the RD
		:return Will return True on success and False on failure.
		"""
		evpn_instance_template = self.env.get_template("evpn_instance.xml")
		evpn_instance_rendered = evpn_instance_template.render(
			OPERATION_DELETE=False,
			EVPN_INSTANCE_ID=evpn_instance_id,
			EVPN_FORWARDING_DOMAIN=forwarding_domain,
			LOCAL_SERVICE_ID=local_service_id,
			REMOTE_SERVICE_ID=remote_service_id,
			ROUTE_TARGET=route_target,
			RD=custom_rd,
			ROUTE_DISTINGUISHER=rd_value
		)
		rpc_reply = self.device.edit_config(target="running", config=evpn_instance_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "CREATE EVPN INSTANCE"):
			return False
		return True

	def set_ethernet_segment(self, name: str, logical_port: str, es_type: str="MAC", mac_address: str="00:00:00:00:00:00", 
		es_id: str="bb:22:33:44:55:66:77:88:99") -> bool:
		""" Manually specifies the ES ID (not required on single-homed services)

		:param name The name of the ethernet segment
		:param logical_port The logical port the ethernet segment applies to
		:param es_type The type of ethernet-segment-identifier values are mac based or arbitrary (default: MAC)
		:param mac_address The MAC Address to use (default: "00:00:00:00:00:00")
		:param es_id If using arbitrary then it must be an 9-octect hex string (default: "bb:22:33:44:55:66:77:88:99")
		:return Will return True on success and False on failure.
		"""
		ethernet_segment_template = self.env.get_template("ethernet_segment.xml")
		ethernet_segment_rendered = ethernet_segment_template.render(
			ETHERNET_SEGMENT_NAME=name,
			LOGICAL_PORT=logical_port,
			ES_TYPE=es_type,
			MAC_ADDRESS=mac_address,
			ES_ID=es_id
		)
		rpc_reply = self.device.edit_config(target="running", config=ethernet_segment_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "SET ETHERNET SEGMENT"):
			return False
		return True

	def delete_classifier(self, name: str) -> bool:
		""" Deletes a classifier on SAOS10 devices.

		:param name: The name of the classifier
		:return Will return True on success and False on failure.
		"""
		classifier_template = self.env.get_template("classifier.xml")
		classifier_rendered = classifier_template.render(
			C_DELETE=True,
			CLASSIFIER_NAME=name
		)
		rpc_reply = self.device.edit_config(target="running", config=classifier_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "DELETE_CLASSIFIER"):
			return False
		return True

	def delete_flow_point(self, name: str) -> bool:
		""" Delete a flow point on SAOS10 devices.

		:param name: The name of the flow point
		:return Will return True on success and False on Failure.
		"""
		fp_template = self.env.get_template("flow_point.xml")
		fp_rendered = fp_template.render(
			FP_DELETE=True,
			FP_NAME=name
		)
		rpc_reply = self.device.edit_config(target = "running", config = fp_rendered, default_operation = "none")
		if not self._check_response(rpc_reply, "DELETE_FLOW_POINT"):
			return False
		return True

	def delete_forwarding_domain(self, name:str) -> bool:
		""" Deletes a forwarding domain on SAOS10

		:param name: The name of the forwarding domain
		:return Will return True on Success and False on Failure.
		"""
		fd_template = self.env.get_template("forwarding_domain.xml")
		fd_rendered = fd_template.render(
			FD_DELETE=True,
			FD_NAME=name
		)
		rpc_reply = self.device.edit_config(target="running", config=fd_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "DELETE_FORWARDING_DOMAIN"):
			return False
		return True

	def delete_aggregation(self, name: str) -> bool:
		""" Delete an aggregation on SAOS10

		:param name: The name of the LACP aggregation to build
		:return Will return True on Success and False on Failure.
		"""
		aggregation_template = self.env.get_template("aggregation_interface.xml")
		aggregation_rendered = aggregation_template.render(
			AGG_DELETE=True,
			AGG_NAME=name
		)
		rpc_reply = self.device.edit_config(target="running", config=aggregation_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "DELETE_AGGREGATION_INTERFACE"):
			return False
		return True

	def remove_aggregation_member(self, name: str, interface_name: str) -> bool:
		""" Add an interface to an aggregation port on SAOS10

		:param name: The name of the aggregation to add the interface to.
		:param interface_name: The name of the interface that will be added to the aggregation.
		:return Will return True on success and False on failure.
		"""
		add_aggregation_template = self.env.get_template("add_aggregation_member.xml")
		add_aggregation_rendered = add_aggregation_template.render(
			AGG_NAME=name,
			MEMBOR_REMOVE=True,
			PORT=interface_name
		)
		rpc_reply = self.device.edit_config(target="running", config=add_aggregation_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "REMOVE_AGGREGATION_INTERFACE"):
			return False
		return True

	def delete_g8032_logicalRing(self, name: str) -> bool:
		""" Deletes a G8032 Logical Ring

		:param name: The name of the Logical Ring
		:return Will return True on Success and False on Failure
		"""
		g8032_conf = C.DELETE_G8032_LOGICAL_RING % (name)
		rpc_reply = self.device.edit_config(target="running", config=g8032_conf, default_operation = "merge")
		if not self._check_response(rpc_reply, "DELETE_G8032_LOGICAL_RING"):
			return False
		return True

	def delete_g8032_virtualRing(self, lr_name: "Logical Ring name", vr_name: "Virtual Ring Name") -> bool:
		""" Deletes a G8032 ERP Construct (Virtual Ring)

		:param lr_name: The Logical Ring name the ERP construct is attached to
		:param vr_name: The Virtual Ring name 
		:return Will return True on success and False on failure.
		"""
		g8032_conf = C.DELETE_G8032_VIRTUAL_RING % (lr_name, vr_name)
		rpc_reply = self.device.edit_config(target="running", config=g8032_conf, default_operation = "merge")
		if not self._check_response(rpc_reply, "DELETE_G8032_VIRTUAL_RING"):
			return False
		return True

	def delete_isis_instance(self, isis_instance_name:str) -> bool:
		""" Deletes an ISIS instance

		:param isis_instance_name: The name/tag of the ISIS instance
		:return Will return True on success and False on failure.
		"""
		isis_template = self.env.get_template("isis_instance.xml")
		isis_rendered = isis_template.render(
			OPERATION_DELETE=True,
			INSTANCE_TAG=isis_instance_name
		)
		rpc_reply = self.device.edit_config(target="running", config=isis_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "DELETE_ISIS_INSTANCE"):
			return False
		return True

	def delete_isis_interface(self, isis_instance_name: str, interface_name: str) -> bool:
		""" Delete an interface from the ISIS process

		:param isis_instance_name: The name/tag of the ISIS instance.
		:param interface_name: The interface to remove from the ISIS process.
		:return Will return True on success and False on failure.
		"""
		isis_interface_template = self.env.get_template("isis_interface.xml")
		isis_rendered = isis_interface_template.render(
			OPERATION_DELETE=True,
			INSTANCE_TAG=isis_instance_name,
			INTERFACE_NAME=interface_name
		)
		rpc_reply = self.device.edit_config(target="running", config=isis_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "DELETE_ISIS_INTERFACE"):
			return False
		return True

	def delete_bgp_instance(self, bgp_asn: str) -> bool:
		""" Deletes a BGP Process

		:param bgp_asn: The BGP Process ASN
		:return Will return True on success and False on failure.
		"""
		bgp_template = self.env.get_template("bgp.xml")
		bgp_rendered = bgp_template.render(
			OPERATION_DELETE=True,
			ASN=bgp_asn
		)
		rpc_reply = self.device.edit_config(target="running", config=bgp_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "DELETE_BGP_INSTANCE"):
			return False
		return True

	def delete_bgp_peer(self, bgp_asn: str, router_id: str, peer_address: str) -> bool:
		""" Deletes a BGP Peer

		:param bgp_asn: The BGP Process ASN
		:param router_id: The router id for the BGP Process
		:param peer_address: The peer address IP to delete
		:return Will return True on success and False on failure.
		"""
		bgp_peer_template = self.env.get_template("bgp_peer_evpn.xml")
		bgp_peer_rendered = bgp_peer_template.render(
			OPERATION_DELETE=True,
			ASN=bgp_asn,
			ROUTER_ID=router_id,
			PEER_ADDRESS=peer_address
		)
		rpc_reply = self.device.edit_config(target="running", config=bgp_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "DELETE_BGP_INSTANCE"):
			return False
		return True

	def delete_evpn_instance(self, evpn_instance_id: int) -> bool:
		""" Deletes an EVPN Instance 

		:param evpn_instance_id: The EVPN instance ID to be deleted.
		:return Will return True on success and False on failure.
		"""
		evpn_instance_template = self.env.get_template("evpn_instance.xml")
		evpn_instance_rendered = evpn_instance_template.render(
			OPERATION_DELETE=True,
			EVPN_INSTANCE_ID=evpn_instance_id
		)
		rpc_reply = self.device.edit_config(target="running", config=evpn_instance_rendered, default_operation = "merge")
		if not self._check_response(rpc_reply, "CREATE EVPN INSTANCE"):
			return False
		return True
