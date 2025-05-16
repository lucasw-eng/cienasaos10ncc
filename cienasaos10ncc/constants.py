# namespaces for SAOS 10 native models
NS = {
	"arp": "http://ciena.com/ns/yang/ciena-arp",
	"bfd": "http://ciena.com/ns/yang/ciena-bdf",
	"bgp": "http://ciena.com/ns/yang/ciena-bgp",
	"logical-ports":"urn:ciena:params:xml:ns:yang:ciena-pn::ciena-mef-logical-port",
    "ciena-ext-lag": "urn:ietf:params:xml:ns:yang:ciena-ext-lag",
	"ciena-ieee-lag": "urn:ietf:params:xml:ns:yang:ciena-ieee-lag",
	"classifier": "http://ciena.com/ns/yang/ciena-mef-classifier",
	"classifiers": "urn:ciena:params:xml:ns:yang:ciena-pn::ciena-mef-classifier",
	"classifier-show": "http://ciena.com/ns/yang/ciena-mef-classifier-show",
	"dns-client": "http://ciena.com/ns/yang/ciena-dns-client",
	"fd": "http://ciena.com/ns/yang/ciena-mef-fd",
	"fd-deviation": "http://ciena.com/ns/yang/ciena-mef-fd-deviation",
	"fd-show": "http://ciena.com/ns/yang/ciena-mef-fd-show",
	"fdbs-state": "urn:ciena:params:xml:ns:yang:ciena-pn:ciena-mef-mac-management",
	"fds": "urn:ciena:params:xml:ns:yang:ciena-pn:ciena-mef-fd",
	"fp": "http://ciena.com/ns/yang/ciena-mef-fp",
	"fps": "urn:ciena:params:xml:ns:yang:ciena-pn:ciena-mef-fp",
	"fp-show": "http://ciena.com/ns/yang/ciena-mef-fp-show",
	"interfaces": "http://openconfig.net/yang/interfaces",
	"ipv4": "http://ciena.com/ns/yang/ciena-openconfig-if-ip",
	"isis": "http://ciena.com/ns/yang/ciena-isis",
	"member-ports": "urn:ietf:params:xml:ns:netconf:base:1.0",
	"ospf": "http://ciena.com/ns/yang/ciena-ospf",
	"protection-port": "http://www.ciena.com/ns/yang/ciena-ext-lag",
	"rib": "http://ciena.com/ns/yang/ciena-rip",
	"system": "http://openconfig.net/yang/system",
	"ztp": "http://ciena.com/ns/yang/ciena-ztp"	
}

# GET RPC to retrieve device facts
FACTS_RPC_REQ = """<get xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <filter>
    <set-current-datetime xmlns="http://www.ciena.com/ns/yang/ciena-system">
      <current-datetime />
    </set-current-datetime>
    <system xmlns="http://openconfig.net/yang/system">
      <config>
        <hostname />
        <description />
      </config>
    </system>
  </filter>
</get>
"""

# subtree filter to get flow-points using GET CONFIG RPC
FPS_RPC_REQ_FILTER = """
<mef-fp:fps xmlns:mef-fp="urn:ciena:params:xml:ns:yang:ciena-pn:ciena-mef-fp" />
"""

# subtree filter to get interfaces using GET CONFIG RPC
ETTPS_RPC_REQ_FILTER = """
<interfaces xmlns:ncx="http://netconfcentral.org/ns/yuma-ncx"/>
"""

# subtree filter to get logical-ports using GET CONFIG RPC
LOGICALPORTS_RPC_REQ_FILTER = """
<mef-logical-port:logical-ports xmlns:mef-logical-port="urn:ciena:params:xml:ns:yang:ciena-pn::ciena-mef-logical-port"/>
"""

# subtree filter to get classifiers using GET CONFIG RPC
CLASSIFIERS_RPC_REQ_FILTER = """
<classifiers xmlns="urn:ciena:params:xml:ns:yang:ciena-pn::ciena-mef-classifier">
	<classifier />
</classifiers>
"""

# subtree filter to get MAC entries for a given forarding domain.
FDBS_RPC_REQ_FILTER = """
<fdbs-state xmlns="urn:ciena:params:xml:ns:yang:ciena-pn:ciena-mef-mac-management">
	<fdb>
		<name>{name}</name>
	</fdb>
</fdbs-state>
"""

# subtree filter to get forwarding domains using GET CONFIG RPC
FDS_RPC_REQ_FILTER = """
<mef-fd:fds xmlns:mef-fd="urn:ciena:params:xml:ns:yang:ciena-pn:ciena-
mef-fd"/>
"""

FDS_RPC_REQ_FILTER = """
<mef-fd:fds xmlns:mef-fd="urn:ciena:params:xml:ns:yang:ciena-pn:ciena-mef-fd" />
"""

# subtree filter to get G8032 Ring Data
G8032_LR_RPC_REQ_FILTER = """
<g8032:g8032-rings-state xmlns:g8032="http://www.ciena.com/ns/yang/ciena-itut-g8032-draft"/>
"""

# subtree filter to get system state using GET CONFIG RPC
SYSTEM_STATE_RPC_REQ_FILTER = """
<system xmlns="http://openconfig.net/yang/system"> 
    <state />
</system>
"""

# subtree filter to get system config using GET CONFIG RPC
SYSTEM_CONFIG_RPC_REQ_FILTER = """
<system xmlns="http://openconfig.net/yang/system"> 
    <config />
</system>
"""

# subtree filter to get system mac using GET CONFIG RPC
SYSTEM_MACS_RPC_REQ_FILTER = """
<system xmlns="http://openconfig.net/yang/system"> 
    <macs />
</system>
"""

# subtree filter to get ip interfaces using GET CONFIG RPC
IP_INTERFACES_REQ_FILTER = """
<oc-if:interfaces xmlns:oc-if="http://openconfig.net/yang/interfaces"/>
"""

# subtree filter to get ip interfaces using GET CONFIG RPC
EVPN_INSTANCES_REQ_FILTER = """
<evpn xmlns="http://ciena.com/ns/yang/ciena-evpn" />
"""

# possible encoding values for optional argument "config_encoding"
CONFIG_ENCODINGS = ["cli", "xml"]
