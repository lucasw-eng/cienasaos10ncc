# namespaces for SAOS 10 native models
NS = {
	"arp": "http://ciena.com/ns/yang/ciena-arp",
	"bfd": "http://ciena.com/ns/yang/ciena-bdf",
	"bgp": "http://ciena.com/ns/yang/ciena-bgp",
	"classifier": "http://ciena.com/ns/yang/ciena-mef-classifier",
	"classifiers": "urn:ciena:params:xml:ns:yang:ciena-pn::ciena-mef-classifier",
	"classifier-show": "http://ciena.com/ns/yang/ciena-mef-classifier-show",
	"dns-client": "http://ciena.com/ns/yang/ciena-dns-client",
	"fd": "http://ciena.com/ns/yang/ciena-mef-fd",
	"fd-deviation": "http://ciena.com/ns/yang/ciena-mef-fd-deviation",
	"fd-show": "http://ciena.com/ns/yang/ciena-mef-fd-show",
	"fds": "urn:ciena:params:xml:ns:yang:ciena-pn:ciena-mef-fd",
	"fp": "http://ciena.com/ns/yang/ciena-mef-fp",
	"fps": "urn:ciena:params:xml:ns:yang:ciena-pn:ciena-mef-fp",
	"fp-show": "http://ciena.com/ns/yang/ciena-mef-fp-show",
	"interfaces": "http://openconfig.net/yang/interfaces",
	"ipv4": "http://ciena.com/ns/yang/ciena-openconfig-if-ip",
	"isis": "http://ciena.com/ns/yang/ciena-isis",
	"ospf": "http://ciena.com/ns/yang/ciena-ospf",
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

# subtree filter to get classifiers using GET CONFIG RPC
CLASSIFIERS_RPC_REQ_FILTER = """
<classifiers xmlns="urn:ciena:params:xml:ns:yang:ciena-pn::ciena-mef-classifier">
	<classifier />
</classifiers>
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

# Enabled G8032 globally and enabled notifications globally for the protocol
ENABLE_G8032 = """
<config>
	<g8032-rings xmlns="http://www.ciena.com/ns/yang/ciena-itut-g8032-draft" xmlns:ncx="http://netconfcentral.org/ns/yuma-ncx"> 
		<ring-system-control>enabled</ring-system-control> 
		<notification-enabled>true</notification-enabled>
		<raps-version xmlns:g8032="http://www.ciena.com/ns/yang/ciena-itut-g8032-draft">g8032-version1</raps-version> 
	</g8032-rings>
</config>
"""

# EDIT-CONFIG RPC for creating a G.8032 Logical Ring
CREATE_G8032_LOGICAL_RING = """
<config>
	<g8032-rings xmlns="http://www.ciena.com/ns/yang/ciena-itut-g8032-draft" xmlns:ncx="http://netconfcentral.org/ns/yuma-ncx"> 
		<g8032-ring>
      <ring-name>%s</ring-name>
      <ring-id>%d</ring-id>
      <ring-ports>
				<ring-port>
					<port-id>port0</port-id>
          <interface>%s</interface>
        </ring-port>
        <ring-port>
          <port-id>port1</port-id>
          <interface>%s</interface>
        </ring-port>
      </ring-ports>
    </g8032-ring>
  </g8032-rings>
</config>
"""

# EDIT-CONFIG RPC for creating a G.8032 Virtual Ring Instance
CREATE_G8032_VIRTUAL_RING = """
<config>
	<g8032-rings xmlns="http://www.ciena.com/ns/yang/ciena-itut-g8032-draft" xmlns:ncx="http://netconfcentral.org/ns/yuma-ncx"> 
		<g8032-ring>
      <ring-name>%s</ring-name>
      <erp-instances>
				<erp-instance>
					<instance-name>%s</instance-name> 
					<raps-vid>%d</raps-vid>
					<raps-level>%d</raps-level> 
					<data-members>%s</data-members>
					<erp-instance-construct xmlns:g8032="http://www.ciena.com/ns/yang/ciena-itut-g8032-draft">major-ring</erp-instance-construct> 
					<reversion>revertive</reversion>
          <wtr-timer>1</wtr-timer>
          <guard-timer>500</guard-timer>
          <hold-off-time>0</hold-off-time>
          <ports>
            <port>
              <port-id>port0</port-id>
              <rpl>%s</rpl>
            </port>
            <port>
              <port-id>port1</port-id>
              <rpl>%s</rpl>
            </port>
          </ports>
        </erp-instance>
      </erp-instances>
    </g8032-ring>
  </g8032-rings>
</config>
"""

# Enabled G8032 globally and enabled notifications globally for the protocol
DISABLE_G8032 = """
<config>
	<g8032-rings xmlns="http://www.ciena.com/ns/yang/ciena-itut-g8032-draft" xmlns:ncx="http://netconfcentral.org/ns/yuma-ncx"> 
		<ring-system-control>disabled</ring-system-control> 
		<notification-enabled>false</notification-enabled>
		<raps-version xmlns:g8032="http://www.ciena.com/ns/yang/ciena-itut-g8032-draft">g8032:g8032-version1</raps-version> 
	</g8032-rings>
 </config>
"""

# EDIT-CONFIG RPC for deleting a G.8032 Logical Ring
DELETE_G8032_LOGICAL_RING = """
<config>
	<g8032-rings xmlns="http://www.ciena.com/ns/yang/ciena-itut-g8032-draft" xmlns:ncx="http://netconfcentral.org/ns/yuma-ncx"> 
		<g8032-ring operation="delete">
      <ring-name>%s</ring-name>
    </g8032-ring>
  </g8032-rings>
</config>
"""

# EDIT-CONFIG RPC for deleting a G.8032 Virtual Ring Instance
DELETE_G8032_VIRTUAL_RING = """
<config>
	<g8032-rings xmlns="http://www.ciena.com/ns/yang/ciena-itut-g8032-draft" xmlns:ncx="http://netconfcentral.org/ns/yuma-ncx"> 
		<g8032-ring>
      <ring-name>%s</ring-name>
      <erp-instances>
				<erp-instance operation="delete">
					<instance-name>%s</instance-name> 
        </erp-instance>
      </erp-instances>
    </g8032-ring>
  </g8032-rings>
</config>
"""

# possible encoding values for optional argument "config_encoding"
CONFIG_ENCODINGS = ["cli", "xml"]
