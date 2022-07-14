# Ciena SAOS10 ncc
A simple tool to interact with Ciena SAOS 10 devices using Netconf/Yang. 

Current functions implemented so far:
 
 * open()                                   : Establish the connection
 * close()                                  : Close the connection
 * get_server_capabilities()                : Retrieves and stores all supported yang models.
 * get_forwarding_domains()                 : Returns a list of forwarding domains configured on the device
 * get_flow_points()                        : Returns a list of flow points configured on the device
 * get_classifiers()                        : Returns a list of classifiers configured on the device
 * get_g8032_rings()                        : Returns a list of 8032 rings and ERP instances configured on the device and their current state
 * create_classifier()                      : Creates a classifier on the device
 * create_forwarding_domain()               : Creates a forwarding domain on the device
 * create_flow_point()                      : Creates a flow point on the device
 * add_egress_transform_flow_point()        : Adds an egress_l2_transform action onto a flow point
 * add_ingress_transform_flow_point()       : Adds an ingress_l2_transform action onto a flow point
 * create_l3_interface()                    : Creates an L3 interface on the device
 * create_loopback_interface()              : Creates a Loopback interface on the device
 * configure_authentication_group()         : Performs all necessary configuration to build an authentication group
 * set_authentication_method()              : Configures the authentication method for the device
 * enable_g8032()                           : Enables the G.8032 service
 * create_g8032_logicalRing()               : Creates a G.8032 Logical Ring
 * create_g8032_virtualRing()               : Creates a G.8032 Virtual Ring
 * create_isis_instance()                   : Creates an ISIS Routing Process
 * add_isis_interface()                     : Adds an interface into the ISIS Process
 * create_bgp_instance()                    : Creates a BGP instance on the device
 * add_bgp_peer()                           : add a BGP peer to an existing BGP Process
 * create_evpn_instance()                   : Creates an EVPN Instance
 * set_ethernet_segment()                   : Creates an EVPN Ethernet Segment
 * delete_classifier()                      : Deletes a classifier from the device
 * delete_flow_point()                      : Deletes a flow point from the device
 * delete_forwarding_domain()               : Deletes a forwarding domain from the device
 * delete_g8032_logicalRing()               : Deletes a G.8032 Logical Ring from the device
 * delete_g8032_virtualRing()               : Deletes a G.8032 Virtual Ring from the device

## Timeline

|  Date  |  Release  |  Description  |
| :----: | :-------: | :-----------: |
| 07/11/2022 | `0.2.0`| Initial Creation of pip package and initial function support. |
| 06/29/2022 | `0.1.` | Initial creation of the repository and application. |

## Requirements

* Python 2.7 or Python 3.5+
* setuptools 0.6+
* Paramiko 1.7+
* lxml 3.3.0+
* libxml2
* libxslt
* xmltodict
* jinja2

## Installation

Install my-project with pip
```bash
  unzip cienasaos10ncc.zip
  cd cienasaos10ncc
  pip install .
```

## Usage

```python
  import json
  from cienasaos10ncc import saos10_netconf
  
  test = saos10_netconf.SAOS10NETCONFDriver(host, user, password)
  test.open()
  print(json.dumps(test.get_classifiers(),indent=4,sort_keys=True))
  print(json.dumps(test.get_forwarding_domains(),indent=4,sort_keys=True))
  print(json.dumps(test.get_flow_points(),indent=4,sort_keys=True))
  test.close()

```

## Authors
* [Lucas Wood] (mailto:lucasw@lucaswood.net)