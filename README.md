## Introduction

Plexus is an OpenFlow controller application developed at Duke University.

It makes use of the Ryu OpenFlow controller framework
(http://osrg.github.io/ryu/), and is derived from the
"rest_router" example application that is included with Ryu.

Plexus extends the "rest_router" example in several key ways:

1. The concept of a "policy routing table" is added, wherein static routes can be applied only for specific source address ranges.
2. Error reporting is provided if a gateway associated with a route is unreachable.
3. Management of DHCP traffic is provided, for integration with existing production deployments.

Plexus is nowhere near complete, and has some known bugs.
Development is ongoing, and contributions are welcomed.

Near-term planned additions:

1. Traffic "tag flipping" from one VLAN to another.
2. Network address translation from one subnet to another, for a specified range of IPs.
3. Routing of traffic based on source and/or destination TCP/UDP port matches.

Longer-term planned additions:
1. IPv6 support
2. Porting to Python 3.x

The name "Plexus" was chosen due to both the English meaning and
Latin etymology of the word.
The second meaning of the word, according to the Mirriam-Webster
dictionary (http://www.merriam-webster.com/dictionary/plexus) is:

```
"an interwoven combination of parts or elements in a structure or system"
```

According to the wikitionary (https://en.wiktionary.org/wiki/plexus#Latin),
"plexus" is the perfect passive participle of plectō (plectere, plexī, plexum).
This translates, in English, to "(having been) plaited, woven or braided."

We hope that, as Plexus develops, it permits you the flexibility
to create arbitrarily complex weavings within your network
infrastructure, that also remain understandable and manageable.

At Duke, we manage the complexity of our software-defined network
using the Switchboard web application
(https://github.com/mccahill/switchboard), as authored by
Mark P. McCahill.

## Building and Deploying Plexus

Plexus runs on Unix-like systems, due to relying on supervisord to
manage the Ryu controller framework.

Installing Plexus can be done by installing the correct set of
dependency packages using pip, and then running "python setup.py".

For ease of deployment, however, an RPM build process has been
provided, and a Dockerfile is being worked on. If demand exists, a
Debian/Ubuntu packaging infrastructure will be added as well.

Distribution of binary RPMs is planned in the near future, as is a
detailed description of the RPM build process.

## REST API Documentation

The following REST API description is based on the description
originally included with the "rest_router" example application,
and has been added to as new functions were integrated into
Plexus.

This API is still in flux; please expect changes, as we solidify
the set of core functions and abstractions.

Specific switches or VLANs are specified below, using the following convention:
```
{switch_id} may be: "all", or a specific DPID
{vlan_id} may be "all", or a specific numeric value corresponding to a given VLAN
```

### Get subnet address range data and routing data.

Get information about the "default" VLAN (VLAN "0" or "1", a.k.a. untagged traffic) on a particular DPID:
```
GET /router/{switch_id}
```

Get information about a specific VLAN, on a particular DPID:
```
GET /router/{switch_id}/{vlan_id}
```

The requested information is returned as a JSON-encoded string.

### Set subnet address range data or routing data.

Set information on the "default" VLAN, on a particular DPID:
```
POST /router/{switch_id}
```

Set information on a specific VLAN, on a particular DPID:
```
POST /router/{switch_id}/{vlan_id}
```

When setting information, the information to set is specified as a JSON-encoded string parameter to the POST.
Examples of the JSON-encoded data for specific operations are described below.

Define a subnet address range:
```
parameter = {"address": "A.B.C.D/M"}
```

Set a static route:
```
parameter = {"destination": "A.B.C.D/M", "gateway": "E.F.G.H"}
```

Set the default route:
```
parameter = {"gateway": "E.F.G.H"}
```

Set a static route for a specific subnet address range:
```
parameter = {"destination": "A.B.C.D/M", "gateway": "E.F.G.H", "address_id": "<int>"}
```

Set the default route for a specific subnet address range:
```
parameter = {"gateway": "E.F.G.H", "address_id": "<int>"}
```

Address identifiers for the above two operations can be retrieved using the GET operations described above.

Set valid DHCP server(s) for the default VLAN or a specific VLAN:
```
parameter = {"dhcp_servers": [ "A.B.C.D", "E.F.G.H" ]}
```

### Delete subnet address range data or routing data.

Delete information associated with the "default" VLAN, on a particular DPID:
```
DELETE /router/{switch_id}
```

Delete information associated with a specific VLAN, on a particular DPID:
```
DELETE /router/{switch_id}/{vlan_id}
```

When deleting information, the information to delete is specified as a JSON-encoded string parameter to the DELETE.
Examples of the JSON-encoded data for specific operations are described below.

Delete a subnet address range, or all subnet address ranges:
```
parameter = {"address_id": "<int>"} or {"address_id": "all"}
```

Delete a static route, or all static routes:
```
parameter = {"route_id": "<int>"} or {"route_id": "all"}
```
