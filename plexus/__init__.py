# Copyright (c) 2015 Duke University.
# This software is distributed under the terms of the MIT License,
# the text of which is included in this distribution within the file
# named LICENSE.
#
# Portions of this software are derived from the "rest_router" controller
# application included with Ryu (http://osrg.github.io/ryu/), which is:
# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Modifications and additions were made to the original content by the
# following authors:
# Author: Victor J. Orlikowski <vjo@duke.edu>

# Common imports
import struct

from ryu import cfg
from ryu.lib import hub
from ryu.lib import dpid as dpid_lib
from ryu.lib import mac as mac_lib
from ryu.lib.packet import arp
from ryu.lib.packet import dhcp
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import vlan
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3

# Application constant definitions and configuration setup
__author__ = "Victor J. Orlikowski"
__copyright__ = "Copyright 2015, Duke University"
__credits__ = ["Victor J. Orlikowski", "Nippon Telegraph and Telephone Corporation"]
__license__ = "MIT"
__version__ = '0.1'
__maintainer__ = "Victor J. Orlikowski"
__email__ = "vjo@duke.edu"

UINT16_MAX = 0xffff
UINT32_MAX = 0xffffffff
UINT64_MAX = 0xffffffffffffffff

ETHERNET = ethernet.ethernet.__name__
VLAN = vlan.vlan.__name__
SVLAN = vlan.svlan.__name__
IPV4 = ipv4.ipv4.__name__
ARP = arp.arp.__name__
ICMP = icmp.icmp.__name__
TCP = tcp.tcp.__name__
UDP = udp.udp.__name__
DHCP = dhcp.dhcp.__name__

# Maximum number of suspended packets awaiting send per IP
MAX_SUSPENDPACKETS_PER_IP = 20
# Maximum number of suspended packets awaiting send per VlanRouter for all IPs
MAX_SUSPENDPACKETS = 200

# Seconds between walking the penalty box list
PENALTY_BOX_CHECK_INTERVAL = 3
# Amount by which to decrease penalty box counts every interval
PENALTY_BOX_DRAIN_AMOUNT = 50

# Maximum number of hits to an ARP matching penalty box entry
# before a penalty box rule gets inserted.
PENALTY_BOX_ENTRY_ARP_MAXHITS = 1000
# Number of hits to an ARP matching penalty box entry
# at which the switch is forcibly disconnected.
PENALTY_BOX_ARP_DISCONNECT_THRESHOLD = (PENALTY_BOX_ENTRY_ARP_MAXHITS * 2)
# Hard timeout for ARP matching penalty box rules, in seconds.
PENALTY_BOX_ARP_HARD_TIMEOUT = 10

# Maximum number of hits to an IPv4 matching penalty box entry,
# before a penalty box rule gets inserted.
PENALTY_BOX_ENTRY_IPV4_MAXHITS = 500
# Number of hits to an IPv4 matching penalty box entry
# at which the switch is forcibly disconnected.
PENALTY_BOX_IPV4_DISCONNECT_THRESHOLD = (PENALTY_BOX_ENTRY_IPV4_MAXHITS * 2)
# Hard timeout for IPv4 matching penalty box rules, in seconds.
PENALTY_BOX_IPV4_HARD_TIMEOUT = 15

ARP_REPLY_TIMER = 10  # sec
OFP_REPLY_TIMER = 1.0  # sec
CHK_ROUTING_TBL_INTERVAL = 30  # Seconds before cyclically checking reachability of all switch-defined routers

SWITCHID_PATTERN = dpid_lib.DPID_PATTERN + r'|all'
VLANID_PATTERN = r'[0-9]{1,4}|all'

VLANID_NONE = 0
VLANID_MIN = 2
VLANID_MAX = 4094

DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68

COOKIE_DEFAULT_ID = 0
COOKIE_SHIFT_VLANID = 32
COOKIE_SHIFT_ROUTEID = 16

INADDR_ANY_BASE = '0.0.0.0'
INADDR_ANY_MASK = '0'
INADDR_ANY = INADDR_ANY_BASE + '/' + INADDR_ANY_MASK

INADDR_BROADCAST_BASE = '255.255.255.255'
INADDR_BROADCAST_MASK = '32'
INADDR_BROADCAST = INADDR_BROADCAST_BASE + '/' + INADDR_BROADCAST_MASK

IDLE_TIMEOUT = 300  # sec
DEFAULT_TTL = 64

REST_COMMAND_RESULT = 'command_result'
REST_RESULT = 'result'
REST_DETAILS = 'details'
REST_OK = 'success'
REST_NG = 'failure'
REST_ALL = 'all'
REST_SWITCHID = 'switch_id'
REST_VLANID = 'vlan_id'
REST_NW = 'internal_network'
REST_ADDRESSID = 'address_id'
REST_ADDRESS = 'address'
REST_ROUTEID = 'route_id'
REST_ROUTE = 'route'
REST_DESTINATION = 'destination'
REST_DESTINATION_VLAN = 'destination_vlan'
REST_GATEWAY = 'gateway'
REST_GATEWAY_MAC = 'gateway_mac'
REST_SOURCE = 'source'
REST_BARE = 'bare'
REST_DHCP = 'dhcp_servers'

PRIORITY_VLAN_SHIFT = 1000
PRIORITY_NETMASK_SHIFT = 32

PRIORITY_ARP_HANDLING = 1
PRIORITY_DEFAULT_ROUTING = 1
PRIORITY_ADDRESSED_DEFAULT_ROUTING = 2
PRIORITY_MAC_LEARNING = 3
PRIORITY_STATIC_ROUTING = 3
PRIORITY_ADDRESSED_STATIC_ROUTING = 4
PRIORITY_IMPLICIT_ROUTING = 5
PRIORITY_L2_SWITCHING = 6
PRIORITY_IP_HANDLING = 7
PRIORITY_PENALTYBOX = 8

PRIORITY_TYPE_ROUTE = 'priority_route'

CONF = cfg.CONF
plexus_configuration_group = 'plexus'
plexus_backdoor_opt = cfg.BoolOpt('backdoor_enable',
                                  default = True,
                                  help = 'Enable backdoor REPL for inspecting state of python runtime')
plexus_backdoor_port_opt = cfg.IntOpt('backdoor_listen_port',
                                      default = 3000,
                                      help='Port on which the backdoor REPL should listen, on the local interface')
CONF.register_opt(plexus_backdoor_opt, group = plexus_configuration_group)
CONF.register_opt(plexus_backdoor_port_opt, group = plexus_configuration_group)

switchboard_configuration_group = 'switchboard'
switchboard_stateurl_opt = cfg.StrOpt('state_url',
                                      default = 'https://switchboard.oit.duke.edu/sdn_callback/restore_state',
                                      help = 'URL for accessing SwitchBoard knowledge base')
switchboard_username_opt = cfg.StrOpt('username',
                                      default = 'username',
                                      help='Username for accessing SwitchBoard knowledge base')
switchboard_password_opt = cfg.StrOpt('password',
                                      default = 'password',
                                      help = 'Password for accessing SwitchBoard knowledge base')
CONF.register_opt(switchboard_stateurl_opt, group = switchboard_configuration_group)
CONF.register_opt(switchboard_username_opt, group = switchboard_configuration_group)
CONF.register_opt(switchboard_password_opt, group = switchboard_configuration_group)
