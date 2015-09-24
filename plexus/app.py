# Plexus controller application entry point/main program
import requests
import urllib3.contrib.pyopenssl

from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import WSGIApplication
from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.exception import OFPUnknownVersion
from ryu.exception import RyuException

from plexus import *
from plexus.router import *
from plexus.util import *

#=============================
#          REST API
#=============================
#
#  Note: specify switch and vlan group, as follows.
#   {switch_id} : 'all' or switchID
#   {vlan_id}   : 'all' or vlanID
#
#
## 1. get address data and routing data.
#
# * get data of no vlan
# GET /router/{switch_id}
#
# * get data of specific vlan group
# GET /router/{switch_id}/{vlan_id}
#
#
## 2. set address data or routing data.
#
# * set data of no vlan
# POST /router/{switch_id}
#
# * set data of specific vlan group
# POST /router/{switch_id}/{vlan_id}
#
#  case1: set address data.
#    parameter = {"address": "A.B.C.D/M"}
#  case2-1: set static route.
#    parameter = {"destination": "A.B.C.D/M", "gateway": "E.F.G.H"}
#  case2-2: set default route.
#    parameter = {"gateway": "E.F.G.H"}
#  case2-3: set static route for a specific address range.
#    parameter = {"destination": "A.B.C.D/M", "gateway": "E.F.G.H", "address_id": "<int>"}
#  case2-4: set default route for a specific address range.
#    parameter = {"gateway": "E.F.G.H", "address_id": "<int>"}
#  case3: set DHCP server for a VLAN
#    parameter = {"dhcp_servers": [ "A.B.C.D", "E.F.G.H" ]}
#
#
## 3. delete address data or routing data.
#
# * delete data of no vlan
# DELETE /router/{switch_id}
#
# * delete data of specific vlan group
# DELETE /router/{switch_id}/{vlan_id}
#
#  case1: delete address data.
#    parameter = {"address_id": "<int>"} or {"address_id": "all"}
#  case2: delete routing data.
#    parameter = {"route_id": "<int>"} or {"route_id": "all"}
#
#

class Plexus(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION,
                    ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'dpset': dpset.DPSet,
                 'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(Plexus, self).__init__(*args, **kwargs)

        # logger configure
        PlexusController.set_logger(self.logger)

        wsgi = kwargs['wsgi']
        self.waiters = {}
        self.data = {'waiters': self.waiters}

        mapper = wsgi.mapper
        wsgi.registory['PlexusController'] = self.data
        requirements = {'switch_id': SWITCHID_PATTERN,
                        'vlan_id': VLANID_PATTERN}

        # For no vlan data
        path = '/router/{switch_id}'
        mapper.connect('router', path, controller=PlexusController,
                       requirements=requirements,
                       action='get_data',
                       conditions=dict(method=['GET']))
        mapper.connect('router', path, controller=PlexusController,
                       requirements=requirements,
                       action='set_data',
                       conditions=dict(method=['POST']))
        mapper.connect('router', path, controller=PlexusController,
                       requirements=requirements,
                       action='delete_data',
                       conditions=dict(method=['DELETE']))
        # For vlan data
        path = '/router/{switch_id}/{vlan_id}'
        mapper.connect('router', path, controller=PlexusController,
                       requirements=requirements,
                       action='get_vlan_data',
                       conditions=dict(method=['GET']))
        mapper.connect('router', path, controller=PlexusController,
                       requirements=requirements,
                       action='set_vlan_data',
                       conditions=dict(method=['POST']))
        mapper.connect('router', path, controller=PlexusController,
                       requirements=requirements,
                       action='delete_vlan_data',
                       conditions=dict(method=['DELETE']))

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def datapath_handler(self, ev):
        if ev.enter:
            PlexusController.register_router(ev.dp)
        else:
            PlexusController.unregister_router(ev.dp)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        datapath.n_tables = ev.msg.n_tables

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        PlexusController.packet_in_handler(ev.msg)

    def _stats_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath

        if (dp.id not in self.waiters
                or msg.xid not in self.waiters[dp.id]):
            return
        event, msgs = self.waiters[dp.id][msg.xid]
        msgs.append(msg)

        if ofproto_v1_3.OFP_VERSION == dp.ofproto.OFP_VERSION:
            more = dp.ofproto.OFPMPF_REPLY_MORE
        else:
            more = dp.ofproto.OFPSF_REPLY_MORE
        if msg.flags & more:
            return
        del self.waiters[dp.id][msg.xid]
        event.set()

    # for OpenFlow version1.0
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_0(self, ev):
        self._stats_reply_handler(ev)

    # for OpenFlow version1.2/1.3
    @set_ev_cls(ofp_event.EventOFPStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler_v1_2(self, ev):
        self._stats_reply_handler(ev)

    #TODO: Update routing table when port status is changed.


class PlexusController(ControllerBase):
    _ROUTER_LIST = {}
    _LOGGER = None

    def __init__(self, req, link, data, **config):
        super(PlexusController, self).__init__(req, link, data, **config)
        self.waiters = data['waiters']

    @classmethod
    def set_logger(cls, logger):
        cls._LOGGER = logger

    @classmethod
    def register_router(cls, dp):
        logger = RouterLoggerAdapter(cls._LOGGER, {'sw_id': dpid_lib.dpid_to_str(dp.id)})
        try:
            router = Router(dp, logger)
        except OFPUnknownVersion as message:
            logger.error(str(message))
            return
        cls._ROUTER_LIST.setdefault(dp.id, router)
        logger.info('Join as router.')

        logger.info('Requesting configuration from Switchboard.')
        try:
            urllib3.contrib.pyopenssl.inject_into_urllib3()
            payload = {'rest_caller_id': CONF.switchboard.username, 'rest_caller_pw': CONF.switchboard.password}
            r = requests.get(CONF.switchboard.state_url, params=payload)
        except:
            logger.error('Error in retrieving Switchboard configuration!')
            return

    @classmethod
    def unregister_router(cls, dp):
        if dp.id in cls._ROUTER_LIST:
            cls._ROUTER_LIST[dp.id].delete()
            del cls._ROUTER_LIST[dp.id]

            logger = RouterLoggerAdapter(cls._LOGGER, {'sw_id': dpid_lib.dpid_to_str(dp.id)})
            logger.info('Leave router.')

    @classmethod
    def packet_in_handler(cls, msg):
        dp_id = msg.datapath.id
        if dp_id in cls._ROUTER_LIST:
            router = cls._ROUTER_LIST[dp_id]
            router.packet_in_handler(msg)

    # GET /router/{switch_id}
    @rest_command
    def get_data(self, req, switch_id, **_kwargs):
        return self._access_router(switch_id, VLANID_NONE,
                                   'get_data', req.body)

    # GET /router/{switch_id}/{vlan_id}
    @rest_command
    def get_vlan_data(self, req, switch_id, vlan_id, **_kwargs):
        return self._access_router(switch_id, vlan_id,
                                   'get_data', req.body)

    # POST /router/{switch_id}
    @rest_command
    def set_data(self, req, switch_id, **_kwargs):
        return self._access_router(switch_id, VLANID_NONE,
                                   'set_data', req.body)

    # POST /router/{switch_id}/{vlan_id}
    @rest_command
    def set_vlan_data(self, req, switch_id, vlan_id, **_kwargs):
        return self._access_router(switch_id, vlan_id,
                                   'set_data', req.body)

    # DELETE /router/{switch_id}
    @rest_command
    def delete_data(self, req, switch_id, **_kwargs):
        return self._access_router(switch_id, VLANID_NONE,
                                   'delete_data', req.body)

    # DELETE /router/{switch_id}/{vlan_id}
    @rest_command
    def delete_vlan_data(self, req, switch_id, vlan_id, **_kwargs):
        return self._access_router(switch_id, vlan_id,
                                   'delete_data', req.body)

    def _access_router(self, switch_id, vlan_id, func, rest_param):
        rest_message = []
        routers = self._get_router(switch_id)
        param = eval(rest_param) if rest_param else {}
        for router in routers.values():
            function = getattr(router, func)
            data = function(vlan_id, param, self.waiters)
            rest_message.append(data)

        return rest_message

    def _get_router(self, switch_id):
        routers = {}

        if switch_id == REST_ALL:
            routers = self._ROUTER_LIST
        else:
            sw_id = dpid_lib.str_to_dpid(switch_id)
            if sw_id in self._ROUTER_LIST:
                routers = {sw_id: self._ROUTER_LIST[sw_id]}

        if routers:
            return routers
        else:
            raise NotFoundError(switch_id=switch_id)
