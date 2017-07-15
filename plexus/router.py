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

import warnings
from distutils.util import strtobool

from plexus import *
from plexus.ofctl import *
from plexus.tables import *
from plexus.util import *

class Router(dict):
    def __init__(self, dp, ports, waiters, logger):
        super(Router, self).__init__()
        self.dp = dp
        self.waiters = waiters
        self.logger = logger
        self.dpid_str = dpid_lib.dpid_to_str(dp.id)
        self.sw_id = {'sw_id': self.dpid_str}

        self.port_data = PortData(ports)
        self.logger.info('Known ports at switch connect time:')
        for port in self.port_data:
            self.logger.info('\t%s', port)
        self.logger.info('Done listing known ports.')

        ofctl = OfCtl.factory(dp, logger)
        cookie = COOKIE_DEFAULT_ID

        # Clear existing flows:
        ofctl.clear_flows()
        self.logger.info('Clearing pre-existing flows [cookie=0x%x]', cookie)

        # Set flow: ARP handling (packet in)
        priority = get_priority(PRIORITY_ARP_HANDLING)
        ofctl.set_packetin_flow(cookie, priority, dl_type=ether.ETH_TYPE_ARP)
        self.logger.info('Set ARP handling (packet in) flow [cookie=0x%x]', cookie)

        # Set VlanRouter for vid=None.
        vlan_router = VlanRouter(VLANID_NONE, self)
        self[VLANID_NONE] = vlan_router

        # Start cyclic routing table check.
        self.thread = hub.spawn(self._cyclic_update_routing_tbls)
        self.logger.info('Started cyclic routing table update.')

    def delete(self):
        hub.kill(self.thread)
        self.thread.wait()
        self.logger.info('Stopped cyclic routing table update.')
        for vlan_router in self.values():
            vlan_router.shutdown()
            del self[vlan_router.vlan_id]

    def _get_vlan_router(self, vlan_id):
        vlan_routers = []

        if vlan_id == REST_ALL:
            vlan_routers = self.values()
        else:
            vlan_id = int(vlan_id)
            if (vlan_id != VLANID_NONE and
                    (vlan_id < VLANID_MIN or VLANID_MAX < vlan_id)):
                msg = 'Invalid {vlan_id} value. Set [%d-%d]'
                raise ValueError(msg % (VLANID_MIN, VLANID_MAX))
            elif vlan_id in self:
                vlan_routers = [self[vlan_id]]

        return vlan_routers

    def _add_vlan_router(self, vlan_id, bare=False):
        vlan_id = int(vlan_id)
        if vlan_id not in self:
            vlan_router = VlanRouter(vlan_id, self, bare)
            self[vlan_id] = vlan_router
        return self[vlan_id]

    def _del_vlan_router(self, vlan_id, waiters):
        # We never delete the default VLAN.
        # FIXME: How can the default VLAN be converted to "bare," if so desired?
        if vlan_id == VLANID_NONE:
            return

        self[vlan_id].delete(waiters)
        del self[vlan_id]

    def get_data(self, vlan_id, dummy1, dummy2):
        vlan_routers = self._get_vlan_router(vlan_id)
        msgs = [vlan_router.get_data() for vlan_router in vlan_routers]
        if not msgs:
            msgs = [{REST_VLANID: vlan_id}]

        return {REST_SWITCHID: self.dpid_str,
                REST_NW: msgs}

    def set_data(self, vlan_id, param, waiters):
        # FIXME: Decide the semantics of switching a VLAN router
        # between bare and not, on the fly.
        # Will require clearing rules associated with a given VLAN
        # on the switch, and replacing with new rules.
        bare = False
        if REST_BARE in param:
            bare = param[REST_BARE]
            try:
                bare = bool(strtobool(bare))
            except ValueError as e:
                err_msg = 'Invalid [%s] value. %s'
                raise ValueError(err_msg % (REST_BARE, e.message))

        if vlan_id != REST_ALL:
            self._add_vlan_router(vlan_id, bare)

        msgs = []
        vlan_routers = self._get_vlan_router(vlan_id)
        for vlan_router in vlan_routers:
            if not vlan_router.bare:
                try:
                    msg = vlan_router.set_data(param)
                    msgs.append(msg)
                    if msg[REST_RESULT] == REST_NG:
                        # Setting data failed.
                        self._del_vlan_router(vlan_router.vlan_id, waiters)
                except ValueError as err_msg:
                    # Setting data failed.
                    self._del_vlan_router(vlan_router.vlan_id, waiters)
                    raise err_msg
            else:
                msgs.append({REST_RESULT: REST_OK, REST_VLANID: vlan_id})

        return {REST_SWITCHID: self.dpid_str,
                REST_COMMAND_RESULT: msgs}

    def delete_data(self, vlan_id, param, waiters):
        msgs = []
        vlan_routers = self._get_vlan_router(vlan_id)
        for vlan_router in vlan_routers:
            msg = vlan_router.delete_data(param, waiters)
            if msg:
                msgs.append(msg)
            # Check unnecessary VlanRouter.
            self._del_vlan_router(vlan_router.vlan_id, waiters)
        if not msgs:
            msgs = [{REST_RESULT: REST_NG,
                     REST_DETAILS: 'Data is nothing.'}]

        return {REST_SWITCHID: self.dpid_str,
                REST_COMMAND_RESULT: msgs}

    def port_update_handler(self, port):
        # FIXME: Need to update more than just port data; might need to update routing tables.
        self.logger.info('Updating port data for port [%s].', port.port_no)
        self.port_data.update(port)

    def port_delete_handler(self, port):
        self.logger.info('Deleting port data for port [%s].', port.port_no)
        self.port_data.delete(port)

    def packet_in_handler(self, msg):
        pkt = None
        try:
            pkt = packet.Packet(msg.data)
        except:
            return None 
        #TODO: Packet library convert to string
        #self.logger.debug('Packet in = %s', str(pkt), self.sw_id)
        header_list = dict((p.protocol_name, p)
                           for p in pkt.protocols if type(p) != str)
        try:
            if header_list:
                # Check vlan-tag
                vlan_id = VLANID_NONE
                if VLAN in header_list:
                    vlan_id = header_list[VLAN].vid

                # Event dispatch
                if vlan_id in self:
                    self[vlan_id].packet_in_handler(msg, header_list)
                    # FIXME: Deal with updating any routing rules that route to this vlan_id from other routers here.
                else:
                    # FIXME: Have a penalty box rule here, per-VLAN, that inserts a block rule for any VLAN that attempts DoS
                    self.logger.debug('Drop unknown vlan packet. [vlan_id=%d]', vlan_id)
            else:
                self.logger.debug('Unable to parse payload packet headers; dropping packet-in.')
        except:
            self.logger.exception('Exception encountered during packet-in processing. '
                                  'This may be a result of external datapath changes '
                                  'causing internal state inconsistency. '
                                  'Internal state should regain consistency shortly.')

    def _cyclic_update_routing_tbls(self):
        while True:
            # send ARP to all gateways.
            for vlan_router in self.values():
                vlan_router.send_arp_all_gw()
                hub.sleep(1)

            hub.sleep(CHK_ROUTING_TBL_INTERVAL)


class VlanRouter(object):
    def __init__(self, vlan_id, parent_router, bare=False):
        super(VlanRouter, self).__init__()
        self.vlan_id = vlan_id
        self.parent_router = parent_router
        self.dp = parent_router.dp
        self.logger = parent_router.logger
        self.port_data = parent_router.port_data
        self.bare = bare
        self.quiescing = False

        self.sw_id = {'sw_id': dpid_lib.dpid_to_str(self.dp.id)}
        self.address_data = AddressData()
        self.policy_routing_tbl = PolicyRoutingTable()
        self.packet_buffer = SuspendPacketList(self.send_icmp_unreach_error)
        self.penalty_box = PenaltyBoxList()
        self.mac_table = MACAddressTable()
        self.ofctl = OfCtl.factory(self.dp, self.logger)

        # Set default route flow:
        # 1) If bare VLAN, define packet in handler.
        # 2) If managed VLAN, drop by default.
        if self.bare:
            self._set_bare_vlan_ip_handling()
        else:
            self._set_defaultroute_drop()

    # Call this method if the datapath may not still be connected.
    # It will not attempt to delete flows from the datapath.
    def shutdown(self):
        # First, mark that we're shutting down,
        # so that no further packet processing occurs.
        self.quiescing = True

        self.packet_buffer.shutdown()
        self.penalty_box.shutdown()
        self.mac_table.shutdown()

    # Call this method only if the datapath *is* still connected.
    # Otherwise, it may not make sense to try to delete flows.
    def delete(self, waiters):
        self.shutdown()
        # Delete all flows associated with this VLAN.
        msgs = self.ofctl.get_all_flow(waiters)
        for msg in msgs:
            for stats in msg.body:
                vlan_id = VlanRouter._cookie_to_id(REST_VLANID, stats.cookie)
                if vlan_id == self.vlan_id:
                    self.ofctl.delete_flow(stats)

    @staticmethod
    def _cookie_to_id(id_type, cookie):
        if id_type == REST_VLANID:
            rest_id = cookie >> COOKIE_SHIFT_VLANID
        elif id_type == REST_ADDRESSID:
            rest_id = cookie & UINT16_MAX
        elif id_type == REST_ROUTEID:
            rest_id = (cookie & UINT32_MAX) >> COOKIE_SHIFT_ROUTEID
        else:
            raise ValueError('Invalid id_type: %s' % id_type)

        return rest_id

    def _id_to_cookie(self, id_type, rest_id):
        vid = self.vlan_id << COOKIE_SHIFT_VLANID

        if id_type == REST_VLANID:
            cookie = rest_id << COOKIE_SHIFT_VLANID
        elif id_type == REST_ADDRESSID:
            cookie = vid + rest_id
        elif id_type == REST_ROUTEID:
            cookie = vid + (rest_id << COOKIE_SHIFT_ROUTEID)
        else:
            raise ValueError('Invalid id_type: %s' % id_type)

        return cookie

    def _get_priority(self, priority_type, route=None):
        return get_priority(priority_type, vid=self.vlan_id, route=route)

    def _response(self, msg):
        msg.setdefault(REST_VLANID, self.vlan_id)
        return msg

    def get_data(self):
        data = {}

        if self.bare:
            data.update({REST_BARE: self.bare})
        else:
            address_data = self._get_address_data()
            routing_data = self._get_routing_data()

            if address_data[REST_ADDRESS]:
                data.update(address_data)
            if routing_data[REST_ROUTE]:
                data.update(routing_data)

        return self._response(data)

    def _get_address_data(self):
        address_data = []
        for value in six.itervalues(self.address_data):
            default_gw = ip_addr_ntoa(value.default_gw)
            address = '%s/%d' % (default_gw, value.netmask)
            data = {REST_ADDRESSID: value.address_id,
                    REST_ADDRESS: address}
            address_data.append(data)
        return {REST_ADDRESS: address_data}

    def _get_routing_data(self):
        routing_data = []
        for table in six.itervalues(self.policy_routing_tbl):
            for dst, route in six.iteritems(table):
                gateway = ip_addr_ntoa(route.gateway_ip)
                source_addr = ip_addr_ntoa(route.src_ip)
                source = '%s/%d' % (source_addr, route.src_netmask)
                data = {REST_ROUTEID: route.route_id,
                        REST_DESTINATION: dst,
                        REST_GATEWAY: gateway,
                        REST_GATEWAY_MAC: route.gateway_mac,
                        REST_SOURCE: source}
                routing_data.append(data)
        return {REST_ROUTE: routing_data}

    def set_data(self, data):
        # Bail out, if we're shutting down.
        if self.quiescing:
            msg = {REST_RESULT: REST_NG, REST_DETAILS: "Shutting down."}
            return self._response(msg)

        details = None

        try:
            # Set address data
            if REST_ADDRESS in data:
                address = data[REST_ADDRESS]
                address_id = self._set_address_data(address)
                details = 'Add address [address_id=%d]' % address_id
            # Set routing data
            elif REST_GATEWAY in data:
                gateway = data[REST_GATEWAY]
                destination = INADDR_ANY
                dest_vlan = None
                address_id = None

                if REST_DESTINATION in data:
                    destination = data[REST_DESTINATION]

                if REST_DESTINATION_VLAN in data:
                    dest_vlan = data[REST_DESTINATION_VLAN]

                if REST_ADDRESSID in data:
                    address_id = data[REST_ADDRESSID]

                route_id = self._set_routing_data(destination, dest_vlan, gateway, address_id)
                details = 'Add route [route_id=%d]' % route_id
            elif REST_DHCP in data:
                dhcp_servers = data[REST_DHCP]
                self._set_dhcp_data(dhcp_servers, update_records=True)
                details = 'DHCP server(s) set as %r' % dhcp_servers

        except CommandFailure as err_msg:
            msg = {REST_RESULT: REST_NG, REST_DETAILS: str(err_msg)}
            return self._response(msg)

        if details is not None:
            msg = {REST_RESULT: REST_OK, REST_DETAILS: details}
            return self._response(msg)
        else:
            raise ValueError('Invalid parameter.')

    def _set_address_data(self, address):
        address = self.address_data.add(address)

        cookie = self._id_to_cookie(REST_ADDRESSID, address.address_id)

        # Set flow: host MAC learning (packet in)
        priority = self._get_priority(PRIORITY_MAC_LEARNING)
        self.ofctl.set_packetin_flow(cookie, priority,
                                     dl_type=ether.ETH_TYPE_IP,
                                     dl_vlan=self.vlan_id,
                                     dst_ip=address.nw_addr,
                                     dst_mask=address.netmask)
        log_msg = 'Set host MAC learning (packet in) flow [cookie=0x%x]'
        self.logger.info(log_msg, cookie)

        # set Flow: IP handling(PacketIn)
        priority = self._get_priority(PRIORITY_IP_HANDLING)
        self.ofctl.set_packetin_flow(cookie, priority,
                                     dl_type=ether.ETH_TYPE_IP,
                                     dl_vlan=self.vlan_id,
                                     dst_ip=address.default_gw)
        self.logger.info('Set IP handling (packet in) flow [cookie=0x%x]', cookie)

        # Send GARP
        self.send_arp_request(address.default_gw, address.default_gw)

        return address.address_id

    def _set_routing_data(self, destination, dest_vlan, gateway, address_id=None):
        err_msg = 'Invalid [%s] value.' % REST_GATEWAY
        dst_ip = ip_addr_aton(gateway, err_msg=err_msg)
        address = self.address_data.get_data(ip=dst_ip)
        requested_address = None

        if address_id is not None:
            if address_id != REST_ALL:
                try:
                    address_id = int(address_id)
                except ValueError as e:
                    err_msg = 'Invalid [%s] value. %s'
                    raise ValueError(err_msg % (REST_ADDRESSID, e.message))

                requested_address = self.address_data.get_data(addr_id=address_id)
                if requested_address is None:
                    msg = 'Requested address %s for route is not registered.' % address_id
                    raise CommandFailure(msg=msg)

        if dest_vlan is not None:
            try:
                dest_vlan = int(dest_vlan)
            except ValueError as e:
                err_msg = 'Invalid [%s] value. %s'
                raise ValueError(err_msg % (REST_DESTINATION_VLAN, e.message))

            if not (dest_vlan == VLANID_NONE or
                    (dest_vlan >= VLANID_MIN and dest_vlan <= VLANID_MAX)):
                err_msg = ('Value {%d} for [%s] out of permitted range. ' +
                           'Please use any of [%d] or [%d-%d].')
                raise ValueError(err_msg % (dest_vlan, REST_DESTINATION_VLAN,
                                            VLANID_NONE, VLANID_MIN, VLANID_MAX))

            if (self.vlan_id == dest_vlan):
                # It is not an invalid usage of the API to specify a destination VLAN
                # that is the same as the VLAN of the router handling the packet...
                # ...but it is pointless.
                dest_vlan = None

        if address is None:
            msg = 'Gateway=%s\'s address is not registered.' % gateway
            raise CommandFailure(msg=msg)
        elif dst_ip == address.default_gw:
            msg = 'Gateway=%s is used as default gateway of address_id=%d'\
                % (gateway, address.address_id)
            raise CommandFailure(msg=msg)
        else:
            src_ip = address.default_gw
            route = self.policy_routing_tbl.add(destination, dest_vlan, gateway, requested_address)
            # FIXME: Remove? Seems to be causing problems!
            # self._set_route_packetin(route)
            self.send_arp_request(src_ip, dst_ip)
            return route.route_id

    def _set_dhcp_data(self, dhcp_server_list, update_records=False):
        # OK - we've received a list of DHCP servers here.
        # We should now check to see if at least one is reachable.
        # We should, at least semi-regularly, update them.
        # This should be a rule with a short-lived idle time.
        # Actually - how about this:
        # For each IP in the list we receive:
        # - Check that it's a valid IP
        # - Check that it's one that we should be able to reach via (via a bypass or production route with a gateway).
        # - Append the IP to the list of dhcp servers for the policy routing table for this VLAN
        # - Send an ICMP ping to the IP.
        # We can then, as a periodic task, run _set_dhcp_data on the routing table,
        # which will result in a population of the switch rules, via the ICMP response handler.
        # This means that this method will need another parameter, that says whether to update the list of DHCP servers or not.
        # The ICMP response handler will check to see if the response is from one of the DHCP servers,
        # and will send an update to the switches. 

        # Check to see that IPs submitted as DHCP servers are valid.
        # FIXME: create a DHCPServer object, that has the IP address of the DHCP server, as well as whether it has been verified or not.
        err_msg = 'Invalid [%s] value.' % REST_DHCP
        for server in dhcp_server_list:
            self.logger.info('Testing DHCP IP [%s]', server)
            ip_addr_aton(server, err_msg=err_msg)

        # OK - now that we're sure all of the servers in the list have valid IP addresses, set the records.
        self.policy_routing_tbl.dhcp_servers = dhcp_server_list

        # Next, loop over the list one more time; this time, check how best to ping each server in the list,
        # then do so.
        for server in self.policy_routing_tbl.dhcp_servers:
            pass # FIXME

        # OK - this is broken, for now.
        # What I need to do: figure out *a* port, *any port* that leads to the production network,
        # or, to a network that contains the subnet of the DHCP servers (if they are locally attached), and ping out those ports.
        #production_route = self.policy_routing_tbl.get_data(dst_ip=ip_addr_aton(INADDR_ANY_BASE))
        #if production_route is not None:
        #    dst_ip = production_route.gateway_ip
        #    dst_mac = production_route.gateway_mac
        #    self.logger.info('Found production gateway at IP [%s], MAC [%s]', dst_ip, dst_mac)
        #    address = self.address_data.get_data(ip=dst_ip)
        #    src_ip = address.default_gw
        #    self.logger.info('Will use source IP [%s]', src_ip)
        #else:
        #    self.logger.info('Unable to find production gateway in tables')
        #    return

        # FIXME: we need to get the "default gateway" from the address data.
        # OK - we now know where the gateways are.
        # Now - we need to look at the DHCP server IP, and see if it is an "internal host" - meaning, it's in a subnet we know about.
        # If it is? The DHCP server *may* be directly attached to the switch.
        # That means that we need to send our probe out all of the ports on the switch, so that we can try to find the DHCP server.
        # If the DHCP server is *not* in a subnet we know about? We should try sending a probe out the known gateway ports, bound for the DHCP server.
        
        # Basically? We need to send an ICMP from the "IP of the switch" to the production gateway serving the subnet to which the switch belongs, or, if the DHCP server is in a subnet the switch knows about, flood it out...
        gateways = self.policy_routing_tbl.get_all_gateway_info()
        for gateway in gateways:
            gateway_ip, gateway_mac = gateway
            address = self.address_data.get_data(ip=gateway_ip)
            if gateway_mac is not None and address is not None:
                src_ip = address.default_gw
                for send_port in six.itervalues(self.port_data):
                    src_mac = send_port.hw_addr
                    out_port = send_port.port_no
                    header_list = dict()
                    header_list[ETHERNET] = ethernet.ethernet(src_mac, gateway_mac, ether.ETH_TYPE_IP)
                    for server in dhcp_server_list:
                        header_list[IPV4] = ipv4.ipv4(src=server, dst=src_ip)
                        data = icmp.echo()
                        self.ofctl.send_icmp(out_port, header_list, self.vlan_id,
                                             icmp.ICMP_ECHO_REQUEST,
                                             0,
                                             icmp_data=data, out_port=out_port)
            else:
                self.logger.info('Unable to find path to gateway [%s] while attempting to verify DHCP server [%s]',
                                 gateway_ip, server)

    def _set_bare_vlan_ip_handling(self):
        cookie = self._id_to_cookie(REST_VLANID, self.vlan_id)
        priority = self._get_priority(PRIORITY_DEFAULT_ROUTING)
        self.ofctl.set_packetin_flow(cookie, priority, dl_type=ether.ETH_TYPE_IP, dl_vlan=self.vlan_id)
        self.logger.info('Set IP handling (packet in) flow [cookie=0x%x] for bare VLAN [%d]', cookie, self.vlan_id)

    def _set_defaultroute_drop(self):
        cookie = self._id_to_cookie(REST_VLANID, self.vlan_id)
        priority = self._get_priority(PRIORITY_DEFAULT_ROUTING)
        outport = None  # for drop
        self.ofctl.set_routing_flow(cookie, priority, outport,
                                    dl_vlan=self.vlan_id)
        self.logger.info('Set default route (drop) flow [cookie=0x%x]', cookie)

    def _set_route_packetin(self, route):
        cookie = self._id_to_cookie(REST_ROUTEID, route.route_id)
        priority, log_msg = self._get_priority(PRIORITY_TYPE_ROUTE,
                                               route=route)
        self.ofctl.set_packetin_flow(cookie, priority,
                                     dl_type=ether.ETH_TYPE_IP,
                                     dl_vlan=self.vlan_id,
                                     dst_ip=route.dst_ip,
                                     dst_mask=route.dst_netmask,
                                     src_ip=route.src_ip,
                                     src_mask=route.src_netmask)
        self.logger.info('Set %s (packet in) flow [cookie=0x%x]', log_msg, cookie)

    def delete_data(self, data, waiters):
        # Bail out, if we're shutting down.
        if self.quiescing:
            msg = {REST_RESULT: REST_NG, REST_DETAILS: "Shutting down."}
            return self._response(msg)

        if REST_ROUTEID in data:
            route_id = data[REST_ROUTEID]
            msg = self._delete_routing_data(route_id, waiters)
        elif REST_ADDRESSID in data:
            address_id = data[REST_ADDRESSID]
            msg = self._delete_address_data(address_id, waiters)
        elif REST_WIPE in data:
            wipe = data[REST_WIPE]
            try:
                wipe = bool(strtobool(wipe))
            except ValueError as e:
                err_msg = 'Invalid [%s] value. %s'
                raise ValueError(err_msg % (REST_WIPE, e.message))
            if wipe:
                msg = self._wipe_all_data(waiters)
            else:
                msg = {REST_RESULT: REST_OK}
        elif REST_DISCONNECT in data:
            disconnect = data[REST_DISCONNECT]
            try:
                disconnect = bool(strtobool(disconnect))
            except ValueError as e:
                err_msg = 'Invalid [%s] value. %s'
                raise ValueError(err_msg % (REST_DISCONNECT, e.message))
            if disconnect:
                self.logger.info('Disconnecting datapath at administrator request.')
                self.dp.close()
            msg = {REST_RESULT: REST_OK}
        else:
            raise ValueError('Invalid parameter.')

        return self._response(msg)

    def _delete_address_data(self, address_id, waiters):
        if address_id != REST_ALL:
            try:
                address_id = int(address_id)
            except ValueError as e:
                err_msg = 'Invalid [%s] value. %s'
                raise ValueError(err_msg % (REST_ADDRESSID, e.message))

        skip_ids = self._chk_addr_relation_route(address_id)

        # Get all flow.
        delete_list = []
        msgs = self.ofctl.get_all_flow(waiters)
        max_id = UINT16_MAX
        for msg in msgs:
            for stats in msg.body:
                vlan_id = VlanRouter._cookie_to_id(REST_VLANID, stats.cookie)
                if vlan_id != self.vlan_id:
                    continue
                addr_id = VlanRouter._cookie_to_id(REST_ADDRESSID,
                                                   stats.cookie)
                if addr_id in skip_ids:
                    continue
                elif address_id == REST_ALL:
                    if addr_id <= COOKIE_DEFAULT_ID or max_id < addr_id:
                        continue
                elif address_id != addr_id:
                    continue
                delete_list.append(stats)

        delete_ids = []
        for flow_stats in delete_list:
            # Delete flow
            self.ofctl.delete_flow(flow_stats)
            address_id = VlanRouter._cookie_to_id(REST_ADDRESSID,
                                                  flow_stats.cookie)

            del_address = self.address_data.get_data(addr_id=address_id)
            if del_address is not None:
                # Clean up suspend packet threads.
                self.packet_buffer.delete(del_addr=del_address)

                # Delete data.
                self.address_data.delete(address_id)
                if address_id not in delete_ids:
                    delete_ids.append(address_id)

        msg = {}
        if delete_ids:
            delete_ids = ','.join(str(addr_id) for addr_id in delete_ids)
            details = 'Delete address [address_id=%s]' % delete_ids
            msg = {REST_RESULT: REST_OK, REST_DETAILS: details}

        if skip_ids:
            skip_ids = ','.join(str(addr_id) for addr_id in skip_ids)
            details = 'Skip delete (related route exist) [address_id=%s]'\
                % skip_ids
            if msg:
                msg[REST_DETAILS] += ', %s' % details
            else:
                msg = {REST_RESULT: REST_NG, REST_DETAILS: details}

        return msg

    def _delete_routing_data(self, route_id, waiters):
        if route_id != REST_ALL:
            try:
                route_id = int(route_id)
            except ValueError as e:
                err_msg = 'Invalid [%s] value. %s'
                raise ValueError(err_msg % (REST_ROUTEID, e.message))

        # Get all flow.
        msgs = self.ofctl.get_all_flow(waiters)

        delete_list = []
        for msg in msgs:
            for stats in msg.body:
                vlan_id = VlanRouter._cookie_to_id(REST_VLANID, stats.cookie)
                if vlan_id != self.vlan_id:
                    continue
                rt_id = VlanRouter._cookie_to_id(REST_ROUTEID, stats.cookie)
                if route_id == REST_ALL:
                    if rt_id == COOKIE_DEFAULT_ID:
                        continue
                elif route_id != rt_id:
                    continue
                delete_list.append(stats)

        # Delete flow.
        delete_ids = []
        for flow_stats in delete_list:
            self.ofctl.delete_flow(flow_stats)
            route_id = VlanRouter._cookie_to_id(REST_ROUTEID,
                                                flow_stats.cookie)
            self.policy_routing_tbl.delete(route_id)
            if route_id not in delete_ids:
                delete_ids.append(route_id)

            # case: Default route deleted. -> set flow (drop)
            route_type = get_priority_type(flow_stats.priority,
                                           vid=self.vlan_id)
            if route_type == PRIORITY_DEFAULT_ROUTING:
                self._set_defaultroute_drop()

        msg = {}
        if delete_ids:
            delete_ids = ','.join(str(route_id) for route_id in delete_ids)
            details = 'Delete route [route_id=%s]' % delete_ids
            msg = {REST_RESULT: REST_OK, REST_DETAILS: details}

        return msg

    def _wipe_all_data(self, waiters):
        self._delete_routing_data(REST_ALL, waiters)
        self._delete_address_data(REST_ALL, waiters)

        return {REST_RESULT: REST_OK}

    def _chk_addr_relation_route(self, address_id):
        # Check exist of related routing data.
        relate_list = []
        gateways = self.policy_routing_tbl.get_all_gateway_info()
        for gateway in gateways:
            gateway_ip, gateway_mac = gateway
            address = self.address_data.get_data(ip=gateway_ip)
            if address is not None:
                if (address_id == REST_ALL
                        and address.address_id not in relate_list):
                    relate_list.append(address.address_id)
                elif address.address_id == address_id:
                    relate_list = [address_id]
                    break
        return relate_list

    def _check_penalty_box_arp(self, msg, header_list):
        in_port = self.ofctl.get_packetin_inport(msg)
        dl_type = ether.ETH_TYPE_ARP

        penalty_entry = next((entry
                             for entry in self.penalty_box if ((entry.in_port == in_port) and
                                                               (entry.dl_type == dl_type))),
                             None)
        if penalty_entry:
            penalty_entry.count += 1
            if penalty_entry.count > PENALTY_BOX_ENTRY_ARP_MAXHITS:
                if penalty_entry.count > PENALTY_BOX_ARP_DISCONNECT_THRESHOLD:
                    # Penalty box rule should be in place.
                    # If we got here, the switch is buggy or misbehaving.
                    self.logger.warning('Disconnect threshold exceeded for penalty box entry!!')
                    self.logger.warning('Disconnecting offending datapath!!')
                    self.dp.close()
                    return True
                self.logger.info('ARP PacketIn events from port [%d] '
                                 'exceeded maximum allowed for time window.',
                                 in_port)
                self.logger.info('PacketIn hit count is: %d', penalty_entry.count)
                cookie = self._id_to_cookie(REST_VLANID, self.vlan_id)
                penalty_entry.priority = self._get_priority(PRIORITY_PENALTYBOX)
                actions = []
                self.ofctl.set_flow(cookie, penalty_entry.priority,
                                    in_port=in_port,
                                    dl_type=dl_type, dl_vlan=self.vlan_id,
                                    hard_timeout=PENALTY_BOX_ARP_HARD_TIMEOUT,
                                    actions=actions)
                self.logger.info('Set penalty box flow '
                                 '[cookie=0x%x, hard_timeout=%d]',
                                 cookie, PENALTY_BOX_ARP_HARD_TIMEOUT)
                return True
        else:
            penalty_entry = PenaltyBoxEntry(in_port=in_port,
                                            dl_type=dl_type)
            self.penalty_box.append(penalty_entry)
        return False

    def _check_penalty_box_ipv4(self, msg, header_list):
        in_port = self.ofctl.get_packetin_inport(msg)
        src_ip = header_list[IPV4].src
        dst_ip = header_list[IPV4].dst
        src_ip_str = ip_addr_ntoa(src_ip)
        dst_ip_str = ip_addr_ntoa(dst_ip)
        dl_type = ether.ETH_TYPE_IP

        # Keep track of the number of hits in the penalty box.
        penalty_entry = next((entry
                             for entry in self.penalty_box if ((entry.in_port == in_port) and
                                                               (entry.dl_type == dl_type) and
                                                               (entry.src_ip == src_ip) and
                                                               (entry.dst_ip == dst_ip))),
                             None)
        if penalty_entry:
            penalty_entry.count += 1
            if penalty_entry.count > PENALTY_BOX_ENTRY_IPV4_MAXHITS:
                if penalty_entry.count > PENALTY_BOX_IPV4_DISCONNECT_THRESHOLD:
                    # Penalty box rule should be in place.
                    # If we got here, the switch is buggy or misbehaving.
                    self.logger.warning('Disconnect threshold exceeded for penalty box entry!!')
                    self.logger.warning('Disconnecting offending datapath!!')
                    self.dp.close()
                    return True
                self.logger.info('IPv4 PacketIn events matching the following pattern '
                                 'exceeded maximum allowed for time window: '
                                 '[%s]->[%s] inbound on port [%d]',
                                 src_ip_str, dst_ip_str, in_port)
                self.logger.info('PacketIn hit count is: %d', penalty_entry.count)
                cookie = self._id_to_cookie(REST_VLANID, self.vlan_id)
                penalty_entry.priority = self._get_priority(PRIORITY_PENALTYBOX)
                actions = []
                self.ofctl.set_flow(cookie, penalty_entry.priority,
                                    in_port=in_port,
                                    dl_type=dl_type, dl_vlan=self.vlan_id,
                                    nw_src=src_ip, nw_dst=dst_ip,
                                    hard_timeout=PENALTY_BOX_IPV4_HARD_TIMEOUT,
                                    actions=actions)
                self.logger.info('Set penalty box flow '
                                 '[cookie=0x%x, hard_timeout=%d]',
                                 cookie,
                                 PENALTY_BOX_IPV4_HARD_TIMEOUT)
                return True
        else:
            penalty_entry = PenaltyBoxEntry(in_port=in_port,
                                            dl_type=dl_type,
                                            src_ip=src_ip,
                                            dst_ip=dst_ip)
            self.penalty_box.append(penalty_entry)
        return False

    def _learn_src_mac(self, msg, header_list):
        in_port = self.ofctl.get_packetin_inport(msg)
        src_mac = header_list[ETHERNET].src
        if ((src_mac != mac_lib.BROADCAST_STR) and
            (src_mac != mac_lib.DONTCARE_STR) and
            (src_mac != mac_lib.MULTICAST) and
            (src_mac != mac_lib.UNICAST)):
            existing_mac_entry = self.mac_table.get(src_mac)
            if existing_mac_entry:
                existing_mac_entry.refresh()
            else:
                self.mac_table[src_mac] = MACAddressEntry(in_port)

    def packet_in_handler(self, msg, header_list):
        # Bail out, if we're shutting down.
        if self.quiescing:
            return

        # Check invalid TTL (for OpenFlow V1.2/1.3)
        ofproto = self.dp.ofproto
        if ofproto.OFP_VERSION == ofproto_v1_2.OFP_VERSION or \
                ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            if msg.reason == ofproto.OFPR_INVALID_TTL:
                self._packetin_invalid_ttl(msg, header_list)
                return

        # Analyze event type.
        if ARP in header_list:
            self._learn_src_mac(msg, header_list)
            if self._check_penalty_box_arp(msg, header_list):
                return
            self._packetin_arp(msg, header_list)
            return

        if IPV4 in header_list:
            self._learn_src_mac(msg, header_list)
            if self._check_penalty_box_ipv4(msg, header_list):
                return
            rt_ports = self.address_data.get_default_gw()
            if header_list[IPV4].dst in rt_ports:
                # Packet to router's port.
                if ICMP in header_list:
                    if header_list[ICMP].type == icmp.ICMP_ECHO_REQUEST:
                        self._packetin_icmp_req(msg, header_list)
                        return
                    elif header_list[ICMP].type == icmp.ICMP_ECHO_REPLY:
                        self._packetin_icmp_reply(msg, header_list)
                        return
                elif TCP in header_list or UDP in header_list:
                    self._packetin_tcp_udp(msg, header_list)
                    return
            else:
                # Packet to internal host or gateway router.
                self._packetin_to_node(msg, header_list)
                return

    def _packetin_arp(self, msg, header_list):
        in_port = self.ofctl.get_packetin_inport(msg)
        src_ip = header_list[ARP].src_ip
        dst_ip = header_list[ARP].dst_ip
        src_ip_str = ip_addr_ntoa(src_ip)
        dst_ip_str = ip_addr_ntoa(dst_ip)
        src_addr = self.address_data.get_data(ip=src_ip)

        self.logger.info('Handling incoming ARP: [%s]->[%s] on VLAN [%d]',
                         src_ip_str, dst_ip_str, self.vlan_id)
        if (src_addr is None) and (not self.bare):
            self.logger.info('No gateway defined for subnet containing [%s]; '
                             'not handling ARP.',
                             src_ip)
            return

        # Housekeeping tasks, associated with seeing an ARP.
        # 1) Update the routing tables.
        # 2) Learn the MAC of the host.
        # FIXME: what happens here, if someone is ARP spoofing?!?
        if not self.bare:
            self._update_routing_tbls(msg, header_list)
        self._learning_host_mac(msg, header_list)

        # Fetch requested destination MAC out of headers
        packet_dst_mac = header_list[ARP].dst_mac

        # ARP packet handling.
        rt_ports = self.address_data.get_default_gw()

        if src_ip == dst_ip:
            # GARP -> ALL
            # FIXME: Is there anything that can be done to mitigate a malicious GARP?
            # Answer: check proteus before sending it - but that only works if someone isn't MAC spoofing too...
            # That said - in the MAC spoofing case - the grat ARP is *not* a problem.
            output = self.dp.ofproto.OFPP_ALL
            self.ofctl.send_packet_out(in_port, output, msg.data)

            self.logger.info('Received GARP from [%s].', src_ip_str)
            self.logger.info('Sending GARP (flood)')

        elif dst_ip not in rt_ports:
            dst_addr = self.address_data.get_data(ip=dst_ip)
            if (dst_addr is not None and
                    src_addr.address_id == dst_addr.address_id) or self.bare:
                # ARP from internal host -> ALL (in the same address range, which must be defined)
                output = self.dp.ofproto.OFPP_ALL
                mac_entry = self.mac_table.get(packet_dst_mac)
                if mac_entry:
                    output = mac_entry.port
                self.ofctl.send_packet_out(in_port, output, msg.data)

                self.logger.info('Received ARP from an internal host [%s].', src_ip_str)
                if mac_entry:
                    self.logger.info('Sent ARP to learned port [%s] for MAC [%s]',
                                     output, packet_dst_mac)
                else:
                    self.logger.info('Flooding ARP: [%s]->[%s]', src_ip_str, dst_ip_str)
        else:
            if header_list[ARP].opcode == arp.ARP_REQUEST:
                # ARP request to router port -> send ARP reply
                dst_mac = header_list[ARP].src_mac
                arp_target_mac = dst_mac

                src_port = self.port_data.get(in_port)
                if not src_port:
                    # FIXME: Log something here, if we got an ARP
                    # on a port we don't know about?
                    return
                src_mac = src_port.hw_addr

                output = in_port
                in_port = self.dp.ofproto.OFPP_CONTROLLER

                self.ofctl.send_arp(arp.ARP_REPLY, self.vlan_id,
                                    src_mac, dst_mac, dst_ip, src_ip,
                                    arp_target_mac, in_port, output)

                self.logger.info(('Received ARP request from [%s] ' +
                                 'to router at [%s].'),
                                 src_ip_str, dst_ip_str)
                self.logger.info('Sending ARP reply to [%s] on port [%s]',
                                 src_ip_str, output)
            elif header_list[ARP].opcode == arp.ARP_REPLY:
                #  ARP reply to router port -> suspend packets forward
                log_msg = 'Received ARP reply from [%s] to router at [%s].'
                self.logger.info(log_msg, src_ip_str, dst_ip_str)

                packet_list = self.packet_buffer.get_data(src_ip)
                if packet_list:
                    # stop ARP reply wait thread.
                    for suspend_packet in packet_list:
                        self.packet_buffer.delete(pkt=suspend_packet)

                    # send suspend packet.
                    output = self.dp.ofproto.OFPP_TABLE
                    for suspend_packet in packet_list:
                        self.ofctl.send_packet_out(suspend_packet.in_port,
                                                   output,
                                                   suspend_packet.data)
                        self.logger.info('Sent suspended packet to [%s].', src_ip_str)

    def _packetin_icmp_req(self, msg, header_list):
        # Send ICMP echo reply.
        in_port = self.ofctl.get_packetin_inport(msg)
        self.ofctl.send_icmp(in_port, header_list, self.vlan_id,
                             icmp.ICMP_ECHO_REPLY,
                             icmp.ICMP_ECHO_REPLY_CODE,
                             icmp_data=header_list[ICMP].data)

        src_ip_str = ip_addr_ntoa(header_list[IPV4].src)
        dst_ip_str = ip_addr_ntoa(header_list[IPV4].dst)
        log_msg = 'Handling incoming ICMP echo request to router: [%s]->[%s].'
        self.logger.info(log_msg, src_ip_str, dst_ip_str)
        self.logger.info('ICMP echo reply sent to [%s].', src_ip_str)

    def _packetin_icmp_reply(self, msg, header_list):
        # Deal with ICMP echo reply; primarily used for DHCP.
        in_port = self.ofctl.get_packetin_inport(msg)

        src_ip_str = ip_addr_ntoa(header_list[IPV4].src)
        dst_ip_str = ip_addr_ntoa(header_list[IPV4].dst)
        log_msg = 'Handling incoming ICMP echo reply: [%s]->[%s].'
        self.logger.info(log_msg, src_ip_str, dst_ip_str)

    def _packetin_tcp_udp(self, msg, header_list):
        # Log the receipt of the packet...
        src_ip_str = ip_addr_ntoa(header_list[IPV4].src)
        dst_ip_str = ip_addr_ntoa(header_list[IPV4].dst)
        self.logger.info('Handling incoming TCP/UDP to router: [%s]->[%s].', src_ip_str, dst_ip_str)

        # ...and then send an ICMP port unreachable.
        in_port = self.ofctl.get_packetin_inport(msg)
        self.ofctl.send_icmp(in_port, header_list, self.vlan_id,
                             icmp.ICMP_DEST_UNREACH,
                             icmp.ICMP_PORT_UNREACH_CODE,
                             msg_data=msg.data)
        log_msg = 'ICMP destination unreachable sent to [%s], in response to TCP/UDP packet directed to router at [%s].'
        self.logger.info(log_msg, src_ip_str, dst_ip_str)

    def _packetin_to_node(self, msg, header_list):
        # Log the receipt of the packet
        in_port = self.ofctl.get_packetin_inport(msg)
        src_ip = header_list[IPV4].src
        dst_ip = header_list[IPV4].dst
        src_ip_str = ip_addr_ntoa(src_ip)
        dst_ip_str = ip_addr_ntoa(dst_ip)
        self.logger.info('Handling incoming TCP/UDP: [%s]->[%s].', src_ip_str, dst_ip_str)

        # Check to see if we've exceeded limits for suspended packets.
        suspended_packet_list_for_ip = self.packet_buffer.get_data(dst_ip_str)
        drop_packet = False
        if (len(suspended_packet_list_for_ip) >= MAX_SUSPENDPACKETS_PER_IP):
            self.logger.info('Suspended packet maximum exceeded for IP [%s]', dst_ip_str)
            drop_packet = True
        if (len(self.packet_buffer) >= MAX_SUSPENDPACKETS):
            self.logger.info('Suspended packet maximum exceeded for VLAN [%d]', self.vlan_id)
            drop_packet = True
        if drop_packet:
            self.logger.info('Dropping packet.')
            return

        # Determine if this is a DHCP packet, and send it out.
        # FIXME:
        # Check to see if the packet is a DHCP OFFER.
        # Check to see if IP address if one of the configured DHCP server addresses.
        # If it is not, check that the IP address is that of the default gateway for the subnet (if such exists).
        # Presuming the correct set of the above conditions is met,
        # broadcast ping with frame containing requesting MAC from the DHCP header list as destination (to 
        # determine where it lives).
        # Upon finding the port on which the MAC lives, send out the DHCP OFFER.
        if DHCP in header_list:
            op_type = None
            flood = False
            dhcp_state = ord([opt for opt in header_list[DHCP].options.option_list if opt.tag == dhcp.DHCP_MESSAGE_TYPE_OPT][0].value)

            if dhcp_state == dhcp.DHCP_OFFER:
                op_type = "OFFER"
            elif dhcp_state == dhcp.DHCP_ACK:
                op_type = "ACK"

            if op_type is not None:
                flood = True

            if ((header_list[DHCP].op == dhcp.DHCP_BOOT_REPLY) and flood):
                self.logger.debug('Flooding received DHCP %s for MAC address [%s].', op_type, header_list[ETHERNET].dst)
                output = self.dp.ofproto.OFPP_ALL
                self.ofctl.send_packet_out(in_port, output, msg.data)

        
        if self.bare:
            src_mac = header_list[ETHERNET].src
            dst_mac = header_list[ETHERNET].dst
            out_port = None

            self.logger.info('TCP/UDP on bare VLAN; attempting to discover how to forward: ' +
                             '[%s]->[%s]', src_mac, dst_mac)

            mac_entry = self.mac_table.get(dst_mac)
            if mac_entry:
                self.logger.info('Found egress port for: [%s]', dst_mac)
                out_port = mac_entry.port
            else:
                self.logger.info('Egress port not found for: [%s]', dst_mac)
                self.logger.info('Generating ARP to search for: [%s]', dst_mac)
                self.send_arp_request(src_ip, dst_ip, in_port, src_mac)

            if out_port is not None:
                actions = [self.dp.ofproto_parser.OFPActionOutput(out_port)]
                cookie = self._id_to_cookie(REST_VLANID, self.vlan_id)
                priority = self._get_priority(PRIORITY_IMPLICIT_ROUTING)
                self.logger.info('Setting IP flow rule for [%s]->[%s]', src_mac, dst_mac)
                self.ofctl.set_flow(cookie, priority,
                                    in_port=in_port,
                                    dl_type=ether.ETH_TYPE_IP,
                                    dl_src=mac_lib.haddr_to_bin(src_mac),
                                    dl_dst=mac_lib.haddr_to_bin(dst_mac),
                                    dl_vlan=self.vlan_id,
                                    idle_timeout=L2_IDLE_TIMEOUT,
                                    actions=actions)
                self.ofctl.send_packet_out(in_port, out_port, msg.data)
            else:
                self.packet_buffer.add(in_port, header_list, msg.data)
        else:
            # Send ARP request to get node MAC address.
            arp_src_ip = None

            address = self.address_data.get_data(ip=dst_ip)
            if address is not None:
                log_msg = 'Received IP packet bound for an internal host: [%s]->[%s].'
                self.logger.info(log_msg, src_ip_str, dst_ip_str)
                arp_src_ip = address.default_gw
            else:
                route = self.policy_routing_tbl.get_data(dst_ip=dst_ip, src_ip=src_ip_str)
                if route is not None:
                    log_msg = 'Received IP packet intended for routing: [%s]->[%s].'
                    self.logger.info(log_msg, src_ip_str, dst_ip_str)
                    gw_address = self.address_data.get_data(ip=route.gateway_ip)
                    if gw_address is not None:
                        arp_src_ip = gw_address.default_gw
                        dst_ip = route.gateway_ip

            if arp_src_ip is not None:
                self.packet_buffer.add(in_port, header_list, msg.data)
                self.send_arp_request(arp_src_ip, dst_ip, in_port)
                self.logger.info('Flooding ARP request on behalf of [%s]: [%s] asking who-has [%s]',
                                 src_ip_str, arp_src_ip, dst_ip_str)
            else:
                self.logger.info('Could not find a viable path to destination [%s] for source [%s]',
                                 dst_ip_str, src_ip_str)

    def _packetin_invalid_ttl(self, msg, header_list):
        # Send ICMP TTL error.
        src_ip_str = ip_addr_ntoa(header_list[IPV4].src)
        self.logger.info('Received invalid ttl packet from [%s].', src_ip_str)

        in_port = self.ofctl.get_packetin_inport(msg)
        src_ip = self._get_send_port_ip(header_list)
        if src_ip is not None:
            self.ofctl.send_icmp(in_port, header_list, self.vlan_id,
                                 icmp.ICMP_TIME_EXCEEDED,
                                 icmp.ICMP_TTL_EXPIRED_CODE,
                                 msg_data=msg.data, src_ip=src_ip)
            self.logger.info('Send ICMP time exceeded to [%s].', src_ip_str)

    def send_arp_all_gw(self):
        gateways = self.policy_routing_tbl.get_all_gateway_info()
        for gateway in gateways:
            gateway_ip, gateway_mac = gateway
            address = self.address_data.get_data(ip=gateway_ip)
            self.send_arp_request(address.default_gw, gateway_ip)

    def send_arp_request(self, src_ip, dst_ip, in_port=None, proxy_src_mac=None):
        # Send ARP request from all ports.
        self.logger.info('Sending ARP request from [%s] asking who-has [%s].', src_ip, dst_ip)
        for send_port in six.itervalues(self.port_data):
            if in_port is None or in_port != send_port.port_no:
                dst_mac = mac_lib.BROADCAST_STR
                arp_target_mac = mac_lib.DONTCARE_STR
                if ((proxy_src_mac is not None) and
                    (in_port is not None)):
                    src_mac = proxy_src_mac
                    inport = in_port
                else:
                    src_mac = send_port.hw_addr
                    inport = self.dp.ofproto.OFPP_CONTROLLER
                output = send_port.port_no
                self.ofctl.send_arp(arp.ARP_REQUEST, self.vlan_id,
                                    src_mac, dst_mac, src_ip, dst_ip,
                                    arp_target_mac, inport, output)

    def send_icmp_unreach_error(self, packet_buffer):
        # Send ICMP host unreach error.
        self.logger.info('ARP reply wait timer timed out.')

        src_ip = self._get_send_port_ip(packet_buffer.header_list)
        if src_ip is not None:
            self.ofctl.send_icmp(packet_buffer.in_port,
                                 packet_buffer.header_list,
                                 self.vlan_id,
                                 icmp.ICMP_DEST_UNREACH,
                                 icmp.ICMP_HOST_UNREACH_CODE,
                                 msg_data=packet_buffer.data,
                                 src_ip=src_ip)

            dst_ip = ip_addr_ntoa(packet_buffer.dst_ip)
            self.logger.info('Sent ICMP destination unreachable to [%s] regarding [%s].', src_ip, dst_ip)

    def _update_routing_tbls(self, msg, header_list):
        # FIXME:
        # Need to have a way to wait a certain amount of time, to ensure that there has not been a race to MAC/ARP poison the rule table.

        # Set flow: routing to gateway.
        out_port = self.ofctl.get_packetin_inport(msg)
        src_mac = header_list[ARP].src_mac
        src_ip = header_list[ARP].src_ip

        dst_port = self.port_data.get(out_port)
        if not dst_port:
            return
        dst_mac = dst_port.hw_addr

        default_route = self.policy_routing_tbl.get_data(dst_ip=INADDR_ANY_BASE, src_ip=src_ip)
        gateway_flg = False
        for table in six.itervalues(self.policy_routing_tbl):
            for key, value in six.iteritems(table):
                if value.gateway_ip == src_ip:
                    gateway_flg = True
                    if value.gateway_mac == src_mac:
                        continue
                    table[key].gateway_mac = src_mac

                    cookie = self._id_to_cookie(REST_ROUTEID, value.route_id)
                    priority, log_msg = self._get_priority(PRIORITY_TYPE_ROUTE,
                                                           route=value)
                    self.ofctl.set_routing_flow(cookie, priority, out_port,
                                                dl_vlan=self.vlan_id,
                                                src_mac=dst_mac,
                                                dst_mac=src_mac,
                                                nw_src=value.src_ip,
                                                src_mask=value.src_netmask,
                                                nw_dst=value.dst_ip,
                                                dst_mask=value.dst_netmask)
                    self.logger.info('Set %s flow [cookie=0x%x]', log_msg, cookie)
                    if default_route is not None:
                        if default_route.gateway_ip == value.gateway_ip:
                            self.ofctl.set_routing_flow(cookie, priority, out_port,
                                                        dl_vlan=self.vlan_id,
                                                        nw_src=INADDR_ANY_BASE,
                                                        nw_dst=INADDR_BROADCAST_BASE,
                                                        nw_proto=inet.IPPROTO_UDP,
                                                        src_port=DHCP_CLIENT_PORT,
                                                        dst_port=DHCP_SERVER_PORT)
                            self.logger.info('Set DHCP egress flow...')

        return gateway_flg

    def _learning_host_mac(self, msg, header_list):
        # FIXME:
        # 1) Make sure we don't learn the MAC of the "default gateway" (as defined by the controller for the switch).
        # 2) Need to have a way to wait a certain amount of time, to ensure that there has not been a race to MAC/ARP poison the rule table.

        # Set flow: routing to internal Host.
        out_port = self.ofctl.get_packetin_inport(msg)
        src_mac = header_list[ARP].src_mac
        src_ip = header_list[ARP].src_ip
        src_ip_str = ip_addr_ntoa(src_ip)

        dst_port = self.port_data.get(out_port)
        if not dst_port:
            return
        dst_mac = dst_port.hw_addr

        address = self.address_data.get_data(ip=src_ip)
        if address is not None:
            cookie = self._id_to_cookie(REST_ADDRESSID, address.address_id)
            priority = self._get_priority(PRIORITY_IMPLICIT_ROUTING)
            self.ofctl.set_routing_flow(cookie, priority,
                                        out_port, dl_vlan=self.vlan_id,
                                        src_mac=dst_mac, dst_mac=src_mac,
                                        nw_dst=src_ip,
                                        idle_timeout=L3_IDLE_TIMEOUT)
            self.logger.info('Set implicit routing flow [cookie=0x%x]', cookie)
            # FIXME: 
            # Move this to a background thread; don't want to hold up the handler.
            # Also, not working as well as hoped; need to debug.
            #
            # Delete any penalty box rules associated with this destination IP.
            # Use a queue to register destination IPs for penalty box removal.
            #matching_penalty_box_entries = [entry for entry in self.penalty_box if (entry.dst_ip == src_ip)]
            #if matching_penalty_box_entries:
            #    msgs = self.ofctl.get_all_flow(self.parent_router.waiters)
            #    for msg in msgs:
            #        for stats in msg.body:
            #            vlan_id = VlanRouter._cookie_to_id(REST_VLANID, stats.cookie)
            #            # Check against each entry in matching entries to see if match contains src_ip
            #            for entry in matching_penalty_box_entries:
            #                if entry.priority:
            #                    if ((vlan_id == self.vlan_id) and
            #                        (entry.priority == stats.priority) and
            #                        (entry.dst_ip == self.ofctl.get_match_dst_ip(stats.match))):
            #                        self.ofctl.delete_flow(stats)
            #                        self.logger.info('Removed penalty box flow for [%s].',
            #                                         src_ip_str)

    def _get_send_port_ip(self, header_list):
        try:
            src_mac = header_list[ETHERNET].src
            if IPV4 in header_list:
                src_ip = header_list[IPV4].src
            else:
                src_ip = header_list[ARP].src_ip
        except KeyError:
            self.logger.debug('Received unsupported packet.')
            return None

        address = self.address_data.get_data(ip=src_ip)
        if address is not None:
            return address.default_gw
        else:
            route = self.policy_routing_tbl.get_data(gw_mac=src_mac, src_ip=src_ip)
            if route is not None:
                address = self.address_data.get_data(ip=route.gateway_ip)
                if address is not None:
                    return address.default_gw

        self.logger.debug('Received packet from unknown IP [%s].', ip_addr_ntoa(src_ip))
        return None
