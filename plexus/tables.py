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

import time

from plexus import *
from plexus.util import *


class PortData(dict):
    def __init__(self, ports):
        super(PortData, self).__init__()
        for port in ports:
            data = Port(port.port_no, port.hw_addr)
            self[port.port_no] = data


class Port(object):
    def __init__(self, port_no, hw_addr):
        super(Port, self).__init__()
        self.port_no = port_no
        self.mac = hw_addr


class AddressData(dict):
    def __init__(self):
        super(AddressData, self).__init__()
        self.address_id = 1

    def add(self, address):
        err_msg = 'Invalid [%s] value.' % REST_ADDRESS
        nw_addr, mask, default_gw = nw_addr_aton(address, err_msg=err_msg)

        # Check overlaps
        for other in self.values():
            other_mask = mask_ntob(other.netmask)
            add_mask = mask_ntob(mask, err_msg=err_msg)
            if (other.nw_addr == ipv4_apply_mask(default_gw, other.netmask) or
                    nw_addr == ipv4_apply_mask(other.default_gw, mask,
                                               err_msg)):
                msg = 'Address overlaps [address_id=%d]' % other.address_id
                raise CommandFailure(msg=msg)

        address = Address(self.address_id, nw_addr, mask, default_gw)
        ip_str = ip_addr_ntoa(nw_addr)
        key = '%s/%d' % (ip_str, mask)
        self[key] = address

        self.address_id += 1
        self.address_id &= UINT16_MAX
        if self.address_id == COOKIE_DEFAULT_ID:
            self.address_id = 1

        return address

    def delete(self, address_id):
        for key, value in self.items():
            if value.address_id == address_id:
                del self[key]
                return

    def get_default_gw(self):
        return [address.default_gw for address in self.values()]

    def get_data(self, addr_id=None, ip=None):
        for address in self.values():
            if addr_id is not None:
                if addr_id == address.address_id:
                    return address
            else:
                assert ip is not None
                if ipv4_apply_mask(ip, address.netmask) == address.nw_addr:
                    return address
        return None


class Address(object):
    def __init__(self, address_id, nw_addr, netmask, default_gw):
        super(Address, self).__init__()
        self.address_id = address_id
        self.nw_addr = nw_addr
        self.netmask = netmask
        self.default_gw = default_gw

    def __contains__(self, ip):
        return bool(ipv4_apply_mask(ip, self.netmask) == self.nw_addr)


class PolicyRoutingTable(dict):
    def __init__(self):
        super(PolicyRoutingTable, self).__init__()
        self[INADDR_ANY] = RoutingTable()
        self.route_id = 1
        self.dhcp_servers = []

    def add(self, dst_nw_addr, dst_vlan, gateway_ip, src_address=None):
        err_msg = 'Invalid [%s] value.'
        added_route = None
        key = INADDR_ANY

        if src_address is not None:
            ip_str = ip_addr_ntoa(src_address.nw_addr)
            key = '%s/%d' % (ip_str, src_address.netmask)

        if key not in self:
            self.add_table(key, src_address)

        table = self[key]
        added_route = table.add(dst_nw_addr, dst_vlan, gateway_ip, self.route_id)

        if added_route is not None:
            self.route_id += 1
            self.route_id &= UINT16_MAX
            if self.route_id == COOKIE_DEFAULT_ID:
                self.route_id = 1

        return added_route

    def delete(self, route_id):
        for table in self.values():
            table.delete(route_id)
        return

    def add_table(self, key, address):
        self[key] = RoutingTable(address)
        return self[key]

    def gc_subnet_tables(self):
        for key, value in self.items():
            if key != INADDR_ANY:
                if (len(value) == 0):
                    del self[key]
        return

    def get_all_gateway_info(self):
        all_gateway_info = []
        for table in self.values():
            all_gateway_info += table.get_all_gateway_info()
        return all_gateway_info

    def get_data(self, gw_mac=None, dst_ip=None, src_ip=None):
        desired_table = self[INADDR_ANY]

        if src_ip is not None:
            for table in self.values():
                if table.src_address is not None:
                     if (table.src_address.nw_addr == ipv4_apply_mask(src_ip, table.src_address.netmask)):
                         desired_table = table
                         break

        route = desired_table.get_data(gw_mac, dst_ip)

        if ((route is None) and (desired_table != self[INADDR_ANY])):
            route = self[INADDR_ANY].get_data(gw_mac, dst_ip)

        return route


class RoutingTable(dict):
    def __init__(self, address=None):
        super(RoutingTable, self).__init__()
        self.src_address = address

    def add(self, dst_nw_addr, dst_vlan, gateway_ip, route_id):
        err_msg = 'Invalid [%s] value.'

        if dst_nw_addr == INADDR_ANY:
            dst_ip = 0
            dst_netmask = 0
        else:
            dst_ip, dst_netmask, dst_dummy = nw_addr_aton(
                dst_nw_addr, err_msg=err_msg % REST_DESTINATION)

        gateway_ip = ip_addr_aton(gateway_ip, err_msg=err_msg % REST_GATEWAY)

        dst_ip_str = ip_addr_ntoa(dst_ip)
        key = '%s/%d' % (dst_ip_str, dst_netmask)

        # Check overlaps
        overlap_route = None
        if key in self:
            overlap_route = self[key].route_id

        if overlap_route is not None:
            msg = 'Destination overlaps [route_id=%d]' % overlap_route
            raise CommandFailure(msg=msg)

        routing_data = Route(route_id, dst_ip, dst_netmask, dst_vlan, gateway_ip, self.src_address)
        self[key] = routing_data

        return routing_data

    def delete(self, route_id):
        for key, value in self.items():
            if value.route_id == route_id:
                del self[key]
                return

    def get_all_gateway_info(self):
        all_gateway_info = []
        for route in self.values():
            gateway_info = (route.gateway_ip, route.gateway_mac)
            all_gateway_info.append(gateway_info)
        return all_gateway_info

    def get_data(self, gw_mac=None, dst_ip=None):
        if gw_mac is not None:
            for route in self.values():
                if gw_mac == route.gateway_mac:
                    return route
            return None

        elif dst_ip is not None:
            get_route = None
            mask = 0
            for route in self.values():
                if ipv4_apply_mask(dst_ip, route.dst_netmask) == route.dst_ip:
                    # For longest match
                    if mask < route.dst_netmask:
                        get_route = route
                        mask = route.dst_netmask

            if get_route is None:
                get_route = self.get(INADDR_ANY, None)
            return get_route
        else:
            return None


class Route(object):
    def __init__(self, route_id, dst_ip, dst_netmask, dst_vlan, gateway_ip, src_address=None):
        super(Route, self).__init__()
        self.route_id = route_id
        self.dst_ip = dst_ip
        self.dst_netmask = dst_netmask
        self.dst_vlan = dst_vlan
        self.gateway_ip = gateway_ip
        self.gateway_mac = None
        if src_address is None:
            self.src_ip = 0
            self.src_netmask = 0
        else:
            self.src_ip = src_address.nw_addr
            self.src_netmask = src_address.netmask


class SuspendPacketList(list):
    def __init__(self, timeout_function):
        super(SuspendPacketList, self).__init__()
        self.timeout_function = timeout_function

    def add(self, in_port, header_list, data):
        suspend_pkt = SuspendPacket(in_port, header_list, data,
                                    self.wait_arp_reply_timer)
        self.append(suspend_pkt)

    def delete(self, pkt=None, del_addr=None):
        if pkt is not None:
            del_list = [pkt]
        else:
            assert del_addr is not None
            del_list = [pkt for pkt in self if pkt.dst_ip in del_addr]

        for pkt in del_list:
            self.remove(pkt)
            hub.kill(pkt.wait_thread)
            pkt.wait_thread.wait()

    def get_data(self, dst_ip):
        return [pkt for pkt in self if pkt.dst_ip == dst_ip]

    def wait_arp_reply_timer(self, suspend_pkt):
        hub.sleep(ARP_REPLY_TIMER)
        if suspend_pkt in self:
            self.timeout_function(suspend_pkt)
            self.delete(pkt=suspend_pkt)


class SuspendPacket(object):
    def __init__(self, in_port, header_list, data, timer):
        super(SuspendPacket, self).__init__()
        self.in_port = in_port
        self.dst_ip = header_list[IPV4].dst
        self.header_list = header_list
        self.data = data
        # Start ARP reply wait timer.
        self.wait_thread = hub.spawn(timer, self)


class PenaltyBoxList(list):
    def __init__(self):
        super(PenaltyBoxList, self).__init__()
        self._expiry_thread = hub.spawn(self._expire_loop)

    def shutdown(self):
        hub.kill(self._expiry_thread)
        self._expiry_thread.wait()

    def _expire_loop(self):
        while True:
            for entry in self:
                entry.count -= PENALTY_BOX_DRAIN_AMOUNT
                if (entry.count <= 0):
                    self.remove(entry)
                hub.sleep(0)
            hub.sleep(PENALTY_BOX_CHECK_INTERVAL)


class PenaltyBoxEntry(object):
    def __init__(self, in_port=None, dl_type=None, src_ip=None, dst_ip=None):
        super(PenaltyBoxEntry, self).__init__()
        self.in_port = in_port
        self.dl_type = dl_type
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.count = 1
        self.priority = None # Unset, until a rule is inserted.


class MACAddressTable(dict):
    def __init__(self):
        super(MACAddressTable, self).__init__()
        self._expiry_thread = hub.spawn(self._expire_loop)

    def shutdown(self):
        hub.kill(self._expiry_thread)
        self._expiry_thread.wait()

    def _expire_loop(self):
        while True:
            current_time = time.time()
            for mac, entry in self.items():
                if (entry.expire_time < current_time):
                    del self[mac]
                hub.sleep(0)
            hub.sleep(MAC_ADDRESS_GC_INTERVAL)


class MACAddressEntry(object):
    def __init__(self, port):
        super(MACAddressEntry, self).__init__()
        self.port = port
        self.expire_time = (time.time() + MAC_ADDRESS_TTL)
