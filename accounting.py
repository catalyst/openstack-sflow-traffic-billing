#!/usr/bin/env python
#
# Copyright (c) 2014 Catalyst.net Ltd
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

"""
Use sFlow flow records to classify billable OpenStack traffic and submit this
to ceilometer.

Michael Fincham <michael.fincham@catalyst.net.nz>.

This file is licensed under the GNU General Public License version 3.
"""

import ConfigParser
import copy
import datetime
import ipaddr
import multiprocessing
import pprint
import sqlite3
import sys
import time

# XXX remove when debugging is complete
import pdb

# scapy sometimes throws uninteresting warnings when processing the truncated
# packets provided by sFlow, they are not important in this context
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
import ceilometerclient.client
import neutronclient.v2_0.client

import sflow


class ForkedPdb(pdb.Pdb):
    """
    A Pdb subclass that may be used from a forked multiprocessing child.

    Borrowed from <http://stackoverflow.com/a/23654936> for debugging.
    """

    def interaction(self, *args, **kwargs):
        _stdin = sys.stdin
        try:
            sys.stdin = file('/dev/stdin')
            pdb.Pdb.interaction(self, *args, **kwargs)
        finally:
            sys.stdin = _stdin

def _debug(message, *args, **kwargs):
    """
    Write debugging message to stdout with a timestamp.

    XXX To be removed and replaced with logging module.
    """

    sys.stderr.write("%s debug: %s\n" % (time.strftime('%x %X'), message.format(*args, **kwargs)))

def _sum_header_lengths(flow):
    """
    Return the sum of the byte lengths of the contiguous Ethernet and Dot1Q
    headers in a flow sample.
    """

    HEADER_LENGTHS = {
        'Ether': 14, # bytes
        'Dot1Q': 4, # bytes
    }

    length = 0

    for layer in flow['layers']:
        if layer['decoded_as'] not in HEADER_LENGTHS: # Only count the contiguous
            return length                             # Ether and Dot1Q headers at the
                                                      # beginning of the sample

        length += HEADER_LENGTHS[layer['decoded_as']]

    return length

def _find_first_layer(layers, layer_decoded_as):
    """
    Return the first layer of a certain type from a set of layers.
    """

    for layer in layers:
        if layer['decoded_as'] == layer_decoded_as:
            return layer

    return None

def _address_in_network_list(address, networks):
    """
    Returns true if address is within any of the networks.
    """

    return any([address in network for network in networks])

def _neutron_client(region):
    """
    Returns an instance of the OpenStack Neutron client for the given region.
    Authentication details are taken from the environment (usually these would
    be provided by an OpenStack RC file).
    """

    return neutronclient.v2_0.client.Client(
        username = os.getenv('OS_USERNAME'),
        password = os.getenv('OS_PASSWORD'),
        tenant_name = os.getenv('OS_TENANT_NAME'),
        auth_url = os.getenv('OS_AUTH_URL'),
        region_name = region,
        insecure = os.getenv('OS_INSECURE'),
    )

def _ceilometer_client(region):
    """
    Returns an instance of the OpenStack Ceilometer client for the given region.
    """

    return ceilometerclient.client.get_client(
        '2',
        os_username = os.getenv('OS_USERNAME'),
        os_password = os.getenv('OS_PASSWORD'),
        os_tenant_name = os.getenv('OS_TENANT_NAME'),
        os_auth_url = os.getenv('OS_AUTH_URL'),
        os_region_name = region,
        insecure = os.getenv('OS_INSECURE'),
    )

def _neutron_floating_ip_list(clients):
    """
    Return a list of all the floating IPs across a given list of clients along
    with the associated tenant_id and floating IP address id.

    >>> clients = [_neutron_client('test-1'), _neutron_client('test-2')]
    >>> _neutron_floating_ip_list(clients)
    {u'192.0.2.1': {'id': u'c60bd278-ed5c-4897-9e64-badd2073f96d',
                         'tenant_id': u'ef3e926be03016dc6756f7ecd82498a2',
                         'type': 'floating',
                         'region': 'test-1'},
     u'192.0.2.2': {'id': u'd8b710eb-efa9-49ff-aa27-f731ad96a63b',
                         'tenant_id': u'060cca3aa4c2198f8ff3183e99dc2d9f',
                         'type': 'floating',
                         'region': 'test-1'}}
    """

    ip_list = {}

    # collect up the list of floating IPs for each client in the list along with
    # the tenant they belong to
    for region, components in clients.iteritems():
        ip_list.update({
            ip['floating_ip_address']: {'region': region, 'tenant_id': ip['tenant_id'], 'id': ip['id'], 'type': 'floating'} for ip in components['neutron'].list_floatingips()['floatingips']
        })

    _debug("loaded %i OpenStack floating IPs" % len(ip_list.keys()))
    return ip_list

def _neutron_router_ip_list(clients):
    """
    Return a list of all the router IPs across a given list of clients along
    with the associated tenant_id and router id.

    XXX Currently this function is rather inelegant and would benefit from some
    expert attention.

    >>> clients = [_neutron_client('test-1'), _neutron_client('test-2')]
    >>> _neutron_router_ip_list(clients)
    {u'192.0.2.1': {'id': u'd68d3e4a-ddc4-4113-82ec-59a0f445ed58',
                         'tenant_id': u'b14a61424d89c3e25bb31082b5f34dd7',
                         'type': 'router',
                         'region': 'test-1'},
     u'192.0.2.2': {'id': u'2832bbe0-0597-440b-a8d0-b7cd5108c252',
                         'tenant_id': u'adb73920d5525d53a8f0feb005a5dca9',
                         'type': 'router',
                         'region': 'test-1'}}
    """

    ip_list = {}

    for region, components in clients.iteritems():
        client = components['neutron']

        external_networks = [
            network for network in client.list_networks()['networks'] if network['router:external']
        ]
        external_subnets = sum([network['subnets'] for network in external_networks], [])

        ports = client.list_ports()['ports'] # get all ports in region for all devices
        routers = {router['id']: router for router in client.list_routers()['routers']} # and get all routers

        for port in ports:
            if port['device_id'] in routers: # if the port belongs to a router...

                # ... extract the IPs belonging to the port and check if they
                # belong to a subnet which is part of an "external" network
                external_ips = [
                    ip['ip_address'] for ip in port['fixed_ips'] if ip['subnet_id'] in external_subnets
                ]

                tenant_id = routers[port['device_id']]['tenant_id']

                # generate an ip_list compatible with the floating IP list, except here the
                # id refers to the router itself rather than an IP address object
                ip_list.update({
                    ip: {'region': region, 'tenant_id': tenant_id, 'id': port['device_id'], 'type': 'router'} for ip in external_ips
                })

    _debug("loaded %i OpenStack router IPs" % len(ip_list.keys()))

    return ip_list

def _neutron_ip_list(clients):
    """
    Collect all IPs that are interesting for billing from both floating IPs
    and routers and return an aggregate dictionary.
    """

    ip_list = _neutron_floating_ip_list(clients)
    ip_list.update(_neutron_router_ip_list(clients))
    return ip_list

def _load_networks_from_file(filename):
    """
    Load a list of IPv4 and IPv6 networks from filename and return a list of
    IPNetwork objects corresponding to any valid networks in the file.
    """

    networks = []

    with open(filename, 'r') as fp:
        for line in fp:

            # validate network by parsing it and skip if it doesn't validate
            try:
                networks.append(ipaddr.IPNetwork(line.strip()))
            except:
                continue

    _debug("loaded %i networks from %s" % (len(networks), filename))

    return networks


def accounting(queue):
    """
    Run as a multiprocessing.Process given a multiprocessing.Queue in which
    decoded sFlow packets will be inserted.

    Processes the queued sFlow packets, classifies the traffic and periodically
    sends updates to ceilometer.

    IPs which move between tenants during the buffer_flush_interval will be ignored.

    Records sent to ceilometer will be of the form:

    78000 octets for IP 192.0.2.1 (id=906116c9-2caf-4360-b567-f4822e861bea, tenant_id=5ab78936f80a827b09dc077b372d4514) to traffic.inbound.international
    """

    config = ConfigParser.ConfigParser(allow_no_value=True)
    config.read('accounting.cfg')

    # samples that cannot be submitted immediately to ceilometer go in to the queue
    local_queue_conn = sqlite3.connect(config.get('settings', 'local-queue'))
    local_queue_cursor = local_queue_conn.cursor()
    local_queue_cursor.execute("""
        CREATE TABLE IF NOT EXISTS `queue` (
            `octets`    INTEGER NOT NULL,
            `address`   TEXT NOT NULL,
            `object_id` TEXT NOT NULL,
            `tenant_id` TEXT NOT NULL,
            `direction` TEXT NOT NULL,
            `billing`   TEXT NOT NULL,
            `region`    TEXT NOT NULL,
            `created`   INTEGER NOT NULL,
            `id`    INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT
        );
    """)
    local_queue_conn.commit()

    # the number of seconds between submissions to ceilometer
    buffer_flush_interval = int(config.get('settings','buffer-flush-interval'))

    # connect to neutron and ceilometer for all regions where accting is desired
    clients = {
        region[0].strip(): {'neutron': _neutron_client(region[0].strip()), 'ceilometer': _ceilometer_client(region[0].strip())} for region in config.items('regions')
    }

    # local_networks is the list of addresses at the local site that will be accounted
    local_networks = _load_networks_from_file(config.get('settings','local-networks'))

    # networks which will get a particular classification
    classified_networks = {classification: _load_networks_from_file(networks) for classification, networks in config.items('classifications')}
    unclassifiable_network = config.get('settings','unclassifiable') # fall back if no classification possible

    # query OpenStack for the mappings of IP address to tenant so it can be checked later
    # this allows an IP address to move between tenants during a buffer_flush_interval
    # without the wrong tenant being billed for part of the traffic (the interval will instead
    # be discarded)
    old_ip_ownership = _neutron_ip_list(clients)

    empty_totals_entry = {
        'inbound': {k:0 for k in classified_networks.keys()+[unclassifiable_network]},
        'outbound': {k:0 for k in classified_networks.keys()+[unclassifiable_network]},
    }

    timestamp = int(time.time())
    totals = {}

    while True:
        sflow_packet = queue.get()

        # "samples" can be of several types, only "flow" samples will end up here
        # XXX add checks so sflow code can be made more generic
        for sample in sflow_packet['samples']:

            # every "flow" corresponds to a truncated packet pulled off the wire
            # on one of the agents (e.g. routers)
            for flow in sample['flows']:
                ip_layer = _find_first_layer(flow['layers'], 'IP')

                if ip_layer is None: # ignore packets without an IP header as
                    continue         # they won't have a source or destination address

                ip_layer['src'] = ipaddr.IPAddress(ip_layer['src'])
                ip_layer['dst'] = ipaddr.IPAddress(ip_layer['dst'])

                # determine whether or not the packet was sampled inbound or outbound
                # on the agent interface. agent interfaces should face transit providers,
                # so this direction is also relative to the AS where this runs.
                if sample['input'] == sflow.FlowCollector.SFLOW_INTERFACE_INTERNAL:
                    direction = 'outbound'
                    local_address = ip_layer['src']
                    remote_address = ip_layer['dst']
                else:
                    direction = 'inbound'
                    local_address = ip_layer['dst']
                    remote_address = ip_layer['src']

                # ignore addresses not in the "local-networks" set, this will
                # ignore transit packets
                if not _address_in_network_list(local_address, local_networks):
                    continue

                billing = None

                # determine which billing class the packet belongs to, if any
                for network_class, networks_in_class in classified_networks.iteritems():
                    if _address_in_network_list(remote_address, networks_in_class):
                        billing = network_class
                        break

                if not billing:
                    billing = unclassifiable_network

                if local_address not in totals:
                    totals[local_address] = copy.deepcopy(empty_totals_entry)

                # multiply the original length of the packetby the sampling
                # rate to produce an estimate of the "real world" traffic it
                # represents then increment the totals with that amount (in octets)
                totals[local_address][direction][billing] += (flow['frame_length'] - flow['stripped'] - _sum_header_lengths(flow)) * sample['sampling_rate']

        if time.time() - timestamp >= buffer_flush_interval and len(totals) > 0:
            start_time = time.time()
            _debug("sending ceilometer data for %i local IPs" % len(totals))

            # re-request the mapping of IP addresses to tenants from OpenStack
            new_ip_ownership = _neutron_ip_list(clients)

            # addresses where the owner tenant is no longer the same as the beginning
            # of this interval are removed from the totals to be submitted
            for address, details in new_ip_ownership.iteritems():
                if address in old_ip_ownership and old_ip_ownership[address]['tenant_id'] != details['tenant_id']:
                    _debug("ownership of %s changed during period" % address)
                    totals.pop(address, None)

            old_ip_ownership = new_ip_ownership

            for address, traffic in totals.iteritems():
                address_string = str(address)

                if address_string not in new_ip_ownership:
                    _debug("%s not a tenant or router IP, ignoring" % address)
                    continue

                for direction in ('inbound', 'outbound'):
                    for billing in classified_networks.keys()+[unclassifiable_network]:
                        if traffic[direction][billing] > 0:

                            # XXX ceilometer submission will happen here
                            _debug("ceilometer record - %(octets)s octets by %(address)s (id=%(id)s, tenant_id=%(tenant_id)s) to traffic.%(direction)s.%(billing)s in region %(region)s\n" % {
                                'octets': traffic[direction][billing],
                                'address': address_string,
                                'id': new_ip_ownership[address_string]['id'],
                                'tenant_id': new_ip_ownership[address_string]['tenant_id'],
                                'direction': direction,
                                'billing': billing,
                                'region': new_ip_ownership[address_string]['region'],
                            })


                            try:
                                clients[new_ip_ownership[address_string]['region']]['ceilometer'].samples.create(
                                    source='Traffic accounting',
                                    counter_name='traffic.%s.%s' % (direction, billing),
                                    counter_type='delta',
                                    counter_unit='byte',
                                    counter_volume=traffic[direction][billing],
                                    project_id=new_ip_ownership[address_string]['tenant_id'],
                                    resource_id=new_ip_ownership[address_string]['id'],
                                    timestamp=datetime.datetime.utcnow().isoformat(),
                                    resource_metadata={}
                                )
                            except:
                                _debug("ceilometer submit failed, putting in database instead")
                                local_queue_cursor.execute(
                                    "INSERT INTO queue VALUES(?, ?, ?, ?, ?, ?, ?, 'now', None);",
                                    (
                                        traffic[direction][billing],
                                        address_string,
                                        new_ip_ownership[address_string]['id'],
                                        new_ip_ownership[address_string]['tenant_id'],
                                        direction,
                                        billing,
                                        new_ip_ownership[address_string]['region'],
                                    ),
                                )

                local_queue_conn.commit()


            _debug("ceilometer send complete, took %f seconds" % (time.time() - start_time))
            _debug("queue is now %i entries long" % queue.qsize())

            totals = {}
            timestamp = int(time.time())


if __name__ == '__main__':

    _debug("starting sFlow and accounting processes...")

    accounting_packet_queue = multiprocessing.Queue()
    accounting_process = multiprocessing.Process(
        target=accounting, args=(accounting_packet_queue,)
    )
    accounting_process.start()

    collector = sflow.FlowCollector()

    # receieve sFlow packets from the network and send them to the accounting process
    for packet in collector.receive():
        accounting_packet_queue.put(packet)

    accounting_process.join()
