#!/usr/bin/env python

"""
Use sFlow flow records to classify billable OpenStack traffic and submit this
to ceilometer.

Michael Fincham <michael.fincham@catalyst.net.nz>
"""

import ConfigParser
import copy
import datetime
import ipaddr
import multiprocessing
import pprint
import sys
import time

import pdb
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
import neutronclient.v2_0.client

import sflow

SFLOW_INTERFACE_INTERNAL = 0x3FFFFFFF

class ForkedPdb(pdb.Pdb):
    """
    A Pdb subclass that may be used
    from a forked multiprocessing child
    """

    def interaction(self, *args, **kwargs):
        _stdin = sys.stdin
        try:
            sys.stdin = file('/dev/stdin')
            pdb.Pdb.interaction(self, *args, **kwargs)
        finally:
            sys.stdin = _stdin

def _sum_header_lengths(flow):
    """
    Return the sum of the lengths of the contiguous Ethernet and Dot1Q headers
    of a flow.
    """

    HEADER_LENGTHS = {
        'Ether': 14,
        'Dot1Q': 4,
    }

    length = 0

    for layer in flow['layers']:
        if layer['decoded_as'] not in HEADER_LENGTHS:
            return length

        length += HEADER_LENGTHS[layer['decoded_as']]

    return length

def _find_first_layer(layers, layer_decoded_as):
    for layer in layers:
        if layer['decoded_as'] == layer_decoded_as:
            return layer

    return None

def _address_in_network_list(address, networks):
    return any([address in network for network in networks])

def _struct_time_without_minutes(struct_time):
    return datetime.datetime(*struct_time[:4])

def _neutron_client(region):
    return neutronclient.v2_0.client.Client(
        username = os.getenv('OS_USERNAME'),
        password = os.getenv('OS_PASSWORD'),
        tenant_name = os.getenv('OS_TENANT_NAME'),
        auth_url = os.getenv('OS_AUTH_URL'),
        region_name = region,
        insecure = os.getenv('OS_NEUTRON_INSECURE'),
    )

def _neutron_floating_ip_list(clients):
    ip_list = {}


    for client in clients:
        ip_list.update({
            ip['floating_ip_address']: {'tenant_id': ip['tenant_id'], 'id': ip['id'], 'type': 'floating'} for ip in client.list_floatingips()['floatingips']
        })

    sys.stderr.write('%s debug: loaded %i OpenStack floating IPs\n' % (time.strftime('%x %X'), len(ip_list.keys())))
    return ip_list

def _neutron_router_ip_list(clients):
    """
    XXX this function is a mess, please refactor it
    """

    ip_list = {}

    for client in clients:
        external_networks = [network for network in client.list_networks()['networks'] if network['router:external']]
        external_subnets = sum([network['subnets'] for network in external_networks], [])

        ports = client.list_ports()['ports']
        routers = {router['id']: router for router in client.list_routers()['routers']}

        for port in ports:
            if port['device_id'] in routers:
                external_ips = [ip['ip_address'] for ip in port['fixed_ips'] if ip['subnet_id'] in external_subnets]
                tenant_id = routers[port['device_id']]['tenant_id']

                ip_list.update({
                    ip: {'tenant_id': tenant_id, 'id': port['device_id'], 'type': 'router'} for ip in external_ips
                })

    sys.stderr.write('%s debug: loaded %i OpenStack router IPs\n' % (time.strftime('%x %X'), len(ip_list.keys())))

    return ip_list

def _neutron_ip_list(clients):
    ip_list = _neutron_floating_ip_list(clients)
    ip_list.update(_neutron_router_ip_list(clients))
    return ip_list

def _load_networks_from_file(filename):
    networks = []

    with open(filename, 'r') as fp:
        for line in fp:
            try:
                networks.append(ipaddr.IPNetwork(line.strip()))
            except:
                continue

    sys.stderr.write('%s debug: loaded %i networks from %s\n' % (time.strftime('%x %X'), len(networks), filename))

    return networks


def accounting(queue):

    config = ConfigParser.ConfigParser(allow_no_value=True)
    config.read('accounting.cfg')

    buffer_flush_interval = int(config.get('settings','buffer-flush-interval'))

    neutron_clients = [_neutron_client(region[0].strip()) for region in config.items('regions')]

    local_networks = _load_networks_from_file(config.get('settings','accounted-networks'))
    classified_networks = {classification: _load_networks_from_file(networks) for classification, networks in config.items('classifications')}
    unclassifiable_network = config.get('settings','unclassifiable')

    old_ip_ownership = _neutron_ip_list(neutron_clients)

    empty_totals_entry = {
        'inbound': {k:0 for k in classified_networks.keys()+[unclassifiable_network]},
        'outbound': {k:0 for k in classified_networks.keys()+[unclassifiable_network]},
    }

    timestamp = int(time.time())
    totals = {}

    while True:
        sflow_packet = queue.get()

        for sample in sflow_packet['samples']:
            for flow in sample['flows']:
                ip_layer = _find_first_layer(flow['layers'], 'IP')

                if ip_layer is None:
                    continue

                ip_layer['src'] = ipaddr.IPAddress(ip_layer['src'])
                ip_layer['dst'] = ipaddr.IPAddress(ip_layer['dst'])

                if sample['input'] == SFLOW_INTERFACE_INTERNAL:
                    direction = 'outbound'
                    local_address = ip_layer['src']
                    remote_address = ip_layer['dst']
                else:
                    direction = 'inbound'
                    local_address = ip_layer['dst']
                    remote_address = ip_layer['src']

                if not _address_in_network_list(local_address, local_networks):
                    continue

                billing = None

                for network_class, networks_in_class in classified_networks.iteritems():
                    if _address_in_network_list(remote_address, networks_in_class):
                        billing = network_class
                        break

                if not billing:
                    billing = unclassifiable_network

                if local_address not in totals:
                    totals[local_address] = copy.deepcopy(empty_totals_entry)

                totals[local_address][direction][billing] += (flow['frame_length'] - flow['stripped'] - _sum_header_lengths(flow)) * sample['sampling_rate']

        if time.time() - timestamp >= buffer_flush_interval:
            start_time = time.time()
            sys.stderr.write("%s debug: doing db flush of %i local IPs\n" % (time.strftime('%x %X'), len(totals)))

            new_ip_ownership = _neutron_ip_list(neutron_clients)

            for address, details in new_ip_ownership.iteritems():
                if address in old_ip_ownership and old_ip_ownership[address]['tenant_id'] != details['tenant_id']:
                    sys.stderr.write("%s debug: ownership of %s changed during period\n" % (time.strftime('%x %X'), address))
                    totals.pop(address, None)

            old_ip_ownership = new_ip_ownership

            for address, traffic in totals.iteritems():
                address_string = str(address)

                if address_string not in new_ip_ownership:
                    sys.stderr.write("%s debug: %s not a tenant IP, ignoring\n" % (time.strftime('%x %X'), address))
                    continue

                for direction in ('inbound', 'outbound'):
                    for billing in classified_networks.keys()+[unclassifiable_network]:
                        if traffic[direction][billing] > 0:
                            sys.stderr.write("Ceilometer: %(octets)s octets by %(address)s (id=%(id)s, tenant_id=%(tenant_id)s) to traffic.%(direction)s.%(billing)s\n" % {                                'octets': traffic[direction][billing],
                                'address': address_string,
                                'id': new_ip_ownership[address_string]['id'],
                                'tenant_id': new_ip_ownership[address_string]['tenant_id'],
                                'direction': direction,
                                'billing': billing
                            })

                            # database_connection.commit()
            sys.stderr.write("%s debug: db flush complete, took %f seconds.\n" % (time.strftime('%x %X'), time.time() - start_time))
            sys.stderr.write("%s debug: queue is now %i entries long.\n" % (time.strftime('%x %X'), queue.qsize()))

            totals = {}
            timestamp = int(time.time())


if __name__ == '__main__':

    accounting_packet_queue = multiprocessing.Queue()
    accounting_process = multiprocessing.Process(target=accounting, args=(accounting_packet_queue,))
    accounting_process.start()

    collector = sflow.FlowCollector()

    for packet in collector.receive():
        accounting_packet_queue.put(packet)

    accounting_process.join()
