#!/usr/bin/env python

import time
import datetime
import socket
from xdrlib import Unpacker
from multiprocessing import Process, Queue
import ipaddr
import sys
import pprint
import pickle
import copy
import ConfigParser
import neutronclient.v2_0.client

import pdb
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

SFLOW_INTERFACE_INTERNAL = 0x3FFFFFFF
NATIONAL_NETWORKS_FILE = "compressed"
BUFFER_FLUSH_INTERVAL = 20 # seconds

class ForkedPdb(pdb.Pdb):
    """A Pdb subclass that may be used
    from a forked multiprocessing child

    """
    def interaction(self, *args, **kwargs):
        _stdin = sys.stdin
        try:
            sys.stdin = file('/dev/stdin')
            pdb.Pdb.interaction(self, *args, **kwargs)
        finally:
            sys.stdin = _stdin

class FlowCollector(object):
    """
    Listens for sFlow v5 flow records and decodes them as deeply as possible with scapy.
    """

    SFLOW_SAMPLE_TYPES = {
        'flow': 1,
        'counter': 2,
    }

    TCP_LONG_FLAGS = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PSH',
        'A': 'ACK',
        'U': 'URG',
        'E': 'ECE',
        'C': 'CWR',
    }

    PACKET_RECURSION_LIMIT = 10

    def __init__(self, bind_address='0.0.0.0', bind_port=6343):
        self.sflow_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen_address = (bind_address, bind_port)
        self.sflow_socket.bind(listen_address)

    def _flatten_scapy_payload(self, payload):
        """
        Flatten all layers of a given scapy payload in to an ordered list that
        is safe to pickle.
        """

        payloads = []

        for layer_index in range(0, self.PACKET_RECURSION_LIMIT):
            layer = payload.getlayer(layer_index)

            if not layer: # there are no more layers
                break

            decoded_layer = {'decoded_as': type(layer).__name__}

            if decoded_layer['decoded_as'] == 'TCP':
                decoded_layer['decoded_flags'] = [self.TCP_LONG_FLAGS[x] for x in layer.sprintf('%TCP.flags%')]

            # in some instances scapy includes fields which are further
            # packets and other stuff that can't be pickled and sent over the
            # multiprocessing queue. flatten them to their __repr__ for now.

            # XXX it would be nice to have a more elegant solution

            for key, value in layer.fields.iteritems():

                try:
                    pickle.dumps(value)
                    pickle_ok = True
                except:
                    pickle_ok = False

                if pickle_ok:
                    decoded_layer[key] = value
                else:
                    decoded_layer[key] = repr(value)

            payloads.append(decoded_layer)

        return payloads

    def _decode_sflow_packet(self, payload):
        """
        Decode an sFlow v5 packet and return a dict of its fields.
        """

        packet = {}

        packet['decoded_at'] = time.time()
        packet['sflow_version'] = payload.unpack_int()
        packet['address_family'] = payload.unpack_int()
        packet['agent_address'] = payload.unpack_uint()
        packet['sub_agent_id'] = payload.unpack_uint()
        packet['sequence_number'] = payload.unpack_uint()
        packet['uptime'] = payload.unpack_uint()
        packet['samples'] = []

        for sample_index in range(payload.unpack_uint()):
            sample_type = payload.unpack_uint()
            sample_data = Unpacker(payload.unpack_opaque())

            # only process 'flow' type samples
            if sample_type != self.SFLOW_SAMPLE_TYPES['flow']:
                continue

            sample = {}

            sample['sequence_number'] = sample_data.unpack_uint()
            sample['source_id'] = sample_data.unpack_uint()
            sample['sampling_rate'] = sample_data.unpack_uint()
            sample['sample_pool'] = sample_data.unpack_uint()
            sample['drops'] = sample_data.unpack_uint()
            sample['input'] = sample_data.unpack_uint()
            sample['output'] = sample_data.unpack_uint()
            sample['flows'] = []

            for flow_index in range(sample_data.unpack_uint()):
                flow_type = sample_data.unpack_uint()
                flow_data = Unpacker(sample_data.unpack_opaque())

                flow = {}

                flow['protocol'] = flow_data.unpack_int()
                flow['frame_length'] = flow_data.unpack_uint()
                flow['stripped'] = flow_data.unpack_uint()

                # parse the raw flow with scapy
                flow_packet = Ether(flow_data.unpack_opaque())

                # flatten out the nested payloads in the parsed flow
                flow['layers'] = self._flatten_scapy_payload(flow_packet)
                flow['summary'] = flow_packet.summary()

                sample['flows'].append(flow)

            packet['samples'].append(sample)

        return packet

    def receive(self):
        """
        Listen on the sFlow socket, decode incoming packets and yield them.
        """

        while True:
            data, addr = self.sflow_socket.recvfrom(65535)
            yield(self._decode_sflow_packet(Unpacker(data)))

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

        if time.time() - timestamp >= BUFFER_FLUSH_INTERVAL:
            start_time = time.time()
            sys.stderr.write("%s debug: doing db flush of %i local IPs\n" % (time.strftime('%x %X'), len(totals)))

            new_ip_ownership = _neutron_ip_list(neutron_clients)

            for address, details in new_ip_ownership.iteritems():
                if address in old_ip_ownership and old_ip_ownership[address]['tenant_id'] == details['tenant_id']:
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

    accounting_packet_queue = Queue()
    accounting_process = Process(target=accounting, args=(accounting_packet_queue,))
    accounting_process.start()

    collector = FlowCollector()

    for packet in collector.receive():
        # pprint.pprint(packet)
        accounting_packet_queue.put(packet)

    accounting_process.join()
