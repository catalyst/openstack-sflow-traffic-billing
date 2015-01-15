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

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

SFLOW_INTERFACE_INTERNAL = 0x3FFFFFFF
NATIONAL_NETWORKS_FILE = "compressed"
BUFFER_FLUSH_INTERVAL = 20 # seconds

DATABASE_CONNECT_STRING = "dbname=traffic user=fincham"

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

def accounting(queue):
    import psycopg2

    database_connection = psycopg2.connect(DATABASE_CONNECT_STRING)
    database_cursor = database_connection.cursor()

    local_networks = [
        ipaddr.IPNetwork('192.168.2.0/24'),
        ipaddr.IPNetwork('192.168.192.0/20'),
    ]

    classified_networks = {
        'local-rfc1918': [
            ipaddr.IPNetwork('192.168.0.0/16'),
            ipaddr.IPNetwork('10.0.0.0/8'),
            ipaddr.IPNetwork('172.16.0.0/12'),
        ],
        'local-catalyst': [
            ipaddr.IPNetwork('103.254.156.0/22'),
            ipaddr.IPNetwork('150.242.40.0/22'),
            ipaddr.IPNetwork('202.78.240.0/21'),
            ipaddr.IPNetwork('2404:130::/32'),
        ],
        'national': [], # will be filled later from file
    }

    unclassifiable_network = 'international' # all that remains

    empty_totals_entry = {
        'inbound': {k:0 for k in classified_networks.keys()+[unclassifiable_network]},
        'outbound': {k:0 for k in classified_networks.keys()+[unclassifiable_network]},
    }

    with open(NATIONAL_NETWORKS_FILE, 'r') as fp:
        for line in fp:
            try:
                classified_networks['national'].append(ipaddr.IPNetwork(line))
            except:
                continue

    sys.stderr.write('%s debug: loaded %i national networks\n' % (time.strftime('%x %X'), len(classified_networks['national'])))

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
                    local_address = ip_layer['dst']
                    remote_address = ip_layer['src']
                else:
                    direction = 'inbound'
                    local_address = ip_layer['src']
                    remote_address = ip_layer['dst']

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

            for address, traffic in totals.iteritems():
                for direction in ('inbound', 'outbound'):
                    for billing in classified_networks.keys()+[unclassifiable_network]:
                        if traffic[direction][billing] > 0:
                            query = "WITH upsert AS (UPDATE traffic SET octets=octets+%(octets)s WHERE address=%(address)s and hour=%(hour)s and direction=%(direction)s and billing=%(billing)s RETURNING *) INSERT INTO traffic(address, hour, direction, billing, octets) SELECT %(address)s, %(hour)s, %(direction)s, %(billing)s, %(octets)s WHERE NOT EXISTS (SELECT * FROM upsert);"
                            database_cursor.execute(
                                query,
                                {
                                    'octets': traffic[direction][billing],
                                    'address': str(address),
                                    'hour': _struct_time_without_minutes(time.localtime()),
                                    'direction': direction,
                                    'billing': billing
                                }
                            )

            database_connection.commit()
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
