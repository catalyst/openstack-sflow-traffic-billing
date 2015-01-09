#!/usr/bin/env python

import time
import socket
from xdrlib import Unpacker
from scapy.all import *

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

    def __init__(self, bind_address='0.0.0.0', bind_port=6343):
        self.sflow_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen_address = (bind_address, bind_port)
        self.sflow_socket.bind(listen_address)

    def _decode_with_scapy(self, payload):
        """
        Recursively decode a raw packet using scapy, returning a dict of all
        the packet and its subequent decoded payload packets fields.
        """

        packet = payload.fields
        packet['decoded_as'] = type(payload).__name__

        if packet['decoded_as'] == 'TCP':
            packet['decoded_flags'] = [self.TCP_LONG_FLAGS[x] for x in payload.sprintf('%TCP.flags%')]

        if payload.payload:
            packet['payload'] = self._decode_with_scapy(payload.payload)

        return packet

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
        packet['samples_count'] = payload.unpack_uint()

        samples = []

        for sample_index in range(packet['samples_count']):
            sample_type = payload.unpack_uint()
            sample_data = Unpacker(payload.unpack_opaque())

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

            flows_count = sample_data.unpack_uint()
            flows = []

            for flow_index in range(flows_count):
                flow_type = sample_data.unpack_uint()
                flow_data = Unpacker(sample_data.unpack_opaque())

                flow = {}

                flow['protocol'] = flow_data.unpack_int()
                flow['frame_length'] = flow_data.unpack_uint()
                flow['stripped'] = flow_data.unpack_uint()
                flow_packet = Ether(flow_data.unpack_opaque())
                flow['packet'] = self._decode_with_scapy(flow_packet)
                flow['summary'] = flow_packet.summary()

                flows.append(flow)

            sample['flows'] = flows
            samples.append(sample)

        packet['samples'] = samples

        return packet

    def receive(self):
        """
        Listen on the sFlow socket and decode incoming packets then yield them.
        """

        while True:
            data, addr = self.sflow_socket.recvfrom(65535)
            yield(self._decode_sflow_packet(Unpacker(data)))

if __name__ == '__main__':
    import pprint

    collector = FlowCollector()

    for packet in collector.receive():
        pprint.pprint(packet)
