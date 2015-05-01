#!/usr/bin/env python
#
# Copyright (c) 2015 Catalyst.net Ltd
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
Python sFlow collector.

Michael Fincham <michael.fincham@catalyst.net.nz>
"""

import socket
import time
import xdrlib

class FlowCollector(object):
    """
    Listens for sFlow v5 flow records.
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

    SFLOW_INTERFACE_INTERNAL = 0x3FFFFFFF

    def __init__(self, bind_address='0.0.0.0', bind_port=6343):
        self.sflow_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen_address = (bind_address, bind_port)
        self.sflow_socket.bind(listen_address)

    def _decode_sflow_packet(self, payload):
        """
        Decode an sFlow v5 'flow' packet and return a dict representation.

        >>> packet = '\x00\x00\x00\x05\x00\x00\x00\x01\x7f\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x13\x88\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00d\x00\x00\x00\x01\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00?\xff\xff\xff\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00<\x00\x00\x00\x01\x00\x00\x00.\x00\x00\x00\x04\x00\x00\x00*\xff\xff\xff\xff\xff\xff\xab\xab\xab\xab\xab\xab\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\xab\xab\xab\xab\xab\xab\xc0\x00\x02\x02\x00\x00\x00\x00\x00\x00\xc0\x00\x02\x01\x00\x00'
        >>> collector = FlowCollector()
        >>> collector._decode_sflow_packet(packet)
        {'address_family': 1,
         'agent_address': 2130706689,
         'decoded_at': 1430435127.716034,
         'samples': [{'drops': 0,
                      'flows': [{'frame_length': 46,
                                 'payload': '\xff\xff\xff\xff\xff\xff\xab\xab\xab\xab\xab\xab\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\xab\xab\xab\xab\xab\xab\xc0\x00\x02\x02\x00\x00\x00\x00\x00\x00\xc0\x00\x02\x01',
                                 'protocol': 1,
                                 'stripped': 4}],
                      'input': 1073741823,
                      'output': 4,
                      'sample_pool': 1,
                      'sampling_rate': 1,
                      'sequence_number': 1,
                      'source_id': 4}],
         'sequence_number': 2,
         'sflow_version': 5,
         'sub_agent_id': 0,
         'uptime': 5000}
        """

        payload = xdrlib.Unpacker(payload)
        packet = {}

        packet['decoded_at'] = time.time()
        packet['sflow_version'] = payload.unpack_int()
        packet['address_family'] = payload.unpack_int()
        packet['agent_address'] = payload.unpack_uint()
        packet['sub_agent_id'] = payload.unpack_uint()
        packet['sequence_number'] = payload.unpack_uint()
        packet['uptime'] = payload.unpack_uint()
        packet['samples'] = []

        # sflow packets will contain one or more "sample" records of various
        # types (e.g. flows, interface counters etc)
        for sample_index in range(payload.unpack_uint()):
            sample_type = payload.unpack_uint()
            sample_data = xdrlib.Unpacker(payload.unpack_opaque())

            # only process 'flow' type samples
            # XXX maybe implement other sample types
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

            # "flow"-type samples contain one or more "flows" (truncated
            # packets sampled off the wire w/ metadata)
            for flow_index in range(sample_data.unpack_uint()):
                flow_type = sample_data.unpack_uint()
                flow_data = xdrlib.Unpacker(sample_data.unpack_opaque())

                flow = {}

                flow['protocol'] = flow_data.unpack_int()
                flow['frame_length'] = flow_data.unpack_uint()
                flow['stripped'] = flow_data.unpack_uint()
                flow['payload'] = flow_data.unpack_opaque()

                sample['flows'].append(flow)

            packet['samples'].append(sample)

        return packet

    def receive(self):
        """
        Listen on the sFlow socket, decode incoming packets and yield them.
        """

        while True:
            data, addr = self.sflow_socket.recvfrom(65535)
            yield(self._decode_sflow_packet(data))
