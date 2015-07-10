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
Use sFlow flow records to classify billable OpenStack traffic and submit this
to ceilometer.

Michael Fincham <michael.fincham@catalyst.net.nz>
"""

import collections
import ConfigParser
import copy
import datetime
import logging
import multiprocessing
import os
import sqlite3
import sys
import time

# XXX remove when debugging is complete
import pdb

import ipaddr
import ceilometerclient.client
import neutronclient.v2_0.client

import sflow

from ethernet import Frame

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


class AccountingCollector(object):
    """
    Processes incoming packets and submits samples to Ceilometer.
    """
    
    SFLOW_INTERFACE_INTERNAL = 0x3FFFFFFF

    @staticmethod
    def _address_in_network_list(address, networks):
        """
        Returns true if address is within any of the networks.
        """

        return any([address in network for network in networks])

    @staticmethod
    def _neutron_client(region):
        """
        Returns an instance of the OpenStack Neutron client for the given region.
        Authentication details are taken from the environment (usually these would
        be provided by an OpenStack RC file).
        """

        try:
            return neutronclient.v2_0.client.Client(
                username = os.getenv('OS_USERNAME'),
                password = os.getenv('OS_PASSWORD'),
                tenant_name = os.getenv('OS_TENANT_NAME'),
                auth_url = os.getenv('OS_AUTH_URL'),
                region_name = region,
                insecure = os.getenv('OS_INSECURE'),
            )
        except:
            raise Exception("Unable to create neutron client - is your environment set correctly?")

    @staticmethod
    def _ceilometer_client(region):
        """
        Returns an instance of the OpenStack Ceilometer client for the given region.
        """

        try:
            return ceilometerclient.client.get_client(
                '2',
                os_username = os.getenv('OS_USERNAME'),
                os_password = os.getenv('OS_PASSWORD'),
                os_tenant_name = os.getenv('OS_TENANT_NAME'),
                os_auth_url = os.getenv('OS_AUTH_URL'),
                os_region_name = region,
                insecure = os.getenv('OS_INSECURE'),
            )
        except:
            raise Exception("Unable to create ceilometer client - is your environment set correctly?")


    def _mark_success(self, success_file_name, content=None):
        """
        Touch a file, optionally writing some content to it as well.
        """

        with open(success_file_name, 'w') as success_file:
            os.utime(success_file_name, None)
            if content:
                success_file.write(content)

    def _neutron_floating_ip_list(self):
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
        for region, components in self.clients.iteritems():
            ip_list.update({
                ip['floating_ip_address']: {'region': region, 'tenant_id': ip['tenant_id'], 'id': ip['id'], 'type': 'floating'} for ip in components['neutron'].list_floatingips()['floatingips']
            })

        logging.info("loaded %i OpenStack floating IPs" % len(ip_list.keys()))
        return ip_list

    def _neutron_router_ip_list(self):
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

        for region, components in self.clients.iteritems():
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

        logging.info("loaded %i OpenStack router IPs" % len(ip_list.keys()))

        return ip_list

    def _neutron_ip_list(self):
        """
        Collect all IPs that are interesting for billing from both floating IPs
        and routers and return an aggregate dictionary.
        """

        ip_list = self._neutron_floating_ip_list()
        ip_list.update(self._neutron_router_ip_list())
        return ip_list

    def _load_networks_from_file(self, filename):
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

        logging.info("loaded %i networks from %s" % (len(networks), filename))

        return networks


    def __init__(self, queue):
        self.queue = queue
        self.config = ConfigParser.ConfigParser(allow_no_value=True)
        try:
            self.config.read('accounting.cfg')
        except:
            raise Exception("unable to read `accounting.cfg'")

        # samples that cannot be submitted immediately to ceilometer go in to the queue

        try:
            self.local_queue_conn = sqlite3.connect(self.config.get('settings', 'local-queue'))
            self.local_queue_cursor = self.local_queue_conn.cursor()
            self.local_queue_cursor.execute("""
                CREATE TABLE IF NOT EXISTS `queue` (
                    `counter_name` TEXT NOT NULL,
                    `counter_volume` INTEGER NOT NULL,
                    `project_id` TEXT NOT NULL,
                    `resource_id` TEXT NOT NULL,
                    `region` TEXT NOT NULL,
                    `created`   INTEGER NOT NULL,
                    `id`    INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT
                );
            """)
            self.local_queue_conn.commit()
        except:
            raise Exception("unable to open disk cache sqlite database %s" % self.config.get('settings', 'local-queue'))

        # file to touch on ceilometer submission success, for interim monitoring
        self.success_file = self.config.get('settings','success-file')
        # file in to which undesirable queue length will be reported
        self.queue_length_file = self.config.get('settings','queue-length-file')

        # the number of seconds between submissions to ceilometer
        self.buffer_flush_interval = int(self.config.get('settings','buffer-flush-interval'))

        # connect to neutron and ceilometer for all regions where accting is desired
        try:
            self.clients = {
                region[0].strip(): {'neutron': self._neutron_client(region[0].strip()), 'ceilometer': self._ceilometer_client(region[0].strip())} for region in self.config.items('regions')
            }
        except:
            raise Exception("unable to create any OpenStack client connections - is your auth environment right?")

        # local_networks is the list of addresses at the local site that will be accounted
        try:
            self.local_networks = self._load_networks_from_file(self.config.get('settings','local-networks'))
        except:
            raise Exception("unable to load list of local networks from %s" % self.config.get('settings','local-networks'))

        # networks which will get a particular classification
        try:
            self.classified_networks = {classification: self._load_networks_from_file(networks) for classification, networks in self.config.items('classifications')}
            self.unclassifiable_network = self.config.get('settings','unclassifiable') # fall back if no classification possible
        except:
            raise Exception("unable to load network classifications")

    def process_queue(self):
        """
        Processes the queued sFlow packets, classifies the traffic and periodically
        sends updates to ceilometer.

        IPs which move between tenants during the buffer_flush_interval will be ignored.

        Records sent to ceilometer will be of the form:

        78000 octets for IP 192.0.2.1 (id=906116c9-2caf-4360-b567-f4822e861bea, tenant_id=5ab78936f80a827b09dc077b372d4514) to traffic.inbound.international
        """

        # query OpenStack for the mappings of IP address to tenant so it can be checked later
        # this allows an IP address to move between tenants during a buffer_flush_interval
        # without the wrong tenant being billed for part of the traffic (the interval will instead
        # be discarded)
        old_ip_ownership = self._neutron_ip_list()

        logging.info("starting collector...")

        empty_totals_entry = {
            'inbound': {k:0 for k in self.classified_networks.keys()+[self.unclassifiable_network]},
            'outbound': {k:0 for k in self.classified_networks.keys()+[self.unclassifiable_network]},
        }

        timestamp = int(time.time())
        totals = {}

        memory_queue_lengths = collections.deque([], 5)
        disk_queue_lengths = collections.deque([], 5)

        while True:
            sflow_packet = self.queue.get()

            # "samples" can be of several types, only "flow" samples will end up here
            # XXX add checks so sflow code can be made more generic
            for sample in sflow_packet['samples']:

                # every "flow" corresponds to a truncated packet pulled off the wire
                # on one of the agents (e.g. routers)
                for flow in sample['flows']:

                    try:
                        flow_frame = Frame(flow['payload'])
                    except:
                        logging.warning('unable to parse payload :(')
                        continue

                    if not flow_frame.has_ip: # ignore packets without an IP header as
                        continue              # they won't have a source or destination address

                    # determine whether or not the packet was sampled inbound or outbound
                    # on the agent interface. agent interfaces should face transit providers,
                    # so this direction is also relative to the AS where this runs.
                    if sample['input'] == AccountingCollector.SFLOW_INTERFACE_INTERNAL:
                        direction = 'outbound'
                        local_address = flow_frame.source_ip
                        remote_address = flow_frame.destination_ip
                    else:
                        direction = 'inbound'
                        local_address = flow_frame.destination_ip
                        remote_address = flow_frame.source_ip

                    # ignore addresses not in the "local-networks" set, this will
                    # ignore transit packets
                    if not self._address_in_network_list(local_address, self.local_networks):
                        continue

                    billing = None

                    # determine which billing class the packet belongs to, if any
                    for network_class, networks_in_class in self.classified_networks.iteritems():
                        if self._address_in_network_list(remote_address, networks_in_class):
                            billing = network_class
                            break

                    if not billing:
                        billing = self.unclassifiable_network

                    if local_address not in totals:
                        totals[local_address] = copy.deepcopy(empty_totals_entry)

                    # multiply the original length of the packet by the sampling
                    # rate to produce an estimate of the "real world" traffic it
                    # represents then increment the totals with that amount (in octets)
                    totals[local_address][direction][billing] += (flow['frame_length'] - flow['stripped'] - flow_frame.sum_header_lengths()) * sample['sampling_rate']

            if time.time() - timestamp >= self.buffer_flush_interval and len(totals) > 0:
                start_time = time.time()
                logging.info("sending ceilometer data for %i local IPs" % len(totals))

                # re-request the mapping of IP addresses to tenants from OpenStack
                new_ip_ownership = self._neutron_ip_list()

                # addresses where the owner tenant is no longer the same as the beginning
                # of this interval are removed from the totals to be submitted
                for address, details in new_ip_ownership.iteritems():
                    if address in old_ip_ownership and old_ip_ownership[address]['tenant_id'] != details['tenant_id']:
                        logging.info("ownership of %s changed during period" % address)
                        totals.pop(address, None)

                old_ip_ownership = new_ip_ownership
                ceilometer_is_working = True # optimistic

                for address, traffic in totals.iteritems():
                    address_string = str(address)

                    for direction in ('inbound', 'outbound'):
                        for billing in self.classified_networks.keys()+[self.unclassifiable_network]:
                            if traffic[direction][billing] > 0:

                                if address_string not in new_ip_ownership:
                                    logging.info("not submitting %(octets)i octets for %(direction)s.%(billing)s because %(address)s is not a tenant or router IP" % {'octets': traffic[direction][billing], 'direction': direction, 'billing': billing, 'address': address_string})
                                    continue

                                ceilometer_record = {
                                    'counter_name': 'traffic.%s.%s' % (direction, billing),
                                    'counter_volume': traffic[direction][billing],
                                    'project_id': new_ip_ownership[address_string]['tenant_id'],
                                    'resource_id': new_ip_ownership[address_string]['id'],
                                    'timestamp': datetime.datetime.utcnow().isoformat(),
                                }
                    
                                logging.debug("submitting %(sample)s (region=%(region)s, ip=%(address)s)" % {'sample': repr(ceilometer_record), 'address': address_string, 'region': new_ip_ownership[address_string]['region']})

                                try:
                                    if ceilometer_is_working:
                                        self.clients[new_ip_ownership[address_string]['region']]['ceilometer'].samples.create(
                                            source='TrafficAccounting',
                                            resource_metadata={},
                                            counter_type='delta',
                                            counter_unit='byte',
                                            **ceilometer_record
                                        )
                                    else:
                                        raise Exception("Ceilometer is not working.")
                                except:
                                    ceilometer_is_working = False
                                    logging.info("ceilometer is broken, putting in database instead")
                                    ceilometer_record.update({'region': new_ip_ownership[address_string]['region']})
                                    self.local_queue_cursor.execute(
                                        "INSERT INTO queue VALUES(:counter_name, :counter_volume, :project_id, :resource_id, :region, datetime('now'), null);",
                                        ceilometer_record,
                                    )
                                else:
                                    self._mark_success(self.success_file)

                # try and cut down the number of queued-on-disk items waiting to go to ceilometer
                while ceilometer_is_working and time.time() - start_time < 300:
                    database_samples = self.local_queue_cursor.execute('SELECT * FROM queue ORDER BY created LIMIT 200;').fetchall()
                    if len(database_samples) == 0:
                        break
                    logging.info("attempting to re-submit %i samples spooled on disk..." % len(database_samples))
                    for row in database_samples:
                        try:
                            logging.debug("submitting %(sample)s (region=%(region)s, ip=%(address)s)" % {'sample': repr(row), 'address': address_string, 'region': new_ip_ownership[address_string]['region']})
                            self.clients[row[4]]['ceilometer'].samples.create(
                                source='TrafficAccounting',
                                resource_metadata={},
                                counter_type='delta',
                                counter_unit='byte',
                                counter_name=row[0],
                                counter_volume=row[1],
                                project_id=row[2],
                                resource_id=row[3],
                                timestamp=row[5],
                            )
                        except:
                            logging.debug("ceilometer is still broken, will get this record next time around")
                            break
                        else:
                            self.local_queue_cursor.execute('DELETE FROM queue WHERE id=?', (row[6],))

                self.local_queue_conn.commit()
                logging.info("ceilometer send complete, took %f seconds" % (time.time() - start_time))
                logging.info("in-memory queue is now %i entries long" % self.queue.qsize())

                # XXX this is a terrible way to report the state, but it will do for now
                memory_queue_lengths.append(self.queue.qsize())
                if len(memory_queue_lengths) == memory_queue_lengths.maxlen and list(memory_queue_lengths) == sorted(memory_queue_lengths):
                    increases = 0
                    for index, queue_length in enumerate(memory_queue_lengths):
                        if index+1 < memory_queue_lengths.maxlen and memory_queue_lengths[index+1] > queue_length:
                            increases += 1
                    if increases == memory_queue_lengths.maxlen-1:
                        self._mark_success(self.queue_length_file, str(self.queue.qsize()) + '\n')
                    else:
                        self._mark_success(self.queue_length_file, '0\n')
                else:
                    self._mark_success(self.queue_length_file, '0\n')

                totals = {}
                timestamp = int(time.time())

def accounting(queue):
    while True:
        try:
            collector = AccountingCollector(queue)
            collector.process_queue()
    except Exception as e:
        logging.error("exception in accounting process, will restart it: %s" % str(e))


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

    # reduce the logging verbosity of some openstack components
    logging.getLogger("neutronclient.client").setLevel(logging.ERROR)
    logging.getLogger("keystoneclient.session").setLevel(logging.ERROR)
    logging.getLogger("ceilometerclient.common.http").setLevel(logging.ERROR)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)
    logging.getLogger("iso8601.iso8601").setLevel(logging.ERROR)

    logging.info("starting sFlow and accounting processes...")

    accounting_packet_queue = multiprocessing.Queue()
    accounting_process = multiprocessing.Process(
        target=accounting, args=(accounting_packet_queue,)
    )
    accounting_process.start()

    collector = sflow.FlowCollector()

    # receieve sFlow packets from the network and send them to the accounting process
    for sflow_packet in collector.receive():
        accounting_packet_queue.put(sflow_packet)

    accounting_process.join()
    logging.shutdown()
