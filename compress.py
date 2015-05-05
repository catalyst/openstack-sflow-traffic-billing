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
Given a list of IPv4 or IPv6 networks (autodetected) on stdin or as a file,
return a hopefully shortened and optimised list by collapsing adjacent networks
and supernets.

Michael Fincham <michael.fincham@catalyst.net.nz>
"""

import argparse
import fileinput
import sys
import ipaddr

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', type=str, nargs='?', help='list of networks to compress, defaults to stdin')
    args = parser.parse_args()

    networks = []

    for line in fileinput.input():

        try:
            networks.append(ipaddr.IPNetwork(line.split()[0]))
        except:
            continue

    try:
        for network in ipaddr.CollapseAddrList(networks):
            print str(network)
    except:
        sys.stderr.write("error: unable to collapse input networks - are you mixing IPv4 and IPv6?\n")
        sys.exit(1)
