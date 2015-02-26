#!/usr/bin/env python

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
