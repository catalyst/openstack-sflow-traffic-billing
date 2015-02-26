# openstack-sflow-traffic-billing

Python sFlow collector capable of classifying flows and reporting traffic counters to ceilometer.

This code should be considered "proof of concept" quality at this time.

## Uses

* Integration of existing sFlow infrastructure with OpenStack.
* In situations where you may want to offer differentiated billing to certain classes of traffic (e.g. traffic to or from local peering exchanges or specially discounted destinations)

## Configuration

Lists of addresses should be stored in files in CIDR format (e.g. 192.0.2.0/24 or 2001:db8::/64) and specified in the `accounting.cfg` file.

IP addresses on the "local" network for which accounting data is collected should be specified in a file of the same format and configured with the `local-networks` setting.

Traffic that is not able to be classified will be assigned a classification configured with the `unclassifiable` settings.

The OpenStack regions to examine should be listed in the `regions` section.
