# packet-forwarding

# Task 1.1 - Layer 3 Switching (Routing)
Create the l3 switching.p4 file to implement IPv4 forwarding based on longest prefix matches.
Note the MAC addresses are not changing.

Create table entries to implement the following:
• 10.0.0.0/24 forwarded out port 1
• 10.0.0.0/8 forwarded out port 2
• 10.0.0.0/16 forwarded out port 3
• Drop IPv4 packets to unknown destinations.

# Task 1.2 - IPv6
Modify the l3 switchting.p4 program to implement IPv6 while retaining IPv4 support. This will
require:
• Creating an additional header, parser, and table.
• Setting the IPv6 entry in the start parser.
• Modifying the ingress block.

Create table entries to implement the following:
• 2001::/16 forwarded out port 1
• 2001:4860:4860::/48 forwarded out port 2
• 2001:610:158:960::/64 forwarded out port 3
• Drop IPv6 packets to unknown destinations

# Task 2 - Modifying a Packet (3 pt)
In a separate file extend your layer 3 switching program to (i) update the ethernet destination
address with the address of the next hop (ii) update the ethernet source address with the address
of the switch and (iii) decrement the TTL/Hop Limit of packets. If it reaches zero, discard the
packet. Otherwise maintain IPv4 and IPv6 routing support. Create the same table entries as in
the previous task and test your solution.

# Task 3 - Filtering (4 pt)
In a separate file extend your layer 3 switching program to do packet filtering. Do the filtering
in the egress control block. Other than the requested filtering, maintain IPv4 and IPv6 routing.
support.
# Task 3.1 - Layer 2 Filtering
Create a table that will filter (drop) packets where the layer 2 multicast/broadcast bit is on,
(hint: use a ternary match). 
# Task 3.2 - Higher Layer Filtering
Implement UDP, TCP parsing (do not attempt to parse TCP options) and create a table to filter
(drop) packets destined to TCP port 23 or UDP port 69. Assume that there are no IPv4 option
fields or IPv6 extension headers.
