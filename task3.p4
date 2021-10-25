/* Include P4 core library */
#include <core.p4>
/* Include V1 Model switch architecture */
#include <v1model.p4>

/* Describes the format of an Ethernet header */
header Ethernet_h {
    bit<48> dst;
    bit<48> src;
    bit<16> typ;
}

/* Describes the format of an IPv4 header WITHOUT options. */
header IPv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  tos;
    bit<16> total_len;
    bit<16> id;
    bit<3>  flags;
    bit<13> offset;
    bit<8>  ttl;
    bit<8>  proto;
    bit<16> checksum;
    bit<32> src;
    bit<32> dst;
}

/* Descibes the format of an IPv6 header WITHOUT options. */
header IPv6_h {
    bit<4> version;
    bit<8> traffic_class;
    bit<20> flow_label;
    bit<16> payload_length;
    bit<8> next_header;
    bit<8> hop_limit;
    bit<128> src;
    bit<128> dst;
}

/* Describes the format of a UDP header. */
header UDP_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> cecksum;
}

/* Describes the format of a TCP header. */
header TCP_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  sequence_nr;
    bit<32>  ack_nr;
    bit<4>   data_offset;
    bit<3>   reserved;
    bit<1>   ns;
    bit<1>   cwr;
    bit<1>   ece;
    bit<1>   urg;
    bit<1>   ack;
    bit<1>   psh;
    bit<1>   rst;
    bit<1>   syn;
    bit<1>   fin;
    bit<16>  window_size;
    bit<16>  checksum;
    bit<16>  urgent_pointer;
}

/*
Structure of user metadata.
No user metadata is needed for this example so the struct is empty.
*/
struct user_metadata_t {}
/* Structure of parsed headers. */
struct headers_t {
    Ethernet_h ethernet;
    IPv4_h     ipv4;
    IPv6_h     ipv6;
    UDP_h      udp;
    TCP_h      tcp;
}

/* The parser describes the state machine used to parse packet headers. */
parser MyParser(packet_in pkt, out headers_t hdr, inout user_metadata_t umd, inout standard_metadata_t smd) {
    /* The state maachine always begins parsing with the start state */
    state start {
        /* Fills in the values of the Ethernet header and sets the header as valid. */
        pkt.extract(hdr.ethernet);
        /* Transition to the next state based on the value of the Ethernet type field. */
        transition select(hdr.ethernet.typ) {
	 /* Depending on ethernet type, parse ipv4 or ipv6 */
            0x0800: parse_ipv4;
            0x86DD: parse_ipv6;
	}
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
    
	/* Depending on protocol type, parse tcp or udp */
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.proto) {
            6: parse_tcp;
            17: parse_udp;
        }
    }
    
	/* Depending on protocol type, parse tcp or udp */
    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_header) {
            6: parse_tcp;
            17: parse_udp;
        }
    }
}

/* This contol block is not used for the lab. */
control MyVerifyChecksum(inout headers_t hdr, inout user_metadata_t umd) {
    apply {}
}

/*
Control flow prior to egress port selection.
egress_spec can be assigned a value to control which output port a packet will go to.
egress_port should not be accessed.
 */
control MyIngress(inout headers_t hdr, inout user_metadata_t umd, inout standard_metadata_t smd) {
    /* An action that takes the desired egress port as an argument. */
    action set_egress(bit<9> port) {
        smd.egress_spec = port;
    }


    /* An action that will cause the packet to be dropped. */
    action drop() {
        mark_to_drop(smd);
    }
    table ipv4_forwarding {
        /* Values that will be used to look up an entry. */
        key = { hdr.ipv4.dst: lpm; }
        /* All possible actions that may result from a lookup or table miss. */
        actions = {
            set_egress;
            drop;
        }
        /* The action to take when the table does not find a match for the supplied key. */
        default_action = drop;
    }

    /* Same forwarding principle as with ipv4 */
    table ipv6_forwarding {
	key = { hdr.ipv6.dst: lpm; }
	actions = {
	    set_egress; 
	    drop;
	}
	default_action = drop;
    }

    apply {
	if (hdr.ipv4.isValid()) {
            ipv4_forwarding.apply();
	}
	if (hdr.ipv6.isValid()) {
	    ipv6_forwarding.apply();
	}
    }
}

/*
Control flow after egress port selection.
egress_spec should not be modified. egress_port can be read but not modified. The packet can still be dropped.
*/
control MyEgress(inout headers_t hdr, inout user_metadata_t umd, inout standard_metadata_t smd) {    
    /* An action that will cause the packet to be dropped. */
    action drop() {
        mark_to_drop(smd);
    }

    /* Check given port in CLI to match exact in order to drop the packet */
    table udp_filter {
        key = { hdr.udp.dst_port: exact; }
        actions = {
            drop;
            NoAction;
        }
        default_action = NoAction;
    }

    /* Check given port in CLI to match exact in order to drop the packet */
    table tcp_filter {
        key = { hdr.tcp.dst_port: exact; }
        actions = {
            drop;
            NoAction;
        }
        default_action = NoAction;
    }

    apply {
        if (hdr.tcp.isValid()) {
            tcp_filter.apply();
        }
        if (hdr.udp.isValid()) {
            udp_filter.apply();
        }
    }
}

/* This contol block is not used for the lab. */
control MyComputeChecksum(inout headers_t hdr, inout user_metadata_t umd) {
    apply {}
}

/* The deparser constructs the outgoing packet by reassembling headers in the order specified. */
control MyDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        /* Emitting a header appends the header to the out going packet only if the header is valid. */
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
	pkt.emit(hdr.ipv6);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.tcp);
    }
}

/* This instantiate the V1 Model Switch */.
V1Switch(
 MyParser(),
 MyVerifyChecksum(),
 MyIngress(),
 MyEgress(),
 MyComputeChecksum(),
 MyDeparser()
) main;

