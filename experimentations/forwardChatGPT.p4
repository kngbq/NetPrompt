/*
 * P4 program using V1Model architecture that:
 *  - Defines Ethernet and IPv4 headers
 *  - Declares a metadata structure with an egress_port field
 *  - Implements a parser that extracts the Ethernet header, then
 *    based on ethType extracts an IPv4 header (0x0800) or handles ARP (0x0806)
 *  - Provides empty checksum verification and computes the IPv4 checksum
 *  - Implements an ingress control that defines forward, broadcast, and drop actions,
 *    and installs two tables: an Ethernet exact match table and an IPv4 LPM table
 *  - Uses the Ethernet table for non-IPv4 packets and the IPv4 table when the IPv4 header is valid
 *  - Defines an empty egress control and a deparser that emits Ethernet and IPv4 headers
 *  - Instantiates the pipeline components in the required order.
 */

#include <core.p4>
#include <v1model.p4>

/* Header Definitions */

// Ethernet header: 48-bit dst and src addresses, 16-bit ethType
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> ethType;
}

// IPv4 header with all required fields.
header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

/* Metadata and Header Collections */

// Metadata structure with a 9-bit egress_port.
struct metadata_t {
    bit<9> egress_port;
}

// Collection of all headers.
struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

/* Parser */

// MyParser first extracts the Ethernet header, then uses the ethType to decide:
parser MyParser(packet_in packet,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethType) {
            0x0800: parse_ipv4; // IPv4 packet
            0x0806: parse_arp;  // ARP packet
            default: accept;    // Other types: no further parsing
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_arp {
        // ARP packets are simply accepted without additional parsing.
        transition accept;
    }
}

/* Checksum Handling */

// Verify checksum control (empty apply block).
control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

// Compute checksum control: recomputes the IPv4 header checksum using a 16-bit checksum algorithm.
control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

/* Ingress Processing */

// Ingress control with three actions and two tables.
control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    // Action: forward packet to a specific port.
    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    // Action: set a multicast group (hardcoded to 1) for broadcasting.
    action broadcast() {
        standard_metadata.mcast_grp = 1;
    }

    // Action: drop the packet.
    action drop() {
        mark_to_drop(standard_metadata);
    }

    // Table matching on Ethernet destination address (exact match).
    table ethernet_exact {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            forward;
            broadcast;
            drop;
        }
        size = 1024;
        default_action = broadcast();
    }

    // Table matching on IPv4 destination address (LPM match).
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        } else if (hdr.ethernet.isValid()) {
            ethernet_exact.apply();
        }
    }
}

/* Egress Processing */

// Empty egress control.
control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/* Deparser */

// Deparser emits headers in fixed order. The backend will only output valid headers.
control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/* Pipeline Instantiation */

// Instantiate the V1Switch pipeline connecting all components in order.
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
