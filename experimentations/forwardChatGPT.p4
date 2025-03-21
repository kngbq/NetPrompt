/*
 * P4 program using the v1model architecture.
 */

#include <core.p4>
#include <v1model.p4>

/* Header Definitions */

// Ethernet header: 48-bit dstAddr, 48-bit srcAddr, 16-bit ethType
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> ethType;
}

// IPv4 header: version, IHL, diffserv, totalLen, identification, flags,
// fragOffset, ttl, protocol, hdrChecksum, srcAddr, dstAddr.
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

/* Header Grouping */
struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

/* Metadata Definition */
// Custom metadata including a 9-bit field for the egress port.
struct metadata_t {
    bit<9> egress_port;
}

/* Parser */
parser MyParser(packet_in packet,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethType) {
            0x0800: parse_ipv4;  // IPv4
            0x0806: parse_arp;   // ARP (transition to ARP state; not parsed)
            default: accept;     // For other ethTypes, finish parsing.
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_arp {
        transition accept;
    }
}

/* Checksum Verification */
// This control block is included in the pipeline; it can be left empty.
control MyVerifyChecksum(inout headers_t hdr,
                         inout metadata_t meta,
                         inout standard_metadata_t standard_metadata) {
    apply { }
}

/* Ingress Processing */
control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    /* Actions */

    // Forward: set the egress port in both our custom metadata and standard metadata.
    action forward(bit<9> port) {
        meta.egress_port = port;
        standard_metadata.egress_spec = port;
    }

    // Broadcast: mark the packet for broadcast using multicast group 1.
    action broadcast() {
        standard_metadata.mcast_grp = 1;
    }

    // Drop: mark the packet to be dropped.
    action drop() {
        mark_to_drop(standard_metadata);
    }

    /* Tables */

    // Ethernet Exact Match Table: matches on the Ethernet destination address.
    table eth_exact {
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

    // IPv4 LPM Table: longest prefix match on the IPv4 destination address.
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
            eth_exact.apply();
        }
    }
}

/* Egress Processing */
// This egress control block is defined but left empty since no modifications are needed.
control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/* Checksum Computation */
// Control block to update the IPv4 header checksum using csum16 over all IPv4 fields (except hdrChecksum).
control MyComputeChecksum(inout headers_t hdr,
                          inout metadata_t meta,
                          inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.ipv4.isValid()) {
            update_checksum(
                hdr.ipv4.hdrChecksum,
                { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
                  hdr.ipv4.totalLen, hdr.ipv4.identification,
                  hdr.ipv4.flags, hdr.ipv4.fragOffset,
                  hdr.ipv4.ttl, hdr.ipv4.protocol,
                  hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
                csum16
            );
        }
    }
}

/* Deparser */
// Reassemble the packet by emitting the Ethernet header first and then the IPv4 header.
// Note: Conditional statements are removed because they are not supported on your target.
control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/* Switch Instantiation */
// Instantiate the switch pipeline with the defined components.
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
