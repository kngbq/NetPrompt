/*
 * Complete P4_16 program for the V1 model.
 * This program defines Ethernet and IPv4 headers, metadata, parser states,
 * checksum controls, ingress and egress processing, a deparser, and instantiates the pipeline.
 */

#include <v1model.p4>

//------------------------------------------------------------------------------
// Enum for Checksum Algorithms
//------------------------------------------------------------------------------
// Define an enum for checksum algorithms. This provides an identifier for a 16-bit
// checksum algorithm (csum16) that can be used with update_checksum.
enum HashAlgorithm {
    csum16
};

//------------------------------------------------------------------------------
// Header Definitions
//------------------------------------------------------------------------------

// Ethernet header definition: contains destination MAC, source MAC, and Ethernet type.
header ethernet_t {
    bit<48> dstAddr;   // 48-bit destination MAC address
    bit<48> srcAddr;   // 48-bit source MAC address
    bit<16> ethType;   // 16-bit Ethernet type field
}

// IPv4 header definition: contains various fields for IPv4 packet processing.
header ipv4_t {
    bit<4>  version;       // IP version (4 bits)
    bit<4>  ihl;           // Internet Header Length (4 bits)
    bit<8>  diffserv;      // Differentiated Services (8 bits)
    bit<16> totalLen;      // Total packet length (16 bits)
    bit<16> identification;// Identification (16 bits)
    bit<3>  flags;         // Flags (3 bits)
    bit<13> fragOffset;    // Fragment offset (13 bits)
    bit<8>  ttl;           // Time to live (8 bits)
    bit<8>  protocol;      // Protocol (8 bits)
    bit<16> hdrChecksum;   // Header checksum (16 bits)
    bit<32> srcAddr;       // Source IP address (32 bits)
    bit<32> dstAddr;       // Destination IP address (32 bits)
}

//------------------------------------------------------------------------------
// Metadata and Composite Headers
//------------------------------------------------------------------------------

// Metadata structure: holds additional information used during packet processing.
struct metadata_t {
    bit<9> egress_port;  // 9-bit field for egress port
}

// Composite headers structure: aggregates all packet headers.
struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

//------------------------------------------------------------------------------
// Parser
//------------------------------------------------------------------------------

// The parser extracts packet headers and directs the parsing based on Ethernet type.
parser MyParser(packet_in packet,
                out headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        // Extract the Ethernet header first.
        packet.extract(hdr.ethernet);
        // Transition based on the Ethernet type field.
        transition select(hdr.ethernet.ethType) {
            0x0800: parse_ipv4; // 0x0800 indicates an IPv4 packet.
            0x0806: parse_arp;  // 0x0806 indicates an ARP packet.
            default: accept;    // For any other type, finish parsing.
        }
    }
    
    state parse_ipv4 {
        // Extract the IPv4 header.
        packet.extract(hdr.ipv4);
        transition accept;
    }
    
    state parse_arp {
        // ARP state: no additional extraction is performed in this example.
        transition accept;
    }
}

//------------------------------------------------------------------------------
// Checksum Controls
//------------------------------------------------------------------------------

// Checksum verification control block (empty as no verification is performed here).
control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

// Checksum computation control block: computes the IPv4 header checksum.
control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        if (hdr.ipv4.isValid()) {
            // Compute the IPv4 header checksum using update_checksum.
            // The list includes the IPv4 fields. If a field is wider than 16 bits,
            // the target splits it into 16-bit words as needed.
            update_checksum(
                hdr.ipv4.hdrChecksum,
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
                HashAlgorithm.csum16
            );
        }
    }
}

//------------------------------------------------------------------------------
// Ingress Processing
//------------------------------------------------------------------------------

// Ingress control block: contains actions and tables for packet processing.
control MyIngress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {
    // Action to forward the packet to a specific egress port.
    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    
    // Action to broadcast the packet by assigning it a multicast group.
    action broadcast() {
        standard_metadata.mcast_grp = 1;
    }
    
    // Action to drop the packet.
    action drop() {
        mark_to_drop();
    }
    
    // Table to match on the Ethernet destination address.
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
        // Default action: broadcast the packet.
        default_action = broadcast();
    }
    
    // Table to filter IPv4 packets based on source and destination IP addresses.
    table ipv4_filter {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            forward;
            drop;
        }
        size = 1024;
        // Default action: forward the packet to port 0.
        default_action = forward(0);
    }
    
    apply {
        // If the IPv4 header is valid, apply the IPv4 filter table.
        if (hdr.ipv4.isValid()) {
            ipv4_filter.apply();
        } else if (hdr.ethernet.isValid()) {
            // Otherwise, if the Ethernet header is valid, apply the Ethernet table.
            ethernet_exact.apply();
        }
    }
}

//------------------------------------------------------------------------------
// Egress Processing
//------------------------------------------------------------------------------

// Egress control block (empty for now).
control MyEgress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

//------------------------------------------------------------------------------
// Deparser
//------------------------------------------------------------------------------

// The deparser serializes the packet by emitting the headers back in order.
control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        // Emit the Ethernet header.
        packet.emit(hdr.ethernet);
        // If the IPv4 header is valid, emit it.
        if (hdr.ipv4.isValid()) {
            packet.emit(hdr.ipv4);
        }
    }
}

//------------------------------------------------------------------------------
// Pipeline Instantiation
//------------------------------------------------------------------------------

// Instantiate the switch pipeline by wiring together the parser, checksum controls,
// ingress and egress processing, compute checksum control, and the deparser.
// The pipeline is named "main".
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
