/* 
 * P4 Network Switch with IPv4 Filtering
 * Architecture: V1Model
 * Features: Ethernet forwarding, IPv4 filtering, ARP support
 */

#include <core.p4>
#include <v1model.p4>

// Constants for protocol types and port definitions
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_ARP = 0x0806;
const bit<32> MAX_PORTS = 512;
const bit<9> CPU_PORT = 255;

//===========================
// Header Definitions
//===========================

// Ethernet header definition
header ethernet_t {
    bit<48> dstAddr;   // Destination MAC address
    bit<48> srcAddr;   // Source MAC address
    bit<16> etherType; // Frame type
}

// IPv4 header definition with all standard fields
header ipv4_t {
    bit<4>  version;        // IP version (4 for IPv4)
    bit<4>  ihl;            // Internet Header Length
    bit<8>  diffserv;       // Differentiated Services Code Point
    bit<16> totalLen;       // Total Length of the packet
    bit<16> identification; // Identification field
    bit<3>  flags;          // Flags
    bit<13> fragOffset;     // Fragment Offset
    bit<8>  ttl;            // Time to Live
    bit<8>  protocol;       // Protocol
    bit<16> hdrChecksum;    // Header Checksum
    bit<32> srcAddr;        // Source IP Address
    bit<32> dstAddr;        // Destination IP Address
}

// Metadata structure used for internal processing
struct metadata {
    // Empty for this simple example
}

// Structure for all headers processed by the switch
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

//===========================
// Parser Implementation
//===========================

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    // Parser start point
    state start {
        // Extract Ethernet header
        packet.extract(hdr.ethernet);
        
        // Determine next protocol based on etherType
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_ARP: accept;     // Accept ARP packets without further parsing
            default: accept;           // Accept all other packet types
        }
    }

    // Parse IPv4 packets
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

//===========================
// Checksum Verification
//===========================

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // Verify IPv4 checksum if the header is valid
        verify_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

//===========================
// Ingress Processing
//===========================

control MyIngress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    // Action to drop a packet
    action drop() {
        mark_to_drop(standard_metadata);
    }

    // Action to forward a packet to a specific egress port
    action forward(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    // Action to broadcast a packet to all ports
    action broadcast() {
        standard_metadata.mcast_grp = 1; // Assuming multicast group 1 is configured for broadcast
    }

    // Table for MAC address based forwarding
    table ethernet_forwarding {
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

    // Table for IPv4 filtering based on source and destination addresses
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
        default_action = forward(1); // Default to forwarding to port 1
    }

    // Main apply block for ingress processing
    apply {
        if (hdr.ipv4.isValid()) {
            // If IPv4 packet, apply IP filtering
            ipv4_filter.apply();
            
            // Decrement TTL and drop if zero
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
            if (hdr.ipv4.ttl == 0) {
                drop();
                return;
            }
        } else {
            // For non-IPv4 packets (including ARP), apply Ethernet forwarding
            ethernet_forwarding.apply();
        }
    }
}

//===========================
// Egress Processing
//===========================

control MyEgress(inout headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    // Simple egress processing - no additional operations in this example
    apply { }
}

//===========================
// Checksum Computation
//===========================

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // Update IPv4 checksum for outgoing packets
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

//===========================
// Deparser Implementation
//===========================

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // Emit headers in the correct order
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);    // IPv4 header is emitted only if valid
    }
}

//===========================
// Switch Instance
//===========================

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;