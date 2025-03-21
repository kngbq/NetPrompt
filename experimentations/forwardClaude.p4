/* 
 * Basic L2/L3 Switch with v1model architecture
 * Features:
 * - Ethernet and IPv4 packet handling with ARP support
 * - L3 (IPv4) and L2 (Ethernet) forwarding tables
 * - L3 forwarding priority over L2
 * - Actions for forwarding, broadcasting, and dropping
 * - Default behaviors for unknown destinations
 * - IPv4 checksum recalculation
 */

#include <core.p4>
#include <v1model.p4>

// Header definitions
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<9>  port_t;

// Ethernet types
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP  = 0x0806;

// Header structures
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8>  hwAddrLen;
    bit<8>  protoAddrLen;
    bit<16> opcode;
    macAddr_t senderHwAddr;
    ip4Addr_t senderProtoAddr;
    macAddr_t targetHwAddr;
    ip4Addr_t targetProtoAddr;
}

// Metadata structure
struct metadata {
    bit<1> is_ipv4_forwarded;  // Flag for indicating if IPv4 forwarding was done
}

// Headers structure to hold all headers
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    arp_t      arp;
}

// Parser implementation
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
}

// Checksum verification
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
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
            HashAlgorithm.csum16);
    }
}

// Ingress processing
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    // Initialize IPv4 forwarding flag
    action initialize_metadata() {
        meta.is_ipv4_forwarded = 0;
    }
    
    // IPv4 forwarding actions
    action ipv4_forward(port_t port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        meta.is_ipv4_forwarded = 1;
    }
    
    action ipv4_drop() {
        mark_to_drop(standard_metadata);
        meta.is_ipv4_forwarded = 1;
    }
    
    // Ethernet forwarding actions
    action ethernet_forward(port_t port) {
        standard_metadata.egress_spec = port;
    }
    
    action broadcast() {
        // Assuming port 0 is connected to the CPU or controller
        // and other ports are physical interfaces
        standard_metadata.mcast_grp = 1; // Using multicast group 1 for broadcast
    }
    
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    // IPv4 forwarding table with LPM matching
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            ipv4_drop;
            NoAction;
        }
        size = 1024;
        default_action = ipv4_drop();
    }
    
    // Ethernet forwarding table with exact matching
    table ethernet_exact {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            ethernet_forward;
            broadcast;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = broadcast();
    }
    
    apply {
        // Initialize metadata
        initialize_metadata();
        
        // Process IPv4 packets with priority
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
        
        // Process Ethernet packets if IPv4 forwarding was not done
        if (meta.is_ipv4_forwarded == 0) {
            ethernet_exact.apply();
        }
    }
}

// Egress processing
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

// Checksum computation
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
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
            HashAlgorithm.csum16);
    }
}

// Deparser implementation
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.arp);
    }
}

// Instantiate the switch
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;