#include <core.p4>
#include <v1model.p4>

/****************************************************************
 * Ethernet Header Definition
 ****************************************************************/
header ethernet_t {
    bit<48> dstAddr;  // Destination MAC address
    bit<48> srcAddr;  // Source MAC address
    bit<16> etherType; // EtherType field
}

/****************************************************************
 * IPv4 Header Definition
 ****************************************************************/
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

/****************************************************************
 * Metadata and Headers
 ****************************************************************/
struct metadata {
    bit<9> ingress_port; // Ingress port of the packet (bit<9> to match standard_metadata)
    bit<9> egress_port;  // Egress port for the packet (bit<9> to match standard_metadata)
}

struct headers {
    ethernet_t ethernet; // Ethernet header
    ipv4_t     ipv4;     // IPv4 header
}

/****************************************************************
 * Registers
 ****************************************************************/
register<bit<32>>(512) link_status;      // Register to track link status
register<bit<32>>(512) backup_counter;   // Register to count backup route usage
register<bit<32>>(512) drop_counter;     // Register to count dropped packets
register<bit<9>>(512)  active_port;      // Register to track active port for forwarding
register<bit<9>>(512)  h1_to_h2_active_port; // Register to track active port for h1->h2 traffic

/****************************************************************
 * Parser
 ****************************************************************/
parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet); // Extract Ethernet header
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4; // IPv4
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4); // Extract IPv4 header
        transition accept;
    }
}

/****************************************************************
 * Ingress Control
 ****************************************************************/
control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata); // Drop the packet
        drop_counter.write(standard_metadata.ingress_port, drop_counter.read(standard_metadata.ingress_port) + 1);
    }

    action forward(bit<9> port) {
        standard_metadata.egress_spec = port; // Set egress port (bit<9>)
    }

    action set_active_port(bit<9> port) {
        active_port.write(standard_metadata.ingress_port, port);
        h1_to_h2_active_port.write(standard_metadata.ingress_port, port);
    }

    table arp_table {
        key = {
            hdr.ethernet.dstAddr: exact; // Match destination MAC address
        }
        actions = {
            forward;
            drop;
        }
        size = 1024; // Table size
        default_action = drop();
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm; // Longest prefix match on IPv4 destination address
        }
        actions = {
            forward;
            drop;
        }
        size = 1024; // Table size
        default_action = drop();
    }

    table backup_routes {
        key = {
            hdr.ipv4.dstAddr: exact; // Exact match on IPv4 destination address
        }
        actions = {
            forward;
            drop;
        }
        size = 1024; // Table size
        default_action = drop();
    }

    apply {
        // Simple port forwarding logic
        if (standard_metadata.ingress_port == 1) {
            standard_metadata.egress_spec = 2; // Forward to port 2
        } else if (standard_metadata.ingress_port == 2) {
            standard_metadata.egress_spec = 1; // Forward to port 1
        }

        // Apply ARP table for MAC-based forwarding
        arp_table.apply();

        // Apply IPv4 LPM table for IP-based forwarding
        ipv4_lpm.apply();

        // Apply backup routes table for failover
        backup_routes.apply();

        // Update active port register
        set_active_port(standard_metadata.egress_spec);
    }
}

/****************************************************************
 * Egress Control
 ****************************************************************/
control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        // No specific egress logic for this simple switch
    }
}

/****************************************************************
 * Checksum Verification
 ****************************************************************/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // No checksum verification for Ethernet frames
    }
}

/****************************************************************
 * Checksum Computation
 ****************************************************************/
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // No checksum computation for Ethernet frames
    }
}

/****************************************************************
 * Deparser
 ****************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet); // Emit Ethernet header
        packet.emit(hdr.ipv4);     // Emit IPv4 header
    }
}

/****************************************************************
 * V1Switch Instantiation
 ****************************************************************/
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;