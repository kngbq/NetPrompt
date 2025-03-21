#include <core.p4>
#include <v1model.p4>

// Define Ethernet header
header ethernet_t {
    bit<48> dstAddr;  // Destination MAC address
    bit<48> srcAddr;  // Source MAC address
    bit<16> etherType; // EtherType field
}

// Define metadata structure
struct metadata {
    bit<9> ingress_port; // Ingress port of the packet (matches standard_metadata.ingress_port)
}

// Define headers and metadata
struct headers {
    ethernet_t ethernet;
}

// Define parser
parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet); // Extract Ethernet header
        meta.ingress_port = standard_metadata.ingress_port; // Store ingress port in metadata
        transition accept;
    }
}

// Define ingress control
control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action forward_to_port(bit<9> port) {
        standard_metadata.egress_spec = port; // Set egress port
    }

    table mac_table {
        key = {
            hdr.ethernet.dstAddr: exact; // Match on destination MAC address
        }
        actions = {
            forward_to_port; // Forward to a specific port
            NoAction; // No action (drop)
        }
        size = 1024; // Table size
        default_action = NoAction; // Default action is to drop
    }

    apply {
        // Simple port forwarding logic
        if (meta.ingress_port == 1) {
            forward_to_port(2); // Forward to port 2 if packet arrives on port 1
        } else {
            forward_to_port(1); // Forward to port 1 if packet arrives on any other port
        }

        // Apply MAC table
        mac_table.apply();
    }
}

// Define egress control
control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        // No specific egress processing in this example
    }
}

// Define checksum verification
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // No checksum verification in this example
    }
}

// Define checksum computation
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // No checksum computation in this example
    }
}

// Define deparser
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet); // Emit Ethernet header
    }
}

// Instantiate the V1Switch
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;