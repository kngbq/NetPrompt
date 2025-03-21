#include <core.p4>
#include <v1model.p4>
// Define Ethernet header
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}
// Define metadata structure
struct metadata {
    // No additional metadata needed for this simple example
}

// Define headers and metadata
struct headers {
    ethernet_t ethernet;
}
// Define parser
parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition accept;
    }
}
// Define ingress control
control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    table ethernet_table {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        // Drop all packets regardless of the input port
        ethernet_table.apply();
    }
}
// Define egress control (no action needed for this example)
control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
        // No egress processing needed
    }
}
// Define checksum verification (no action needed for this example)
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // No checksum verification needed
    }
}
// Define checksum computation (no action needed for this example)
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        // No checksum computation needed
    }
}
// Define deparser
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
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