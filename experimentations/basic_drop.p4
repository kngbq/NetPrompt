#include <core.p4>
#include <v1model.p4>

/************** Data Types **************/
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

/************** Metadata Structs **************/
struct metadata { 
    // Empty metadata (required by parser/control signatures)
}

struct headers {
    ethernet_t ethernet;
}

/************** Parser **************/
parser MyParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    state start {
        packet.extract(hdr.ethernet);
        transition accept;
    }
}

/************** Checksum Controls **************/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { /* No checksum verification */ }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { /* No checksum computation */ }
}

/************** Ingress Control **************/
control MyIngress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    table dmac_table {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        dmac_table.apply();
    }
}

/************** Egress & Deparser **************/
control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {}
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
    }
}

/************** Main Pipeline **************/
V1Switch(
    MyParser(),              // Parser
    MyVerifyChecksum(),      // Checksum verification
    MyIngress(),             // Ingress processing
    MyEgress(),              // Egress processing
    MyComputeChecksum(),     // Checksum computation
    MyDeparser()             // Deparser
) main;