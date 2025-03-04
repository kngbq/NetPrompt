#include <core.p4>
#include <v1model.p4>

/*************
 * HEADERS   *
 *************/
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

/*************
 * STRUCTS   *
 *************/
struct metadata_t {} // Empty metadata (required by P4 architecture)

struct headers_t {
    ethernet_t ethernet;
}

/*************
 * PARSER    *
 *************/
parser MyParser(
    packet_in packet,
    out headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata
) {
    state start {
        packet.extract(hdr.ethernet);
        transition accept;
    }
}

/*************
 * PIPELINE  *
 *************/
control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {}
}

control MyIngress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata
) {
    action flood() {
        // Flood to all ports except ingress port
        if (standard_metadata.ingress_port == 1) {
            standard_metadata.egress_spec = 2; // Forward to port 2 (s2)
        } else {
            standard_metadata.egress_spec = 1; // Forward to port 1 (h1)
        }
    }

    table dmac {
        key = { hdr.ethernet.dstAddr: exact; }
        actions = { flood; }
        default_action = flood(); // Always flood
        size = 1024;
    }

    apply {
        dmac.apply(); // Apply forwarding rules
    }
}

control MyEgress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    apply {}
}

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {}
}

/*************
 * DEPARSER  *
 *************/
control MyDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
    }
}

/*************
 * SWITCH    *
 *************/
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;