#include <v1model.p4>

#define MAC_TABLE_SIZE 1024

// Ethernet header definition
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> ethType;
}

// IPv4 header definition
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

// Metadata struct
struct metadata_t {}

// Packet headers struct
struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
}

// Checksum verification control (empty for this example)
control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        // Could implement checksum verification here if needed
    }
}

// Checksum computation control (empty for this example)
control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        // Could implement checksum computation here if needed
    }
}

parser MyParser(
    packet_in pkt,
    out headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata
) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

// Ingress control: IPv4 forwarding logic
control MyIngress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward(bit<48> dst_mac, bit<9> port) {
        hdr.ethernet.dstAddr = dst_mac;
        standard_metadata.egress_spec = port;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            forward;
            drop;
        }
        size = MAC_TABLE_SIZE;
        default_action = drop();
    }

    apply {
        if (hdr.ethernet.ethType == 0x0800) {
            ipv4_lpm.apply();
        }
    }
}

// Egress control (empty for this example)
control MyEgress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    apply {
        // Could implement egress processing here
    }
}

// Deparser: Emit the headers back onto the wire
control MyDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
    }
}

// Main pipeline declaration with all required components
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;