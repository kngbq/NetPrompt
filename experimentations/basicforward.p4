#include <core.p4>
#include <v1model.p4>

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/* Header Definitions */
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>  etherType;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
    macAddr_t sha;
    ip4Addr_t spa;
    macAddr_t tha;
    ip4Addr_t tpa;
}

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
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

/* Metadata and Headers */
struct metadata { bit<9> ingress_port; }

struct headers {
    ethernet_t ethernet;
    arp_t      arp;
    ipv4_t     ipv4;
}

/* Parser */
parser MyParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t std_meta
) {
    state start { transition parse_ethernet; }
    
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            0x0806: parse_arp;
            default: accept;
        }
    }
    
    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
    
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

/* Ingress Processing */
control MyIngress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t std_meta
) {
    action drop() { mark_to_drop(std_meta); }
    
    action forward(bit<9> egress_port) {
        std_meta.egress_spec = egress_port;
    }

    action flood() { std_meta.mcast_grp = 1; }

    // Main MAC learning/forwarding table
    table mac_table {
        key = { hdr.ethernet.dstAddr: exact; }
        actions = { forward; flood; drop; }
        size = 1024;
        default_action = flood();
    }

    // Security ACL table (optional)
    action block() { drop(); }
    table acl {
        key = {
            hdr.ethernet.srcAddr: exact,
            hdr.ethernet.dstAddr: exact
        }
        actions = { block; NoAction; }
        default_action = NoAction();
    }

    apply {
        // Check ACL first
        acl.apply();
        
        // Handle broadcast/multicast
        if (hdr.ethernet.dstAddr == 48w0xFFFF_FFFF_FFFF) {
            flood();
        } else {
            mac_table.apply();
        }
    }
}

/* Other Pipeline Stages (simplified) */
control MyEgress(...) { apply { } }
control MyVerifyChecksum(...) { apply { } }
control MyComputeChecksum(...) { apply { } }
control MyDeparser(...) { apply { packet.emit(hdr.ethernet); } }

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;