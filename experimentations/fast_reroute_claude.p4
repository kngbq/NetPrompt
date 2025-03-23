/* 
 * Fast Failover Network Switch Implementation
 * V1Model Architecture
 * 
 * This implementation closely follows the reference implementation in fast_reroute.txt
 */

#include <core.p4>
#include <v1model.p4>

// Ethernet Header
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> ethType;
}

// IPv4 Header
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

// ARP Header
header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8>  hwAddrLen;
    bit<8>  protoAddrLen;
    bit<16> opcode;
    bit<48> srcHwAddr;
    bit<32> srcProtoAddr;
    bit<48> dstHwAddr;
    bit<32> dstProtoAddr;
}

// Metadata
struct metadata_t {
    bit<9>  primary_port;    // Primary egress port for the route
    bit<9>  backup_port;     // Backup egress port for the route
    bit<48> primary_mac;     // MAC address for the primary next hop
    bit<48> backup_mac;      // MAC address for the backup next hop
    bit<48> src_mac;         // Source MAC address of the switch
    bit<1>  link_status_primary;  // Status of the primary link (1 = up, 0 = down)
}

// Headers
struct headers_t {
    ethernet_t ethernet;
    arp_t      arp;
    ipv4_t     ipv4;
}

// Parser
parser MyParser(packet_in pkt, out headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_meta) {
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethType) {
            0x0800: parse_ipv4;
            0x0806: parse_arp;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }
}

// Checksum Verification
control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {}
}

// Ingress Control
control MyIngress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_meta) {
    // Register to track link status (1 = up, 0 = down), indexed by port number
    register<bit<1>>(512) link_status;
    // Register to count how often the backup path is triggered (for debugging)
    register<bit<32>>(1) backup_counter;
    // Register to count dropped packets due to backup route misses
    register<bit<32>>(1) drop_counter;
    // Register to track the active egress port used for forwarding
    register<bit<9>>(1) active_port;
    // Register to track the active port specifically for h1 to h2 traffic
    register<bit<9>>(1) h1_to_h2_active_port;

    // Drop action
    action drop() {
        mark_to_drop(standard_meta);
    }

    // Generate ARP reply for requests targeting the switch's IP
    action generate_arp_reply(bit<48> srcMac, bit<32> srcIp) {
        hdr.ethernet.srcAddr = srcMac;
        hdr.ethernet.dstAddr = hdr.arp.srcHwAddr;
        hdr.arp.opcode = 2; // ARP Reply
        hdr.arp.srcHwAddr = srcMac;
        hdr.arp.srcProtoAddr = srcIp;
        hdr.arp.dstHwAddr = hdr.arp.srcHwAddr;
        hdr.arp.dstProtoAddr = hdr.arp.srcProtoAddr;
        standard_meta.egress_spec = standard_meta.ingress_port;
        active_port.write(0, standard_meta.egress_spec);
    }

    // ARP table to handle ARP requests
    table arp_table {
        key = {
            hdr.arp.dstProtoAddr: exact;
        }
        actions = {
            generate_arp_reply;
            drop;
        }
        default_action = drop();
        size = 1024;
    }

    // Set primary and backup route information in metadata
    action set_routes(bit<9> primary_port, bit<48> primary_mac, bit<9> backup_port, bit<48> backup_mac, bit<48> src_mac) {
        meta.primary_port = primary_port;
        meta.backup_port = backup_port;
        meta.primary_mac = primary_mac;
        meta.backup_mac = backup_mac;
        meta.src_mac = src_mac;
    }

    // IPv4 longest prefix match table
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_routes;
            drop;
        }
        default_action = drop();
        size = 1024;
    }

    // Set next hop for primary path
    action set_nhop(bit<48> nhop_mac, bit<9> port, bit<48> src_mac) {
        standard_meta.egress_spec = port;
        hdr.ethernet.srcAddr = src_mac;
        hdr.ethernet.dstAddr = nhop_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        active_port.write(0, port);  // Log the active port
        if (hdr.ipv4.dstAddr == 0x0A000201) {  // 10.0.2.1 (h2)
            h1_to_h2_active_port.write(0, port);
        }
    }

    // Set next hop for backup path and increment counter
    action set_backup_nhop(bit<48> nhop_mac, bit<9> port, bit<48> src_mac) {
        standard_meta.egress_spec = port;
        hdr.ethernet.srcAddr = src_mac;
        hdr.ethernet.dstAddr = nhop_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        bit<32> count;
        backup_counter.read(count, 0);
        backup_counter.write(0, count + 1);  // Increment only on successful reroute
        active_port.write(0, port);  // Log the active port
        if (hdr.ipv4.dstAddr == 0x0A000201) {  // 10.0.2.1 (h2)
            h1_to_h2_active_port.write(0, port);
        }
    }

    // Backup routes table
    table backup_routes {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_backup_nhop;
            drop;
        }
        default_action = drop();
        size = 1024;
    }

    apply {
        if (hdr.arp.isValid() && hdr.arp.opcode == 1) { // ARP Request
            arp_table.apply();
        } else if (hdr.ipv4.isValid()) {
            if (ipv4_lpm.apply().hit) {
                if (meta.primary_port == 0) {  // Local delivery (e.g., switch IP)
                    standard_meta.egress_spec = standard_meta.ingress_port;  // Reflect back for ICMP
                    active_port.write(0, standard_meta.egress_spec);
                } else {
                    // Read the link status of the primary port
                    link_status.read(meta.link_status_primary, (bit<32>)meta.primary_port);
                    if (meta.link_status_primary == 1) {
                        // Primary link is up, use primary path
                        set_nhop(meta.primary_mac, meta.primary_port, meta.src_mac);
                    } else {
                        // Primary link is down, attempt backup path
                        if (!backup_routes.apply().hit) {
                            // Debug: Increment counter if backup_routes misses
                            bit<32> count;
                            drop_counter.read(count, 0);
                            drop_counter.write(0, count + 1);
                            drop();
                        }
                    }
                }
            }
        }
    }
}

// Egress Control
control MyEgress(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_meta) {
    apply {}
}

// Compute Checksum
control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen,
              hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset,
              hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

// Deparser
control MyDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.arp);
        pkt.emit(hdr.ipv4);
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;
