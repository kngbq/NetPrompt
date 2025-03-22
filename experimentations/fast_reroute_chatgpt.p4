/*----------------------------------------------------------------
 * P4 Program implementing ARP and IPv4 routing with primary/backup
 * forwarding using the v1model architecture.
 *
 * This version defines a custom metadata struct so that all controls
 * have the expected (headers, custom_metadata, standard_metadata_t)
 * signature.
 *----------------------------------------------------------------*/

#include <core.p4>
#include <v1model.p4>

/*----------------------------------------------------------------
 * Constants
 *----------------------------------------------------------------*/
const bit<48> SWITCH_SRC_MAC = 0x001122334455;

/*----------------------------------------------------------------
 * Header Type Definitions
 *----------------------------------------------------------------*/
header ethernet_t {
    bit<48> dstAddr;    // Destination MAC address
    bit<48> srcAddr;    // Source MAC address
    bit<16> etherType;  // EtherType field
}

header ipv4_t {
    bit<4>   version;       // IP version (should be 4)
    bit<4>   ihl;           // Internet Header Length
    bit<8>   diffserv;      // Differentiated services
    bit<16>  totalLen;      // Total packet length
    bit<16>  identification; // Identification field
    bit<3>   flags;         // Flags field
    bit<13>  fragOffset;    // Fragment offset
    bit<8>   ttl;           // Time To Live
    bit<8>   protocol;      // Protocol field
    bit<16>  hdrChecksum;   // Header checksum
    bit<32>  srcAddr;       // Source IP address
    bit<32>  dstAddr;       // Destination IP address
}

header arp_t {
    bit<16> htype;   // Hardware type
    bit<16> ptype;   // Protocol type
    bit<8>  hlen;    // Hardware address length
    bit<8>  plen;    // Protocol address length
    bit<16> oper;    // Opcode (request/reply)
    bit<48> sha;     // Sender hardware address
    bit<32> spa;     // Sender protocol address
    bit<48> tha;     // Target hardware address
    bit<32> tpa;     // Target protocol address
}

/*----------------------------------------------------------------
 * Header and Custom Metadata Structures
 *----------------------------------------------------------------*/
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    arp_t      arp;
}

/* 
 * Custom metadata used for per-packet state. Note that the 
 * built-in standard_metadata_t is passed separately.
 */
struct custom_metadata {
    bit<9>  primary_egress_port;   // Primary egress port (9 bits)
    bit<9>  backup_egress_port;    // Backup egress port (9 bits)
    bit<48> primary_next_hop_mac;   // Primary next-hop MAC address
    bit<48> backup_next_hop_mac;    // Backup next-hop MAC address
    bit<1>  primary_link_status;   // Flag: primary link status (1: up, 0: down)
}

/*----------------------------------------------------------------
 * Registers for Stateful Tracking
 *----------------------------------------------------------------*/
// Register for link status: indexed by port number.
register<bit<1>>(1024) link_status_reg;
// Global backup route activations counter.
register<bit<32>>(1)   backup_activation_count;
// Global drop counter (for packets dropped due to missing backup routes).
register<bit<32>>(1)   drop_count;
// Log for active egress port (if needed).
register<bit<9>>(1024) active_egress_log;

/*----------------------------------------------------------------
 * Parser
 *----------------------------------------------------------------*/
parser MyParser(packet_in packet,
                out headers hdr,
                inout custom_metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4; // IPv4 packet
            0x0806: parse_arp;  // ARP packet
            default: accept;    // Other types: stop parsing
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

/*----------------------------------------------------------------
 * Checksum Verification (Empty)
 *----------------------------------------------------------------*/
control MyVerifyChecksum(inout headers hdr,
                         inout custom_metadata meta,
                         inout standard_metadata_t standard_metadata) {
    apply { }
}

/*----------------------------------------------------------------
 * Ingress Processing and Routing Logic
 *----------------------------------------------------------------*/
control MyIngress(inout headers hdr,
                  inout custom_metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /*--- Action: Send packet back out the ingress port (local delivery) ---*/
    action send_to_ingress() {
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    /*--- Action: Generate an ARP reply ---*/
    action arp_reply() {
        // Swap Ethernet source/destination and set switch's MAC as source.
        bit<48> tmp_mac;
        tmp_mac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = SWITCH_SRC_MAC;
        hdr.ethernet.dstAddr = tmp_mac;

        // Set ARP opcode to reply (2).
        hdr.arp.oper = 2;

        // Swap ARP addresses.
        bit<48> tmp_sha = hdr.arp.sha;
        hdr.arp.sha = SWITCH_SRC_MAC;
        hdr.arp.tha = tmp_sha;
        bit<32> tmp_spa = hdr.arp.spa;
        hdr.arp.spa = hdr.arp.tpa;
        hdr.arp.tpa = tmp_spa;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    /*--- Action: Set primary route ---*/
    action set_primary_route(bit<9> port, bit<48> next_hop_mac) {
        meta.primary_egress_port = port;
        meta.primary_next_hop_mac = next_hop_mac;

        hdr.ethernet.srcAddr = SWITCH_SRC_MAC;
        hdr.ethernet.dstAddr = next_hop_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        standard_metadata.egress_spec = port;
    }

    /*--- Action: Set backup route ---*/
    action set_backup_route(bit<9> port, bit<48> next_hop_mac) {
        meta.backup_egress_port = port;
        meta.backup_next_hop_mac = next_hop_mac;

        hdr.ethernet.srcAddr = SWITCH_SRC_MAC;
        hdr.ethernet.dstAddr = next_hop_mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        standard_metadata.egress_spec = port;

        // Increment the backup activation counter.
        bit<32> count;
        backup_activation_count.read(count, 0);
        backup_activation_count.write(0, count + 1);
    }

    /*--- Action: Drop the packet ---*/
    action drop_packet() {
        // Increment the drop counter.
        bit<32> count;
        drop_count.read(count, 0);
        drop_count.write(0, count + 1);
        mark_to_drop(standard_metadata);
    }

    /*--- Table: ARP processing ---*/
    table arp_table {
        key = {
            hdr.arp.tpa: exact;
        }
        actions = {
            arp_reply;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    /*--- Table: IPv4 LPM routing ---*/
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_primary_route;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    /*--- Table: Backup routes ---*/
    table backup_routes {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            set_backup_route;
            drop_packet;
            NoAction;
        }
        size = 256;
        default_action = drop_packet();
    }

    apply {
        if (hdr.ethernet.etherType == 0x0806 && hdr.arp.isValid()) {
            arp_table.apply();
        } else if (hdr.ethernet.etherType == 0x0800 && hdr.ipv4.isValid()) {
            // Check for local delivery (e.g., switch IP 10.0.0.1 -> 0x0A000001).
            if (hdr.ipv4.dstAddr == 0x0A000001) {
                send_to_ingress();
            } else {
                ipv4_lpm.apply();

                // Read the primary link status using the selected egress port.
                bit<32> port_idx = (bit<32>) meta.primary_egress_port;
                bit<1> link_status;
                link_status_reg.read(link_status, port_idx);
                meta.primary_link_status = link_status;

                if (meta.primary_link_status == 1) {
                    // Primary link is up; forward using primary route.
                } else {
                    // Primary link is down; try backup routing.
                    backup_routes.apply();
                }
            }
        }
    }
}

/*----------------------------------------------------------------
 * Egress Processing
 *----------------------------------------------------------------
 * This control block does not modify the packet.
 *----------------------------------------------------------------*/
control MyEgress(inout headers hdr,
                 inout custom_metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*----------------------------------------------------------------
 * Checksum Computation
 *----------------------------------------------------------------*/
control MyComputeChecksum(inout headers hdr,
                          inout custom_metadata meta,
                          inout standard_metadata_t standard_metadata) {
    apply {
        if (hdr.ipv4.isValid()) {
            bit<16> computed_cksum;
            update_checksum(
                true,
                { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen,
                  hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset,
                  hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
                computed_cksum,
                HashAlgorithm.csum16
            );
            hdr.ipv4.hdrChecksum = computed_cksum;
        }
    }
}

/*----------------------------------------------------------------
 * Deparser
 *----------------------------------------------------------------*/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        if (hdr.ipv4.isValid()) {
            packet.emit(hdr.ipv4);
        }
        if (hdr.arp.isValid()) {
            packet.emit(hdr.arp);
        }
    }
}

/*----------------------------------------------------------------
 * Pipeline Instantiation
 *----------------------------------------------------------------*/
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
