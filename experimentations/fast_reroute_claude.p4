/* 
 * Fast Failover Network Switch Implementation
 * V1Model Architecture
 * 
 * This program implements a switch that:
 * - Forwards IPv4 packets using LPM
 * - Handles ARP protocol
 * - Detects link failures and implements fast failover
 * - Tracks statistics for monitoring and debugging
 */

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_ARP  = 0x0806;
const bit<8>  PROTO_ICMP = 1;
const bit<8>  PROTO_TCP  = 6;
const bit<8>  PROTO_UDP  = 17;

/* ARP OPCODES */
const bit<16> ARP_REQUEST = 1;
const bit<16> ARP_REPLY   = 2;

/* Special ports */
const bit<9> CPU_PORT = 255;
const bit<9> DROP_PORT = 511;

/* Timeout values for port status monitoring (in microseconds) */
const bit<32> PORT_DOWN_TIMEOUT = 1000000; // 1 second

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ipv4Addr_t;

/* Ethernet header */
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

/* ARP header */
header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8>  hwAddrLen;
    bit<8>  protoAddrLen;
    bit<16> opcode;
    macAddr_t srcHwAddr;
    ipv4Addr_t srcProtoAddr;
    macAddr_t dstHwAddr;
    ipv4Addr_t dstProtoAddr;
}

/* IPv4 header */
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
    ipv4Addr_t srcAddr;
    ipv4Addr_t dstAddr;
}

/* TCP header */
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

/* UDP header */
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

/* ICMP header */
header icmp_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
    bit<32> data;
}

/* Packet-in header for CPU packets */
header packet_in_t {
    bit<9>   ingress_port;
    bit<7>   padding;
}

/* Packet-out header for CPU packets */
header packet_out_t {
    bit<9>   egress_port;
    bit<7>   padding;
}

/* Define metadata fields */
struct metadata {
    bit<9>  ingress_port;
    bit<9>  egress_port;
    bit<1>  is_multicast;
    bit<32> flow_hash;
    bit<1>  use_backup;
    bit<48> last_time;
    bit<48> curr_time;
    bit<1>  link_status;
}

struct headers {
    packet_in_t   packet_in;
    packet_out_t  packet_out;
    ethernet_t    ethernet;
    arp_t         arp;
    ipv4_t        ipv4;
    tcp_t         tcp;
    udp_t         udp;
    icmp_t        icmp;
}

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
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

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        
        /* We'll verify checksum in the verify checksum control block instead */
        transition select(hdr.ipv4.protocol) {
            PROTO_ICMP: parse_icmp;
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        /* IPv4 checksum verification */
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
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    /* Define registers for maintaining state */
    register<bit<48>>(512) port_last_pkt_time;     // Last packet timestamp on each port
    register<bit<1>>(512) port_status;             // Link status: 0 = down, 1 = up
    register<bit<32>>(512) backup_activations;     // Count of backup path activations
    register<bit<32>>(512) drops_count;            // Count of dropped packets
    register<bit<48>>(1024) flow_monitor;          // Monitor specific flows (src/dst pairs)

    /* Define switch's own MAC and IP for ARP responses */
    const macAddr_t SWITCH_MAC = 0x000000000100;
    const ipv4Addr_t SWITCH_IP = 0x0A000001; // 10.0.0.1

    /* Drop action */
    action drop() {
        bit<32> drop_count = 0;
        /* Increment drop counter */
        drops_count.read(drop_count, (bit<32>)standard_metadata.ingress_port);
        drop_count = drop_count + 1;
        drops_count.write((bit<32>)standard_metadata.ingress_port, drop_count);
        
        mark_to_drop(standard_metadata);
    }

    /* Send packet to CPU action */
    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
        /* Add ingress_port as metadata to packet sent to CPU */
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = standard_metadata.ingress_port;
    }

    /* ARP reply action */
    action send_arp_reply() {
        /* Swap MAC addresses */
        macAddr_t temp_mac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = SWITCH_MAC;
        hdr.ethernet.dstAddr = temp_mac;
        
        /* Update ARP header */
        hdr.arp.opcode = ARP_REPLY;
        hdr.arp.dstHwAddr = hdr.arp.srcHwAddr;
        hdr.arp.dstProtoAddr = hdr.arp.srcProtoAddr;
        hdr.arp.srcHwAddr = SWITCH_MAC;
        hdr.arp.srcProtoAddr = hdr.arp.dstProtoAddr;
        
        /* Send back to requester's port */
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    /* IPv4 forwarding action */
    action ipv4_forward(macAddr_t dstAddr, port_t port) {
        /* Update Ethernet addresses */
        hdr.ethernet.srcAddr = SWITCH_MAC;
        hdr.ethernet.dstAddr = dstAddr;
        
        /* Set output port */
        standard_metadata.egress_spec = port;
        
        /* Decrement TTL */
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    /* IPv4 forwarding with backup path for fast failover */
    action ipv4_forward_with_backup(macAddr_t dstAddr_primary, 
                                    port_t port_primary,
                                    macAddr_t dstAddr_backup,
                                    port_t port_backup) {
        bit<1> port_up = 0;
        bit<32> activation_count = 0;
        
        /* Read port status */
        port_status.read(port_up, (bit<32>)port_primary);
        
        /* Calculate flow hash for potential flow monitoring */
        hash(meta.flow_hash, 
             HashAlgorithm.crc32, 
             (bit<32>)0, 
             { hdr.ipv4.srcAddr, 
               hdr.ipv4.dstAddr, 
               hdr.ipv4.protocol }, 
             (bit<32>)65536);
        
        /* Check if primary port is up */
        if (port_up == 1) {
            /* Use primary path */
            hdr.ethernet.srcAddr = SWITCH_MAC;
            hdr.ethernet.dstAddr = dstAddr_primary;
            standard_metadata.egress_spec = port_primary;
        } else {
            /* Use backup path */
            hdr.ethernet.srcAddr = SWITCH_MAC;
            hdr.ethernet.dstAddr = dstAddr_backup;
            standard_metadata.egress_spec = port_backup;
            
            /* Increment backup activation counter */
            backup_activations.read(activation_count, (bit<32>)port_primary);
            activation_count = activation_count + 1;
            backup_activations.write((bit<32>)port_primary, activation_count);
            
            /* Track this flow for monitoring */
            flow_monitor.write(meta.flow_hash, standard_metadata.ingress_global_timestamp);
        }
        
        /* Decrement TTL */
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    /* IPv4 routing table using LPM */
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            ipv4_forward_with_backup;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    
    /* ARP response table */
    table arp_table {
        key = {
            hdr.arp.dstProtoAddr: exact;
        }
        actions = {
            send_arp_reply;
            drop;
            NoAction;
        }
        size = 64;
        default_action = drop();
    }

    /* Action to monitor link status */
    action update_link_status() {
        /* Read last packet timestamp for this port */
        bit<48> last_time = 0;
        port_last_pkt_time.read(last_time, (bit<32>)standard_metadata.ingress_port);
        
        /* Update current timestamp */
        port_last_pkt_time.write((bit<32>)standard_metadata.ingress_port, 
                                standard_metadata.ingress_global_timestamp);
        
        /* Store values in metadata */
        meta.last_time = last_time;
        meta.curr_time = standard_metadata.ingress_global_timestamp;
        
        /* Update port status to UP */
        port_status.write((bit<32>)standard_metadata.ingress_port, (bit<1>)1);
    }

    /* Check all ports periodically to detect down links */
    action check_port_status(bit<9> port_to_check) {
        bit<48> last_pkt_time = 0;
        bit<48> current_time = standard_metadata.ingress_global_timestamp;
        
        /* Read last packet time on the port */
        port_last_pkt_time.read(last_pkt_time, (bit<32>)port_to_check);
        
        /* If no packet for longer than timeout, mark port as down */
        if (current_time - last_pkt_time > (bit<48>)PORT_DOWN_TIMEOUT) {
            port_status.write((bit<32>)port_to_check, (bit<1>)0);
        }
    }
    
    /* Table to check port status */
    table port_checker {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            check_port_status;
            NoAction;
        }
        size = 512;
        default_action = NoAction();
    }

    apply {
        /* Record packet arrival for link monitoring */
        update_link_status();
        
        /* Check other port statuses */
        port_checker.apply();
        
        /* Process based on packet type */
        if (hdr.ethernet.isValid()) {
            if (hdr.arp.isValid()) {
                /* Handle ARP packets */
                if (hdr.arp.opcode == ARP_REQUEST) {
                    arp_table.apply();
                }
            } else if (hdr.ipv4.isValid()) {
                /* Handle IPv4 packets */
                if (hdr.ipv4.ttl > 1) {
                    ipv4_lpm.apply();
                } else {
                    drop();
                }
            }
        }
        
        /* Special case: packet from CPU */
        if (standard_metadata.ingress_port == CPU_PORT) {
            /* If packet from CPU has valid packet_out header, use the specified egress port */
            if (hdr.packet_out.isValid()) {
                standard_metadata.egress_spec = hdr.packet_out.egress_port;
                /* Remove CPU-specific headers */
                hdr.packet_out.setInvalid();
            }
        }
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    apply {
        /* Remove packet_in header if packet is sent to CPU */
        if (standard_metadata.egress_port == CPU_PORT && hdr.packet_in.isValid()) {
            /* Keep the header - the control plane needs it to know the original ingress port */
        } else if (hdr.packet_in.isValid()) {
            /* Remove CPU header for normal packets */
            hdr.packet_in.setInvalid();
        }
    }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        /* IPv4 checksum computation */
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
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        /* Emit CPU-specific headers if needed */
        packet.emit(hdr.packet_in);
        
        /* Emit standard headers */
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
 ***********************  S W I T C H  *******************************
 *************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;