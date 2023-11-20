/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*** CONSTANTS AND TYPES ***/

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

enum bit<16> ether_type_t {
	IPV4 = 0x0800,
	ARP  = 0x0806,
	TPID = 0x8100,
	IPV6 = 0x86DD,
	MPLS = 0x8874
}


#if __TARGET_TOFINO__ == 1
const PortId_t CPU_PORT = 192;
#elif __TARGET_TOFINO__ == 2
const PortId_t CPU_PORT = 192;
#endif

#ifndef IPV4_HOST_SIZE
	#define IPV4_HOST_SIZE 131072
#endif


/*** HEADER DEFINITIONS ***/

header ethernet_h {
	mac_addr_t dst_addr;
	mac_addr_t src_addr;
	ether_type_t ether_type;
}

header vlan_tag_h {
	bit<3>  pcp;
	bit<1>  dei;
	bit<12> vid;
	ether_type_t ether_type;
}

header ipv4_h {
	bit<4>  version;
	bit<4>  ihl;
	bit<8>  diffserv;
	bit<16> total_len;
	bit<16> identification;
	bit<3>  flags;
	bit<13> frag_offset;
	bit<8>  ttl;
	bit<8>  protocol;
	bit<16> hdr_checksum;
	ipv4_addr_t src_addr;
	ipv4_addr_t dst_addr;
}

header udp_t{
  bit<16> srcPort;
  bit<16> desPort;
  bit<16> len;
  bit<16> checksum;
}

header pmu_t {
    bit<16>   sync;
    bit<16>   frame_size;
    bit<16>   id_code;
    bit<32>   soc;
    bit<32>   fracsec;
    bit<16>   stat;
    bit<64>   phasors;
    bit<16>   freq;
    bit<16>   dfreq;
    bit<32>   analog;
    bit<16>   digital;
    bit<16>   chk;
}

/*** INGRESS PIPELINE ***/

struct my_ingress_headers_t {
	ethernet_h      ethernet;
	vlan_tag_h      vlan_tag;
	ipv4_h          ipv4;
}

struct my_ingress_metadata_t { }

parser MyIngressParser(packet_in                pkt,
	out my_ingress_headers_t                hdr,
	out my_ingress_metadata_t               meta,
	out ingress_intrinsic_metadata_t        ig_intr_md)
{

	state start {
		pkt.extract(ig_intr_md);
		pkt.advance(PORT_METADATA_SIZE);
		transition parse_ethernet;
	}

	state parse_ethernet {
		pkt.extract(hdr.ethernet);
		transition select(hdr.ethernet.ether_type) {
			ether_type_t.TPID: parse_vlan_tag;
			ether_type_t.IPV4: parse_ipv4;
			default: accept;
		}
	}

	state parse_vlan_tag {
		pkt.extract(hdr.vlan_tag);
		transition select(hdr.vlan_tag.ether_type) {
			ether_type_t.IPV4 : parse_ipv4;
			default: accept;
		}
	}

	state parse_ipv4 {
		pkt.extract(hdr.ipv4);
		transition accept;
	}
}

control MyIngress(
	inout   my_ingress_headers_t                            hdr,
	inout   my_ingress_metadata_t                           meta,
	in      ingress_intrinsic_metadata_t                    ig_intr_md,
	in      ingress_intrinsic_metadata_from_parser_t        ig_prsr_md,
	inout   ingress_intrinsic_metadata_for_deparser_t       ig_dprsr_md,
	inout   ingress_intrinsic_metadata_for_tm_t             ig_tm_md)
{
	action send(PortId_t port) {
		ig_tm_md.ucast_egress_port = port;
	}

    action copy_to_cpu() {
        ig_tm_md.copy_to_cpu = 1;
    }

	action drop() {
		ig_dprsr_md.drop_ctl = 1;
	}

	table ipv4_host {
		key = {
			hdr.ipv4.dst_addr : exact;
		}
		actions = {
			send;
			drop;
		}
		size = IPV4_HOST_SIZE;
	}

	apply {
		ipv4_host.apply();
        	copy_to_cpu();
	}
}

control MyIngressDeparser(packet_out pkt,
	inout   my_ingress_headers_t                    hdr,
	in      my_ingress_metadata_t                   meta,
	in ingress_intrinsic_metadata_for_deparser_t    ig_dprsr_md)
{
	apply {
		pkt.emit(hdr.ethernet);
		pkt.emit(hdr.vlan_tag);
		pkt.emit(hdr.ipv4);
	}
}

/*** EGRESS PIPELINE ***/

struct my_egress_headers_t {}
struct my_egress_metadata_t {}

parser MyEgressParser(packet_in		pkt,
	out my_egress_headers_t         hdr,
	out my_egress_metadata_t        meta,
	out egress_intrinsic_metadata_t eg_intr_md)
{
	state start { pkt.extract(eg_intr_md); transition accept; }
}

control MyEgress(
	inout   my_egress_headers_t                             hdr,
	inout   my_egress_metadata_t                            meta,
	in      egress_intrinsic_metadata_t                     eg_intr_md,
	in      egress_intrinsic_metadata_from_parser_t         eg_prsr_md,
	inout   egress_intrinsic_metadata_for_deparser_t        eg_dprsr_md,
	inout egress_intrinsic_metadata_for_output_port_t       eg_oport_md)
{ apply { }}

control MyEgressDeparser(packet_out pkt,
	inout   my_egress_headers_t                             hdr,
	in      my_egress_metadata_t                            meta,
	in      egress_intrinsic_metadata_for_deparser_t        eg_dprsr_md)
{ apply { }}

/*** FINAL PACKAGE ***/

Pipeline(
	MyIngressParser(), MyIngress(), MyIngressDeparser(),
	MyEgressParser(), MyEgress(), MyEgressDeparser()
) pipe;

Switch(pipe) main;

