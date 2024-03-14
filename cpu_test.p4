/* -*- P4_16 -*- */

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif
/*** CONSTANTS AND TYPES ***/

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;


struct pair {
    bit<32>     first;
    bit<32>     second;
}


enum bit<16> ether_type_t {
	IPV4 = 0x0800,
	ARP  = 0x0806,
	TPID = 0x8100,
	IPV6 = 0x86DD,
	MPLS = 0x8874
}

const bit<8> TYPE_UDP = 0x11;

#if __TARGET_TOFINO__ == 1
const PortId_t CPU_PORT = 192;
#elif __TARGET_TOFINO__ == 2
const PortId_t CPU_PORT = 192;
#endif

#ifndef IPV4_HOST_SIZE
	#define IPV4_HOST_SIZE 131072
#endif

#ifndef IPV4_LPM_SIZE
	#define IPV4_LPM_SIZE 12288
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

header udp_t{
  bit<16> srcPort;
  bit<16> desPort;
  bit<16> len;
  bit<16> checksum;
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

struct jpt_pmu_triplet_t {
  bit<32>   soc0;
  bit<32>   fracsec0;
  bit<64>   phasors0;
  bit<32>   soc1;
  bit<32>   fracsec1;
  bit<64>   phasors1;
  bit<32>   soc2;
  bit<32>   fracsec2;
  bit<64>   phasors2;
  bit<32>   curr_soc;
  bit<32>   curr_fracsec;
}

struct digest_a_t {
    bit<32> frac_sec_regs_0;
	bit<32> frac_sec_regs_1;
	bit<32> frac_sec_regs_2;

	bit<32> soc_regs_0;
	bit<32> soc_regs_1;
	bit<32> soc_regs_2;
}



/*** INGRESS PIPELINE ***/

struct my_ingress_headers_t {
	ethernet_h      ethernet;
	vlan_tag_h      vlan_tag;
	ipv4_h          ipv4;
	udp_t		 	udp;
	pmu_t				pmu;
}

struct my_ingress_metadata_t {
	bit<32> frac_sec_regs_0;
	bit<32> frac_sec_regs_1;
	bit<32> frac_sec_regs_2;

	bit<32> soc_regs_0;
	bit<32> soc_regs_1;
	bit<32> soc_regs_2;

	bit<64> phasor_regs_0;
	bit<64> phasor_regs_1;
	bit<64> phasor_regs_2;

 }

parser SwitchIngressParser(packet_in                pkt,
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
        transition select(hdr.ipv4.protocol){
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.desPort){
            4712: parse_pmu;
            default: accept;
        }
    }

    state parse_pmu {
        pkt.extract(hdr.pmu);
        transition accept;
    }
}

control SwitchIngress(
	inout   my_ingress_headers_t                            hdr,
	inout   my_ingress_metadata_t                           meta,
	in      ingress_intrinsic_metadata_t                    ig_intr_md,
	in      ingress_intrinsic_metadata_from_parser_t        ig_prsr_md,
	inout   ingress_intrinsic_metadata_for_deparser_t       ig_dprsr_md,
	inout   ingress_intrinsic_metadata_for_tm_t             ig_tm_md)
{

	Register<bit<32>, bit<32>>(3) frac_sec_regs_0;
    RegisterAction<bit<32>, bit<32>, bit<32>>(frac_sec_regs_0) read_frac_sec_regs_0 = {
        void apply(inout bit<32> val, out bit<32> rv) {
			rv = val;
			val = hdr.pmu.fracsec;
        }
    };
	
	Register<bit<32>, bit<32>>(3) frac_sec_regs_1;
    RegisterAction<bit<32>, bit<32>, bit<32>>(frac_sec_regs_1) read_frac_sec_regs_1 = {
        void apply(inout bit<32> val, out bit<32> rv) {
            rv = val;
			val = meta.frac_sec_regs_0;
        }
    };
	
	Register<bit<32>, bit<32>>(3) frac_sec_regs_2;
    RegisterAction<bit<32>, bit<32>, bit<32>>(frac_sec_regs_2) read_frac_sec_regs_2 = {
        void apply(inout bit<32> val, out bit<32> rv) {
            rv = val;
			val = meta.frac_sec_regs_1;
        }
    };

	Register<bit<32>, bit<32>>(3) soc_regs_0;
    RegisterAction<bit<32>, bit<32>, bit<32>>(soc_regs_0) read_soc_regs_0 = {
        void apply(inout bit<32> val, out bit<32> rv) {
			rv = val;
			val = hdr.pmu.soc;
        }
    };
	
	Register<bit<32>, bit<32>>(3) soc_regs_1;
    RegisterAction<bit<32>, bit<32>, bit<32>>(soc_regs_1) read_soc_regs_1 = {
        void apply(inout bit<32> val, out bit<32> rv) {
            rv = val;
			val = meta.soc_regs_0;
        }
    };
	
	Register<bit<32>, bit<32>>(3) soc_regs_2;
    RegisterAction<bit<32>, bit<32>, bit<32>>(soc_regs_2) read_soc_regs_2 = {
        void apply(inout bit<32> val, out bit<32> rv) {
            rv = val;
			val = meta.soc_regs_1;
        }
    };



	/*
	Register<pair, bit<32>>(32w1024) phasor_regs_0;
    // A simple dual-width 32-bit register action that will increment the two
    // 32-bit sections independently and return the value of one half before the
    // modification.
    RegisterAction<pair, bit<32>, pair>(phasor_regs_0) read_phasor_regs_0 = {
        void apply(inout pair val, out pair rv){
			pair my_pair;
			//check this
			my_pair.first = (bit<32>)(hdr.pmu.phasors >> 32);
			my_pair.second = (bit<32>)hdr.pmu.phasors;
			val = my_pair;
        }
    };
	*/

	action send(PortId_t port) {
		ig_tm_md.ucast_egress_port = port;
	}

    action send_digest() {
		ig_dprsr_md.digest_type = 1;
        //ig_tm_md.copy_to_cpu = 1;
    }

	action prep_frac_sec_reg_0() {
		meta.frac_sec_regs_0 = read_frac_sec_regs_0.execute(0);
	}

	action prep_frac_sec_reg_1() {
		meta.frac_sec_regs_1 = read_frac_sec_regs_1.execute(0);
	}

	action prep_frac_sec_reg_2() {
		meta.frac_sec_regs_2 = read_frac_sec_regs_2.execute(0);
	}

	action prep_soc_reg_0() {
		meta.soc_regs_0 = read_soc_regs_0.execute(0);
	}

	action prep_soc_reg_1() {
		meta.soc_regs_1 = read_soc_regs_1.execute(0);
	}

	action prep_soc_reg_2() {
		meta.soc_regs_2 = read_soc_regs_2.execute(0);
	}

	/*
	action prep_phasor_reg_0() {
		pair temp = read_phasor_regs_0.execute(0);
		//check for big endian stuff
		meta.phasor_regs_0 = temp.first ++ temp.second;
	}
	*/

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
		prep_frac_sec_reg_0();
		prep_frac_sec_reg_1();
		prep_frac_sec_reg_2();

		prep_soc_reg_0();
		prep_soc_reg_1();
		prep_soc_reg_2();

		//prep_phasor_reg_0();

        send_digest();
	}
}

control SwitchIngressDeparser(packet_out pkt,
	inout   my_ingress_headers_t                    hdr,
	in      my_ingress_metadata_t                   meta,
	in ingress_intrinsic_metadata_for_deparser_t    ig_dprsr_md)
{
	Digest<digest_a_t>() digest_a;
	
	apply {
        if (ig_dprsr_md.digest_type == 1) {
			digest_a.pack({meta.frac_sec_regs_0, meta.frac_sec_regs_1, meta.frac_sec_regs_2, meta.soc_regs_0, meta.soc_regs_1, meta.soc_regs_2});
		}
		pkt.emit(hdr.ethernet);
		pkt.emit(hdr.vlan_tag);
		pkt.emit(hdr.ipv4);
		pkt.emit(hdr.udp);
		pkt.emit(hdr.pmu);
 	}
}

/*** EGRESS PIPELINE ***/

struct my_egress_headers_t {
	ethernet_h      ethernet;
	vlan_tag_h      vlan_tag;
	ipv4_h          ipv4;
	udp_t udp;
	pmu_t pmu;
}
struct my_egress_metadata_t {}

parser EmptyEgressParser(packet_in		pkt,
	out my_egress_headers_t         hdr,
	out my_egress_metadata_t        meta,
	out egress_intrinsic_metadata_t eg_intr_md)
{
	state start { pkt.extract(eg_intr_md); transition accept; }
}

control EmptyEgress(
	inout   my_egress_headers_t                             hdr,
	inout   my_egress_metadata_t                            meta,
	in      egress_intrinsic_metadata_t                     eg_intr_md,
	in      egress_intrinsic_metadata_from_parser_t         eg_prsr_md,
	inout   egress_intrinsic_metadata_for_deparser_t        eg_dprsr_md,
	inout egress_intrinsic_metadata_for_output_port_t       eg_oport_md)
{ apply { }}

control EmptyEgressDeparser(packet_out pkt,
	inout   my_egress_headers_t                             hdr,
	in      my_egress_metadata_t                            meta,
	in      egress_intrinsic_metadata_for_deparser_t        eg_dprsr_md)
{ 
	apply {

 	}
}

/*** FINAL PACKAGE ***/

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;

