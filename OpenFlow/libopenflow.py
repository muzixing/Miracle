import sys
sys.path.append('/opt/local/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/site-packages/')
from scapy.all import *

"""
TODO:Define the OpenFlow packets handler functions
Author:Licheng
Time:2014/5/7

"""


#uint8_t => XByteField
#uint16_t => ShortField, BitFieldLenField('name', None, 16, length_of='varfield'),BitField('name', None, 16)

#uint32_t => IntField, BitFieldLenField('name', None, 32, length_of='varfield'), BitFieldLenField('name', None, 32)


###################
# Data Structures #
###################
OFP_DL_TYPE_NOT_ETH_TYPE = 0x05ff

ofp_type = { 0: "OFPT_HELLO",
             1: "OFPT_ERROR",
             2: "OFPT_ECHO_REQUEST",
             3: "OFPT_ECHO_REPLY",
             4: "OFPT_VENDOR",
             5: "OFPT_FEATURES_REQUEST",
             6: "OFPT_FEATURES_REPLY",
             7: "OFPT_GET_CONFIG_REQUEST",
             8: "OFPT_GET_CONFIG_REPLY",
             9: "OFPT_SET_CONFIG",
             10: "OFPT_PACKET_IN",
             11: "OFPT_FLOW_REMOVED",
             12: "OFPT_PORT_STATUS",
             13: "OFPT_PACKET_OUT",# with action header
             14: "OFPT_FLOW_MOD",
             15: "OFPT_PORT_MOD",
             16: "OFPT_STATS_REQUEST",
             17: "OFPT_STATS_REPLY",
             18: "OFPT_BARRIER_REQUEST",
             19: "OFPT_BARRIER_REPLY",
             20: "OFPT_QUEUE_GET_CONFIG_REQUEST",
             21: "OFPT_QUEUE_GET_CONFIG_REPLY",
             24:"OFPT_CFEATURES_REPLY",
             0xfe: "OFPT_CPORT_STATUS",
             0xff: "OFPT_CFLOW_MOD"
             }

ofp_port = { 0xff00: "OFPP_MAX",
             0xfff8: "OFPP_IN_PORT",
             0xfff9: "OFPP_TABLE",
             0xfffa: "OFPP_NORMAL",
             0xfffb: "OFPP_FLOOD",
             0xfffc: "OFPP_ALL",
             0xfffd: "OFPP_CONTROLLER",
             0xfffe: "OFPP_LOCAL",
             0xffff: "OFPP_NONE"}

ofp_port_reason = { 1: "OFPPR_ADD",
                    2: "OFPPR_DELETE",
                    3: "OFPPR_MODIFY",
                    254: "OFPPR_BW_MODIFY",
                    255: "OFPPR_BW_DOWN"}

ofp_config_flags = {  0: "OFPC_FRAG_NORMAL",
                      1: "OFPC_FRAG_DORP",
                      2: "OFPC_FRAG_REASM",
                      3: "OFPC_FRAG_MASK"
                    }

ofp_action_type = { 0: "OFPAT_OUTPUT",
                    1: "OFPAT_SET_VLAN_VID",
                    2: "OFPAT_SET_VLAN_PCP",
                    3: "OFPAT_STRIP_VLAN",
                    4: "OFPAT_SET_DL_SRC",
                    5: "OFPAT_SET_DL_DST",
                    6: "OFPAT_SET_NW_SRC",
                    7: "OFPAT_SET_NW_DST",
                    8: "OFPAT_SET_NW_TOS",
                    9: "OFPAT_SET_TP_SRC",
                    10: "OFPAT_SET_TP_DST",
                    11: "OFPAT_ENQUEUE",
                    0xffff: "OFPAT_VENDOR"}

ofp_packet_in_reason = { 0: "OFPR_NO_MATCH",
                         1: "OFPR_ACTION",}

ofp_flow_mod_command = { 0: "OFPFC_ADD",            # New flow
                         1: "OFPFC_MODIFY",         # Modify all matching flows
                         2: "OFPFC_MODIFY_STRICT",  # Modify entry strictly matching wildcards
                         3: "OFPFC_DELETE",         # Delete all matching flows
                         4: "OFPFC_DELETE_STRICT",  # Strictly match wildcards and priority
                         0xffff: "OFPFC_DROP"}      # [added]Terminate a circuit flow

ofp_error_type = { 0: "OFPET_HELLO_FAILED",
                   1: "OFPET_BAD_REQUEST",
                   2: "OFPET_BAD_ACTION",
                   3: "OFPET_FLOW_MOD_FAILED",
                   4: "OFPET_PORT_MOD_FAILED",
                   5: "OFPET_QUEUE_OP_FAILED"}

ofp_hello_failed_code = { 0: "OFPHFC_INCOMPATIBLE",
                          1: "OFPHFC_EPERM"}

ofp_bad_request_code = { 0: "OFPBRC_BAD_VERSION",
                         1: "OFPBRC_BAD_TYPE",
                         2: "OFPBRC_BAD_STAT",
                         3: "OFPBRC_BAD_VENDOR",
                         4: "OFPBRC_BAD_SUBTYPE",
                         5: "OFPBRC_EPERM",
                         6: "OFPBRC_BAD_LEN",
                         7: "OFPBRC_BUFFER_EMPTY",
                         8: "OFPBRC_BUFFER_UNKNOWN"}

ofp_bad_action_code = { 0: "OFPBAC_BAD_TYPE",
                        1: "OFPBAC_BAD_LEN",
                        2: "OFPBAC_BAD_VENDOR",
                        3: "OFPBAC_BAD_VENDOR_TYPE",
                        4: "OFPBAC_BAD_OUT_PORT",
                        6: "OFPBAC_BAD_ARGUMENT",
                        7: "OFPBAC_EPERM",                  #permissions error
                        8: "OFPBAC_TOOMANY",
                        9: "OFPBAC_BAD_QUEUE"}

ofp_flow_mod_failed_code = { 0: "OFPFMFC_ALL_TABLES_FULL",
                             1: "OFPFMFC_OVERLAP",
                             2: "OFPFMFC_EPERM",
                             3: "OFPFMFC_BAD_EMERG_TIMEOUT",
                             4: "OFPFMFC_BAD_COMMAND",
                             5: "OFPFMFC_UNSUPPORT"}

ofp_port_mod_failed_code = { 0: "OFPPMFC_BAD_PORT",
                             1: "OFPPFMC_BAD_HW_ADDR"}

ofp_queue_op_failed_code = { 0: "OFPQOFC_BAD_PORT",
                             1: "OFPQOFC_BAD_QUEUE"}

ofp_queue_properties = {  0: "OFPQT_NONE",
                          1: "OFPQT_MIN_RATE"}

ofp_stats_types = { 0: "OFPST_DESC",
                    1: "OFPST_FLOW",
                    2: "OFPST_AGGREGATE",
                    3: "OFPST_TABLE",
                    4: "OFPST_PORT",
                    5: "OFPST_QUEUE",
                    0xffff: "OFPST_VENDOR"}

class ofp_phy_port(Packet):
    name = "OpenFlow Port"
    fields_desc=[ ShortEnumField("port_no", 0, ofp_port),
                  MACField("hw_addr", "00:00:00:00:00:00"),
                  StrFixedLenField("port_name", None, length=16),
                  #StrField("port_name", None, fmt="H", remain=24),
                  #BitFieldLenField('port_name', None, 128, length_of='varfield'),

                  #TODO: still some problem with this part
                  #uint32_t for port config, for Openflow 1.0, this part only uses 7 bits.
                  BitField("not_defined", 0, 25),
                  BitField("OFPPC_NO_PACKET_IN", 0, 1),
                  BitField("OFPPC_NO_FWD", 0, 1),
                  BitField("OFPPC_NO_FLOOD", 0, 1),
                  BitField("OFPPC_NO_RECV_STP",0, 1),
                  BitField("OFPPC_NO_RECV", 0, 1),
                  BitField("OFPPC_NO_STP", 0, 1),
                  BitField("OFPPC_PORT_DOWN", 0, 1),
                  

                  #uint32_t for state
                  BitField("else", 0, 31),
                  BitField("OFPPS_LINK_DOWN", 0, 1),

                  #uint32_t for Current features
                  BitField("not_defined", 0, 20),
                  BitField("OFPPF_PAUSE_ASYM", 0, 1),
                  BitField("OFPPF_PAUSE", 0, 1),
                  BitField("OFPPF_AUTONEG", 0, 1),
                  BitField("OFPPF_FIBER", 0, 1),
                  BitField("OFPPF_COPPER", 0, 1),
                  BitField("OFPPF_10GB_FD", 0, 1),
                  BitField("OFPPF_1GB_FD", 0, 1),
                  BitField("OFPPF_1GB_HD", 0, 1),
                  BitField("OFPPF_100MB_FD", 0, 1),
                  BitField("OFPPF_100MB_HD", 0, 1),
                  BitField("OFPPF_10MB_FD", 0, 1),
                  BitField("OFPPF_10MB_HD", 0, 1),
                  
                  #uint32_t for features being advised by the port
                  BitField("advertised", 0, 32),

                  #uint32_t for features supported by the port
                  BitField("supported", 0, 32),

                  #uint32_t for features advertised by peer
                  BitField("peer", 0, 32)]
"""
/* Extensions for circuit switch ports */ 
uint16_t supp_sw_gran;             
uint8_t     pad[2];                 
unit8_t sup_sdh_port_bandwidth;    
unit8_t sup_otn_port_bandwidth;    
struct sup_wave_port_bandwidth wave_bw[0];    
uint8_t     pad[2];                      
uint16_t     peer_port_no;             /
uint64_t     peer_datapath_id;         /
}; 
OFP_ASSERT(sizeof(struct ofp_phy_cport) == 72); 
"""
class sup_wave_port_bandwidth(Packet):
    name = "sup_wave_port_bandwidth"
    fields_desc = [ BitField("center_freq_lmda", 0, 32),
                    BitField("num_lmda", 0, 8),
                    BitField("freq_space_lmda", 0, 8),
                    XByteField("pad1.1", 0),
                    XByteField("pad1.2", 0)]

#_________________________________________________This is a new packet on OTN ,you need to pay attention.___________________________

class ofp_phy_cport(Packet):
    sw_grain = []
    name = "OpenFlow Cport"
    fields_desc=[ ShortEnumField("port_no", 0, ofp_port),
                  MACField("hw_addr", "00:00:00:00:00:00"),
                  StrFixedLenField("port_name", None, length=16), #OTN port name

                  BitField("not_defined", 0, 25),
                  BitField("OFPPC_NO_PACKET_IN", 0, 1),
                  BitField("OFPPC_NO_FWD", 0, 1),
                  BitField("OFPPC_NO_FLOOD", 0, 1),
                  BitField("OFPPC_NO_RECV_STP",0, 1),
                  BitField("OFPPC_NO_RECV", 0, 1),
                  BitField("OFPPC_NO_STP", 0, 1),
                  BitField("OFPPC_PORT_DOWN", 0, 1),
                  
                  #uint32_t for state
                  BitField("not_defined_state", 0, 31),
                  BitField("OFPPS_LINK_DOWN", 0, 1),

                  #uint32_t for Current features
                  BitField("curr", 0, 32),
                  
                  #uint32_t for features being advised by the port
                  BitField("advertised", 0, 32),

                  #uint32_t for features supported by the port
                  BitField("supported", 0, 32),

                  #uint32_t for features advertised by peer
                  BitField("peer", 0, 32),
                  
                  #uint16_t supp_swtype
                  BitField("OFPST_FIBER", 0, 1),    # 1<<15 can switch circuits based on SM/MM fiber
                  BitField("OFPST_WAVE", 0, 1),     # 1<<14 can switch circuits based on ITU-T lambdas
                  BitField("OFPST_T_OTN", 0, 1),    # 1<<13 can switch circuits based on OTN standard
                  BitField("OFPST_T_SDH", 0, 1),    # 1<<12 can switch circuits based on SDH standard
                  BitField("OFPST_T_SONET", 0, 1),  # 1<<11 can switch circuits based on SONET standard
                  BitField("NOT_DEFINED", 0, 6),    # Not used
                  BitField("OFPST_ETH", 0, 1),      # 1<<4 can switch packets based on ETH headers
                  BitField("OFPST_VLAN", 0, 1),     # 1<<3 can switch packets based on VLAN tags
                  BitField("OFPST_MPLS", 0, 1),     # 1<<2 can switch packets based on MPLS labels
                  BitField("OFPST_IP", 0, 1),       # 1<<1 can switch packets based on IP headers 
                  BitField("OFPST_L4", 0, 1),       # 1<<0 can switch packets based on TCP/UDP headers
                  
                  #uint16_t supp_sw_gran
                  BitField("SUPP_SW_GRAN", 0, 16),

                  BitField("sup_sdh_port_bandwidth", 0, 8),
                  BitField("sup_otn_port_bandwidth", 0, 8),
                  BitField("peer_port_no", 0, 16),
                  BitField("peer_datapath_id", 0, 64)  
                  #finished    It is correct!
                  ]

    # 
    def show_sw_grain(self):
        if not self.sw_grain == []:
            print self.sw_grain
        elif self.OFPST_T_OTN == 1:
            val = self.SUPP_SW_GRAN
            if val>= 1<<7: val = val%(1<<7)
            if val>= 1<<6: val -= 1<<6; self.sw_grain.append("OFPTOG_ODUFLEX")
            if val>= 1<<5: val -= 1<<5; self.sw_grain.append("OFPTOG_ODU5")
            if val>= 1<<4: val -= 1<<4; self.sw_grain.append("OFPTOG_ODU4")
            if val>= 1<<3: val -= 1<<3; self.sw_grain.append("OFPTOG_ODU3")
            if val>= 1<<2: val -= 1<<2; self.sw_grain.append("OFPTOG_ODU2")
            if val>= 1<<1: val -= 1<<1; self.sw_grain.append("OFPTOG_ODU1")
            if val>= 1<<0: val -= 1<<0; self.sw_grain.append("OFPTOG_ODU0")
            print self.sw_grain
        elif self.OFPST_T_SDH == 1:
            val = self.SUPP_SW_GRAN
            if val>= 1<<5: val = val%(1<<5)
            if val>= 1<<4: val -= 1<<4; self.sw_grain.append("OFPCBT_STM_256")
            if val>= 1<<3: val -= 1<<3; self.sw_grain.append("OFPCBT_STM_64")
            if val>= 1<<2: val -= 1<<2; self.sw_grain.append("OFPCBT_STM_16")
            if val>= 1<<1: val -= 1<<1; self.sw_grain.append("OFPCBT_STM_4")
            if val>= 1<<0: val -= 1<<0; self.sw_grain.append("OFPCBT_STM_1")
            print self.sw_grain
bind_layers(ofp_phy_cport,sup_wave_port_bandwidth)# does it work?

#should be a new field
class ofp_flow_wildcards(Packet):
    name = "OpenFlow Wildcards"
    fields_desc=[ BitField("not_defined", 0, 10), 
                  BitField("OFPFW_NW_TOS", 0, 1),      #1<<21 IP ToS (DSCP field, 6 bits 
                  BitField("OFPFW_DL_VLAN_PCP", 0, 1), #1<<20 VLAN priority
                  
                  #indicating how many bits are not used in the mask
                  BitField("OFPFW_NW_DST_MASK", 0, 6), #((1<<6)-1)<<14
                  BitField("OFPFW_NW_SRC_MASK", 0, 6), #((1<<6)-1)<<8

                  BitField("OFPFW_TP_DST", 0, 1),   #1<<7 TCP/UDP destination port
                  BitField("OFPFW_TP_SRC", 0, 1),   #1<<6 TCP/UDP source port
                  BitField("OFPFW_NW_PROTO", 0, 1), #1<<5 IP protocol
                  BitField("OFPFW_DL_TYPE", 0, 1),  #1<<4 Ethernet frame type
                  BitField("OFPFW_DL_DST",0, 1),    #1<<3 Ethernet destination address
                  BitField("OFPFW_DL_SRC", 0, 1),    #1<<2 Ethernet source address
                  BitField("OFPFW_DL_VLAN", 0, 1),  #1<<1 VLAN id
                  BitField("OFPFW_IN_PORT", 0, 1)   #1<<0 Switch input port
                ]

#the first of the match field is wildcards. I changed it into another
#layer(packet header) before ofp_match structure.
class ofp_match(Packet):
    name = "OpenFlow Match Field"
    fields_desc=[ #should be one wildcards field, defined in the previous class
                  ShortEnumField("in_port", 0, ofp_port),   #Input switch port
                  MACField("dl_src", "00:00:00:00:00:00"),        #Ethernet source address
                  MACField("dl_dst", "00:00:00:00:00:00"),        #Ethernet destination address
                  ShortField("dl_vlan", 0xffff),     #input VLAN id
                  XByteField("dl_vlan_pcp", 0), #input VLAN priority
                  XByteField("pad1", 0),        #Padding to align to 64 bits
                  ShortField("dl_type", 0),     #Ethernet frame type
                  XByteField("nw_tos", 0),      #IP ToS
                  XByteField("nw_proto", 0),    #IP protocol or lower 8 bits of ARP
                  XByteField("pad2.1", 0),      #Padding to align to 64 bits
                  XByteField("pad2.2", 0),      #Padding to align to 64 bits
                  IPField("nw_src","0.0.0.0"),  #IP source address
                  IPField("nw_dst","0.0.0.0"),  #IP destination address
                  ShortField("tp_src", 0),      #TCP/UDP source port
                  ShortField("tp_dst", 0),      #TCP/UDP destination port
                ]


############################

# TODO:Build a match by packet

############################


def packet2match(pkt, in_port = None, spec_frags = False):
    """
    make the wildcards and match form pakcet. //pakcet is the data we recieved.
    """
    #pkt.show()
    rmsg = pkt#of.ofp_header(data[0:8])
    pkt_in_msg = pkt.payload#of.ofp_packet_in(data[8:])
    in_port = pkt_in_msg.in_port
    pkt_parsed = pkt_in_msg.payload#Ether(pkt_in_msg.load)
    match = ofp_match()

    if in_port is not None:
        match.in_port = in_port

    match.dl_src = pkt_parsed.src
    match.dl_dst = pkt_parsed.dst
    match.dl_type = pkt_parsed.type
    packet = pkt_parsed.payload

    # Is this in the spec? 
    if pkt_parsed.type < 1536:
        #print "OFP_DL_TYPE_NOT_ETH_TYPE"
        match.dl_type = OFP_DL_TYPE_NOT_ETH_TYPE
    if pkt_parsed.type ==0x8100:
        #print "0x8100"
        match.dl_type = pkt_parsed.type
        match.dl_vlan = packet.vlan
        packet = packet.next # goto IP
    else:
        #print "match.dl_vlan = 0xffff"
        match.dl_vlan = 0xffff;

    if isinstance(packet, IP):
        #print "<<<<<IP>>>>>"
        match.nw_src = packet.src
        match.nw_dst = packet.dst
        match.nw_proto = packet.proto
        match.nw_tos = packet.tos
        # This seems a bit strange, but see page 9 of the spec.
        if isinstance(packet.payload, TCP) or isinstance(packet.payload, UDP):
            #print "<<<<<TCP or UDP>>>>>"
            match.tp_src = packet.sport
            match.tp_dst = packet.dport
        elif isinstance(packet.payload, ICMP):
            #print "<<<<<ICMP>>>>>"
            match.tp_src = packet.type
            match.tp_dst = packet.code
        else:
            match.tp_dst = 0
            match.tp_src = 0

    elif isinstance(packet, ARP):
        #print "<<<<<ARP>>>>>"
        if packet.ptype <= 255:
            match.nw_proto = packet.ptype
            match.nw_src = packet.psrc
            match.nw_dst = packet.pdst
    return match

#THE SIZE OF MATCH IS 40 BYTES
###################
# OpenFlow Header #
###################

class ofp_header(Packet):
    name = "OpenFlow Header "
    fields_desc=[ XByteField("version", 1),
                  ByteEnumField("type", 0, ofp_type),
                  ShortField("length", 8),
                  IntField("xid", 1) ]

#OFP_HELLO, OFP_ECHO_REQUEST and OFP_FEATURES_REQUEST do not have a body.

class ofp_action_header(Packet):
    name = "OpenFlow Action Header"
    fields_desc=[ ShortEnumField("type", 0, ofp_action_type),
                  ShortField("len", 0), #length of this action (including this header)
                  BitField("pad", 0, 32)]





#####################
# OpenFlow Messages #
#####################

# No. 1
# [header|error_msg]
class ofp_error_msg(Packet):
    name = "OpenFlow Error Message"
    fields_desc=[ ShortEnumField("type", 0, ofp_error_type),
                  ShortField("code", 0), #need to parse with type field, use another function
                  StrFixedLenField("data", None, length=8)]
bind_layers( ofp_header, ofp_error_msg, type=1 )

# No. 6
# [header|features_reply|port]
class ofp_features_reply(Packet):
    name = "OpenFlow Switch Features Reply"
    """
    If the field is number has some meaning, and have to use ``show()`` to present
    better not use things in Simple datatypes like ``LongField`` or ``IEEEDoubleField``
    those field will automatically convert your data into some unreadable numbers
    For presenting, just use ``BitFieldLenField``, parameters are name, default
    value, length(in bits) and something I don't know.
    """
    fields_desc=[ BitField('datapath_id', None, 64),
                  BitField('n_buffers', None, 32),
                  XByteField("n_tables", 0),
                  X3BytesField("pad", 0),
                  #features
                  BitField("OFPC_OTN_SWITCH", 0, 1),    #1<<31
                  BitField("OFPC_WAVE_SWITCH", 0, 1),   #1<<30
                  BitField("NOT_DEFINED", 0, 22),
                  BitField("OFPC_ARP_MATCH_IP", 0, 1),  #1<<7 Match IP address in ARP packets
                  BitField("OFPC_QUEUE_STATS", 0, 1),   #1<<6 Queue statistics
                  BitField("OFPC_IP_STREAM", 0, 1),     #1<<5 Can reassemble IP fragments
                  BitField("OFPC_RESERVED", 0, 1),      #1<<4 Reserved, must be zero
                  BitField("OFPC_STP", 0, 1),           #1<<3 802.1d spanning tree
                  BitField("OFPC_PORT_STATS", 0, 1),    #1<<2 Port statistics
                  BitField("OFPC_TABLE_STATS", 0, 1),   #1<<1 Table statistics
                  BitField("OFPC_FLOW_STATS", 0, 1),    #1<<0 Flow statistics
                  BitField('actions', None, 32),
                  #port info can be resoved at TCP server
                ]
bind_layers( ofp_header, ofp_features_reply, type=6 )

#_________________________________________________This is a new packet on OTN ,you need to pay attention.___________________________

#No. 24
class ofp_cfeatures_reply(Packet):
    name = "OpenFlow Switch CFeatures Reply"
    """
    If the field is number has some meaning, and have to use ``show()`` to present
    better not use things in Simple datatypes like ``LongField`` or ``IEEEDoubleField``
    those field will automatically convert your data into some unreadable numbers
    For presenting, just use ``BitFieldLenField``, parameters are name, default
    value, length(in bits) and something I don't know.
    """
    fields_desc=[ BitField('datapath_id', None, 64),
                  BitField('n_buffers', None, 32),
                  XByteField("n_tables", 0),
                  XByteField("n_cports", 0),#  there is some difference right here.
                  XByteField("pad2.0", 0),
                  XByteField("pad2.1",0),
                  #features
                  BitField("OFPC_OTN_SWITCH", 0, 1),    #1<<31
                  BitField("OFPC_WAVE_SWITCH", 0, 1),   #1<<30
                  BitField("OFPC_IP_SWITCH", 0, 1),    #1<<29
                  BitField("NOT_DEFINED", 0, 21),
                  BitField("OFPC_ARP_MATCH_IP", 0, 1),  #1<<7 Match IP address in ARP packets
                  BitField("OFPC_QUEUE_STATS", 0, 1),   #1<<6 Queue statistics
                  BitField("OFPC_IP_STREAM", 0, 1),     #1<<5 Can reassemble IP fragments
                  BitField("OFPC_RESERVED", 0, 1),      #1<<4 Reserved, must be zero
                  BitField("OFPC_STP", 0, 1),           #1<<3 802.1d spanning tree
                  BitField("OFPC_PORT_STATS", 0, 1),    #1<<2 Port statistics
                  BitField("OFPC_TABLE_STATS", 0, 1),   #1<<1 Table statistics
                  BitField("OFPC_FLOW_STATS", 0, 1),    #1<<0 Flow statistics
                  BitField('actions', None, 32),
                  #port info can be resoved at TCP server
                ]
#bind_layers(ofp_features_reply,ofp_phy_cport)#can we do it ?
bind_layers( ofp_header, ofp_features_reply, type= 24)

#No. 8 or 9
#header()/ofp_switch_config()
class ofp_switch_config(object):
  name = "Openflow switch config"
  fields_desc=[ ShortField("flags", 0),
                ShortField("miss_send_len", 65535)
              ]
#sizeof(ofp_switch_config) = 12

# No. 10
class ofp_packet_in(Packet):
    name = "OpenFlow Packet In"
    fields_desc=[ IntField("buffer_id", None),
                  ShortField("total_len", None),
                  ShortField("in_port", None),
                  ByteEnumField("reason", 0, ofp_packet_in_reason),
                  ByteField("pad", None)]

#No. 11 
#full message is header()/match()/flow_removed
class ofp_flow_removed(Packet):
  name = "Openflow flow removed"
  fields_desc = [ BitField("cookie", 0, 64),
                  BitField("priority", 0,16),
                  BitField("reason", 0, 8),
                  ByteField("pad", None),
                  BitField("duration_sec", 0, 32),
                  BitField("duration_nsec", 0, 32),
                  BitField("idle_timeout", 0, 16),
                  ByteField("pad", 0),
                  ByteField("pad", 0),
                  BitField("packet_count", 0, 64),
                  BitField("byte_count", 0, 64)
                ]
#sizeof(ofp_flow_removed)=88 



# No. 12
class ofp_port_status(Packet):
    name = "OpenFLow Port Status"
    fields_desc=[ ByteEnumField("reason", 0, ofp_port_reason),
                  BitField("pad", 0, 56)]

# No. 13 
class ofp_pktout_header(Packet):
    name = "OpenFlow Packet Out"
    fields_desc=[ IntField("buffer_id", None),
                  ShortField("in_port", None),
                  ShortField("actions_len", None)] 
bind_layers( ofp_header, ofp_pktout_header, type=13)

class ofp_action_output(Packet):
    name = "OpenFLow Action Output"
    fields_desc=[ ShortEnumField("type", 0, ofp_action_type),
                  ShortField("len", 8),
                  ShortEnumField("port", None, ofp_port),
                  ShortField("max_len", 0)]
bind_layers( ofp_pktout_header, ofp_action_output, type=0)
bind_layers( ofp_pktout_header, ofp_action_output, actions_len=8)

# action_strip_vlan is just a action header, with type = 3

class ofp_action_vlan_vid(Packet):
    name = "OpenFlow Action Set VLAN VID"
    fields_desc=[ ShortEnumField("type", 1, ofp_action_type),
                 ShortField("len", 8),
                 ShortField("vlan_vid", 0xffff),
                 BitField("pad", 0, 16)]


# No. 14
class ofp_flow_mod(Packet):
    name = "OpenFlow Flow Modify"
    fields_desc=[ BitField("cookie", 0, 64), #Opaque controller-issued identifier
                  #Flow Actions
                  ShortEnumField("command", 0, ofp_flow_mod_command),
                  ShortField("idle_timeout", 60),
                  ShortField("hard_timeout", 0),
                  ShortField("priority", 0),
                  IntField("buffer_id", 0),
                  ShortField("out_port", 0),
                  #flags are important, the 1<<0 bit is OFPFF_SEND_FLOW_REM, send OFPT_FLOW_REMOVED
                  #1<<1 bit is OFPFF_CHECK_OVERLAP, checking if the entries' field overlaps(among same priority)  
                  #1<<2 bit is OFPFF_EMERG, used only switch disconnected with controller) 
                  ShortField("flags", 0)
                ]
#####################
#create a flow

#####################                
def create_flow(pkt, outport =None):
    wildcards = ofp_flow_wildcards(  OFPFW_NW_TOS=1,
                                        OFPFW_DL_VLAN_PCP=1,
                                        OFPFW_NW_DST_MASK=63,
                                        OFPFW_NW_SRC_MASK=63,
                                        OFPFW_TP_DST=1,
                                        OFPFW_TP_SRC=1,
                                        OFPFW_NW_PROTO=1,
                                        OFPFW_DL_TYPE=1,
                                        OFPFW_DL_VLAN=1,
                                        OFPFW_IN_PORT=1,
                                        OFPFW_DL_DST=0,
                                        OFPFW_DL_SRC=0)
    match = packet2match(pkt)
    #print type(match)
    rmsg = pkt#of.ofp_header(data[0:8])
    pkt_in_msg = pkt.payload#of.ofp_packet_in(data[8:])
    pkt_parsed = pkt_in_msg.payload#of.Ether(pkt_in_msg.load)
    if outport:
        out_port = outport
    else:
        out_port =0xfffb
    flow_mod = ofp_flow_mod( cookie=0,
                                command=0,
                                idle_timeout=10,
                                hard_timeout=30,
                                out_port=out_port,
                                buffer_id=pkt_in_msg.buffer_id,
                                flags=1)
    action = ofp_action_header(type=0,len=8)/ofp_action_output(type=0, port=out_port)
    header = ofp_header(type = 14,xid = rmsg.xid)
    flow_mod = header/wildcards/match/flow_mod/action
    flow_mod.length = len(flow_mod)
    return flow_mod





#No. 15
#header()/ofp_port_mod()
class ofp_port_mod(object):
  name = "Openflow port mod"
  fields_desc=[ ShortEnumField("port_no", 0, ofp_port),
                MACField("hw_addr","00:00:00:00:00:00"),
                BitField("config", 0, 32),
                BitField("mask", 0, 32),
                BitField("advertise", 0, 32),
                X3BytesField("pad", 0),
                ByteField("pad", 0)
              ]
#sizeof(ofp_port_mod)=32

# No. 16 
#full message for flow status request: ofp_stats_rqeuest()/ofp_flow_wildcards()/ofp_match()/ofp_flow_stats_request()
class ofp_stats_request(Packet):
    name = "OpenFlow Stats Request"
    fields_desc=[ ShortEnumField("type", 0, ofp_stats_types),
                  ShortField("flag", 0)]     #body follow this

#body of ofp_status_request
#need to add a match field before this pkt
class ofp_flow_stats_request(Packet):
    name = "OpenFlow Flow Stats Request"
    fields_desc=[ ByteField("table_id", 0xff), #all flows by default
                  BitField("pad", 0, 8),
                  ShortField("out_port", 0xffff)] #no restriction by default, ofp_port.OFPP_NONE

#reply from switch [actually same with ofp_stats_request] len = 4 bytes
class ofp_stats_reply(Packet):
    name = "OpenFlow Stats Reply"
    fields_desc=[ ShortEnumField("type", 0, ofp_stats_types),
                  ShortField("flag", 0)]

#full message: ofp_flow_stats()/ofp_flow_wildcards()/ofp_match()/ofp_flow_stats_data()/ofp_action_header()
class ofp_flow_stats(Packet):
    name = "OpenFlow Flow Stats"
    fields_desc=[ ShortField("length", 0),
                  BitField("table_id", 0, 8),
                  BitField("pad", 0, 8)]# following match strcture
class ofp_table_stats(Packet):
    name = "OpenFlow Table Stats"
    fields_desc=[ BitField("table_id", 0, 8),
                  X3BytesField("pad", 0),
                  StrFixedLenField("name", None, length=32)
                ]
#sizeof(ofp_table_stats == 64),so the strfixedlenfield's length is the byte not bit
#full messege:ofp_table_stats()/ofp_wildcards()/ofp_table_stats_data()

class ofp_table_stats_data(Packet):
    name = "OpenFlow Table Stats data"
    fields_desc=[ BitField("max_entries", 0, 32),
                  BitField("active_count", 0, 32),
                  BitField("lookup_count", 0, 64),
                  BitField("matched_count", 0, 64)
                ]

class ofp_flow_stats_data(Packet):
    name = "OpenFlow Flow Stats Data"
    fields_desc=[ IntField("duration_sec", 0),
                  IntField("duration_nsec", 0),
                  ShortField("priority", 0),
                  ShortField("idle_timeout", 0),
                  ShortField("hard_timeout", 0),
                  BitField("pad", 0, 48),
                  BitField("cookie", 0, 64),
                  BitField("packet_count", 0, 64),
                  BitField("byte_count", 0, 64)]# following ofp_action_header
class ofp_desc_stats(Packet):
  name = "Openflow desc stats"
  fields_desc=[ StrFixedLenField("mfr_desc", None, length=256),
                StrFixedLenField("hw_desc", None, length=256),
                StrFixedLenField("sw_desc", None, length=256),
                StrFixedLenField("serial_num", None, length=32),
                StrFixedLenField("dp_desc", None, length=256)
              ]
#sizeof (ofp_desc_stats) =64  that is so terrible! longer than 1024
#there is match before aggregate_stats_request
class ofp_aggregate_stats_request(Packet):
  name = "OpenFlow aggregate_stats_request"
  fields_desc=[ ByteField("table_id", 0xff),
                ByteField("pad", 0),
                ShortField("out_port", 0xffff)
              ]
    
class ofp_aggregate_stats_reply(Packet):
  name = "Openflow aggregate_stats"
  fields_desc=[ BitField("packet_count", 0, 64),
                BitField("byte_count", 0, 64),
                BitField("flow_count", 0, 32),
                X3BytesField("pad", 0),
                ByteField("pad", 0)
  ]
#sizeof(aggregate_stats_reply) =24

class ofp_port_stats_request(Packet):
  name = "Openflow port stats request"
  fields_desc=[ ShortField("port_no", 0xffff),
                X3BytesField("pad", 0),
                X3BytesField("pad", 0)
              ]
#sizeof(port_stats_request) =8

class ofp_port_stats_reply(Packet):
  name = "Openflow port stats reply"
  fields_desc=[ ShortEnumField("port_no", 0, ofp_port),
                X3BytesField("pad", 0),
                X3BytesField("pad", 0),
                BitField("rx_packets", 0, 64),
                BitField("tx_packets", 0, 64),
                BitField("rx_bytes", 0, 64),
                BitField("tx_bytes", 0, 64),
                BitField("rx_dropped", 0, 64),
                BitField("tx_dropped", 0, 64),
                BitField("rx_errors", 0, 64),
                BitField("tx_errors", 0, 64),
                BitField("rx_frame_err", 0, 64),
                BitField("rx_over_err", 0, 64),
                BitField("rx_crc_err", 0, 64),
                BitField("collisions", 0, 64)
                ]
#sizeof(ofp_port_stats_reply)=104
class ofp_queue_stats_request(Packet):
  name = "Openflow queue stats request"
  fields_desc=[ ShortField("port_no", 0xfffc),
                ByteField("pad", 0 ),
                ByteField("pad", 0),
                BitField("queue_id", 0, 32)
                ]
#sizeof(ofp_queue_stats_request)= 8

class ofp_queue_stats(Packet):
  name = "Openflow queue stats reply"
  fields_desc=[ ShortEnumField("port_no", 0, ofp_port),
                ByteField("pad", 0 ),
                ByteField("pad", 0),
                BitField("queue_id", 0, 32),
                BitField("tx_bytes", 0, 64),
                BitField("tx_packets", 0, 64),
                BitField("tx_errors", 0, 64)
                ]
#sizeof(ofp_queue_stats)=32

class ofp_vendor(Packet):
  name = "Openflow vendor"
  fields_desc=[ BitField("vendor", 0, 32)
              ]
#sizeof (ofp_vendor)= 4

#No.20
class ofp_queue_get_config_request(Packet):
  name = "Openflow queue get config request"
  fields_desc=[ ShortEnumField("port_no", 0, ofp_port),
                ByteField("pad", 0),
                ByteField("pad", 0)
              ]
#sizeof(ofp_queue_get_config_request)=12

#No.21
class ofp_queue_get_config_reply(Packet):
  name = "Openflow queue get config reply"
  fields_desc=[ ShortEnumField("port_no", 0, ofp_port),
                X3BytesField("pad", 0),
                X3BytesField("pad", 0)
              ]
#sizeof(ofp_queue_get_config_request)=16

class ofp_packet_queue(Packet):
  name = "Openflow packet queue"
  fields_desc=[ BitField("queue_id", 0, 32),
                ShortField("len", 0),
                ByteField("pad", 0),
                ByteField("pad", 0)
  ]
#sizeof(ofp_packet_queue)= 8  full message ofp_packet_queue()/ofp_queue_prop_header()

class ofp_queue_prop_header(Packet):
  name = "Openflow queue prop header"
  fields_desc= [  ShortEnumField("property", 0, ofp_queue_properties),
                  ShortField("len", 0),
                  X3BytesField("pad", 0),
                  ByteField("pad", 0)
                ]
#sizeof(ofp_queue_prop_header)=8

class ofp_queue_prop_min_rate(Packet):
  name = "Openflow queue property min rate"
  fields_desc=[ ShortField("rate", 0),
                X3BytesField("pad", 0),
                X3BytesField("pad", 0),
                ]
#sizeof(ofp_queue_prop_min_rate)= 16 full message is ofp_queue_prop_header()/ofp_queue_prop_min_rate()
#_________________________________________________This is a new packet on OTN ,you need to pay attention.___________________________


# of.ofp_header()/of.ofp_cflow_mod()/of.ofp_flow_wildcards()/of.ofp_match()/ofp_connect()/of.ofp_action_output()...
# No. 0xff
class ofp_cflow_mod(Packet):
    name = "OpenFlow Circuit Flow Modify"
    fields_desc=[ ShortEnumField("command", 0, ofp_flow_mod_command),
                  ShortField("hard_timeout", 0),
                  BitField("pad", 0, 32)] # append "ofp_connection" and "ofp_action_header" / "ofp_action"

bind_layers( ofp_header, ofp_cflow_mod, type = 0xff)

class ofp_connect_wildcards(Packet):
    name = "OpenFlow Connect Wildcards"
    fields_desc=[ BitField("not_defined", 0, 10),
                  BitField("OFPCW_OUT_WPORT", 0, 1),# 1 << 5
                  BitField("OFPCW_IN_WPORT", 0, 1), # 1 << 4
                  BitField("OFPCW_OUT_TPORT", 0, 1),# 1 << 3
                  BitField("OFPCW_IN_TPORT", 0, 1), # 1 << 2
                  BitField("OFPCW_OUT_PORT", 0, 1), # 1 << 1
                  BitField("OFPCW_IN_PORT", 0, 1),] # 1 << 0

bind_layers( ofp_cflow_mod, ofp_connect_wildcards)

# need of.ofp_flow_wildcards()/of.ofp_match() before this strcture
class ofp_connect(Packet):
    name = "OpenFlow Circuit Connection"
    fields_desc=[ ShortField("num_components", 0),
                  BitField("pad", 0, 32),
                  ShortEnumField("in_port", 0, ofp_port),
                  ShortEnumField("out_port", 0, ofp_port),
                  #------------------------------------------
                  #ofp_tdm_port in_tport
                  ShortEnumField("tport_in", 0, ofp_port),  
                  ShortField("tstart_in", 0),
                  IntField("tsignal_in", 0),
                  
                  #ofp_tdm_port out_tport
                  ShortEnumField("tport_out", 0, ofp_port),
                  ShortField("tstart_out", 0),
                  IntField("tsignal_out", 0),
                  #------------------------------------------
                  #ofp_otn_port in_nport
                  ShortEnumField("nport_in", 0, ofp_port),  # physical port of in-coming packet
                  ShortField("supp_sw_otn_gran_in", 0),     # ODU of in-coming port 
                  BitField("sup_otn_port_bandwidth_in", 0, 8), 
                  BitField("pad", 0, 8),
                  BitField("bitmap_in", 0, 80),

                  #ofp_otn_port out_nport
                  ShortEnumField("nport_out", 0, ofp_port), # physical port of out-coming packet
                  ShortField("supp_sw_otn_gran_out", 0),    # ODU of out-coming port
                  BitField("sup_otn_port_bandwidth_out", 0, 8),
                  BitField("pad", 0, 8),
                  BitField("bitmap_out", 0, 80),
                  #------------------------------------------
                  #ofp_wave_port in_wport
                  ShortEnumField("wport_in", 0, ofp_port),  # physical port of in-coming packet 
                  IntField("center_freq_lmda_in", 0),
                  BitField("num_wave_in", 0, 8),            # lambda of in-coming port
                  BitField("flag_in", 0, 8),
                  
                  #ofp_wave_port out_wport
                  ShortEnumField("wport_out", 0, ofp_port), # physical port of out-coming packet
                  IntField("center_freq_lmda_out", 0),
                  BitField("num_wave_out", 0, 8),           # lambda of out-coming port
                  BitField("flag_out", 0, 8)
                  ]
    
bind_layers( ofp_connect_wildcards, ofp_connect)







####################
# Useful Functions #
####################

"""
0    okay    "OFPT_HELLO",               8 bytes
1    okay    "OFPT_ERROR",               8 + 12 bytes
2    okay    "OFPT_ECHO_REQUEST",
3    okay    "OFPT_ECHO_REPLY",
4    okay    "OFPT_VENDOR",
5    okay    "OFPT_FEATURES_REQUEST",
6    okay    "OFPT_FEATURES_REPLY",
7    oaky    "OFPT_GET_CONFIG_REQUEST",
8    okay    "OFPT_GET_CONFIG_REPLY",
9    okay    "OFPT_SET_CONFIG",
10   okay    "OFPT_PACKET_IN",
11   okay    "OFPT_FLOW_REMOVED",
12   okay    "OFPT_PORT_STATUS",
13   okay    "OFPT_PACKET_OUT",# with action header
14   okay    "OFPT_FLOW_MOD",
15   okay    "OFPT_PORT_MOD",
16   okay    "OFPT_STATS_REQUEST",
17   okay    "OFPT_STATS_REPLY",
18   okay    "OFPT_BARRIER_REQUEST",
19   okay    "OFPT_BARRIER_REPLY",
20   okay    "OFPT_QUEUE_GET_CONFIG_REQUEST",
21   okay    "OFPT_QUEUE_GET_CONFIG_REPLY"
24   oaky    "OFPT_CFEATURES_REPLY"
0xfe oaky    "OFPT_CPORT_STATUS" 
0xff okay    "OFPT_CFLOW_MO
"""
    
if __name__ == '__main__':
    import convert
    import libopenflow as of 
    #a = ofp_cfeatures_reply()
    #b = ofp_phy_cport()
    #c = ofp_phy_cport()
    #d=ofp_header(type =24,length = 32+78*2)/ofp_cfeatures_reply(n_cports=2)/ofp_phy_cport()/sup_wave_port_bandwidth(num_lmda=4)/ofp_phy_cport()/sup_wave_port_bandwidth(num_lmda=5)

    #d.show()
    #a.n_cports=2
    #a.OFPC_TABLE_STATS=100
    #a.OFPST_T_OTN = 1
    #a.SUPP_SW_GRAN = 129
    #print a.SUPP_SW_GRAN
    buffer = {}
    dpid = 8

    e = of.ofp_header(type =6)/of.ofp_features_reply(datapath_id=1)/of.ofp_phy_port(port_no=1)/of.ofp_phy_port(port_no=2)\
                              /of.ofp_phy_port(port_no=3)/of.ofp_phy_port(port_no=4)/of.ofp_phy_port(port_no=5)
    f = convert.of2ofc(e, buffer, dpid)
    f.show()
    p = str(f)