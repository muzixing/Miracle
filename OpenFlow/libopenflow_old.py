import sys
sys.path.append('/opt/local/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/site-packages/')
from scapy.all import *

#uint8_t => XByteField
#uint16_t => ShortField, BitFieldLenField('name', None, 16, length_of='varfield')
#uint32_t => IntField, BitFieldLenField('name', None, 32, length_of='varfield'),

"""
none    "OFPT_HELLO",
okay    "OFPT_ERROR",
none    "OFPT_ECHO_REQUEST",
none    "OFPT_ECHO_REPLY",
        "OFPT_VENDOR",
okay    "OFPT_FEATURES_REQUEST",
        "OFPT_FEATURES_REPLY",
        "OFPT_GET_CONFIG_REQUEST",
        "OFPT_GET_CONFIG_REPLY",
        "OFPT_SET_CONFIG",
okay    "OFPT_PACKET_IN",
        "OFPT_FLOW_REMOVED",
        "OFPT_PORT_STATUS",
okay    "OFPT_PACKET_OUT",# with action header
okay    "OFPT_FLOW_MOD",
        "OFPT_PORT_MOD",
        "OFPT_STATS_REQUEST",
        "OFPT_STATS_REPLY",
        "OFPT_BARRIER_REQUEST",
        "OFPT_BARRIER_REPLY",
        "OFPT_QUEUE_GET_CONFIG_REQUEST",
        "OFPT_QUEUE_GET_CONFIG_REPLY"
"""


###################
# Data Structures #
###################

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
             21: "OFPT_QUEUE_GET_CONFIG_REPLY"}

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
                    3: "OFPPR_MODIFY"}

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
                         4: "OFPFC_DELETE_STRICT"}  # Strictly match wildcards and priority

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
                        7: "OFPBAC_EPERM", #permissions error
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

#should be a new field, len = 32bits = 4bytes
class ofp_flow_wildcards(Packet):
    name = "OpenFlow Wildcards"
    fields_desc=[ BitField("not_defined", 0, 10), 
                  BitField("OFPFW_NW_TOS", 0, 1),      #1<<21 IP ToS (DSCP field, 6 bits 
                  BitField("OFPFW_DL_VLAN_PCP", 0, 1), #1<<20 VLAN priority
                  
                  #indicating how many bits are not used in the mask
                  BitField("OFPFW_NW_DST_MASK", 0, 6), #((1<<6)-1)<<14
                  BitField("OFPFW_NW_SRC_MASK", 0, 6), #((1<<6)-1)<<8

                  BitField("OFPFW_TP_DST", 0, 1),      #1<<7 TCP/UDP destination port
                  BitField("OFPFW_TP_SRC", 0, 1),      #1<<6 TCP/UDP source port
                  BitField("OFPFW_NW_PROTO", 0, 1),    #1<<5 IP protocol
                  BitField("OFPFW_DL_TYPE", 0, 1),     #1<<4 Ethernet frame type
                  BitField("OFPFW_DL_DST",0, 1),       #1<<3 Ethernet destination address
                  BitField("OFPFW_DL_SRC", 0, 1),      #1<<2 Ethernet source address
                  BitField("OFPFW_DL_VLAN", 0, 1),     #1<<1 VLAN id
                  BitField("OFPFW_IN_PORT", 0, 1)      #1<<0 Switch input port
                ]

#the first of the match field is wildcards. I changed it into another
#layer(packet header) before ofp_match structure. len = 36 bytes
class ofp_match(Packet):
    name = "OpenFlow Match Field"
    fields_desc=[ #should be one wildcards field, defined in the previous class
                  ShortEnumField("in_port", 0, ofp_port),   #Input switch port
                  MACField("dl_src", "00:00:00:00:00:00"),  #Ethernet source address
                  MACField("dl_dst", "00:00:00:00:00:00"),  #Ethernet destination address
                  ShortField("dl_vlan", 0xffff),            #input VLAN id
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
                  ShortField("len", 8), #length of this action (including this header)
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
    fields_desc=[ BitFieldLenField('datapath_id', None, 64, length_of='varfield'),
                  BitFieldLenField('n_buffers', None, 32, length_of='varfield'),
                  XByteField("n_tables", 0),
                  X3BytesField("pad", 0),
                  #features
                  BitField("NOT DEFINED", 0, 24),
                  BitField("OFPC_ARP_MATCH_IP", 0, 1),  #1<<7 Match IP address in ARP packets
                  BitField("OFPC_QUEUE_STATS", 0, 1),   #1<<6 Queue statistics
                  BitField("OFPC_IP_STREAM", 0, 1),     #1<<5 Can reassemble IP fragments
                  BitField("OFPC_RESERVED", 0, 1),      #1<<4 Reserved, must be zero
                  BitField("OFPC_STP", 0, 1),           #1<<3 802.1d spanning tree
                  BitField("OFPC_PORT_STATS", 0, 1),    #1<<2 Port statistics
                  BitField("OFPC_TABLE_STATS", 0, 1),   #1<<1 Table statistics
                  BitField("OFPC_FLOW_STATS", 0, 1),    #1<<0 Flow statistics
                  BitFieldLenField('actions', None, 32, length_of='varfield'),
                  #port info can be resoved at TCP server
                ]
bind_layers( ofp_header, ofp_features_reply, type=6 )

# No. 10
class ofp_packet_in(Packet):
    name = "OpenFlow Packet In"
    fields_desc=[ IntField("buffer_id", None),
                  ShortField("total_len", None),
                  ShortField("in_port", None),
                  ByteEnumField("reason", 0, ofp_packet_in_reason),
                  ByteField("pad", None)]
bind_layers( ofp_header, ofp_packet_in, type=10 )

# No. 12
class ofp_port_status(Packet):
    name = "OpenFLow Port Status"
    fields_desc=[ ByteEnumField("reason", 0, ofp_port_reason),
                  BitField("pad", 0, 56)]
bind_layers( ofp_header, ofp_port_status, type=12 )

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
                  ShortField("flags", 0)]
bind_layers( ofp_header, ofp_flow_mod, type=14 )
    
# No. 16
#full message for flow status request: ofp_status_rqeuest()/ofp_flow_wildcards()/ofp_match()/ofp_flow_status_request()
class ofp_stats_request(Packet):
    name = "OpenFlow Stats Request"
    fields_desc=[ ShortEnumField("type", 0, ofp_stats_types),
                  ShortField("flag", 0)]#body follow this

#body of ofp_status_request
#need to add a match field before this pkt
class ofp_flow_stats_request(Packet):
    name = "OpenFlow Flow Stats Request"
    fields_desc=[ BitField("table_id", 0xff, 8), #all flows by default
                  BitField("pad", 0, 8),
                  ShortField("out_port", 0xffff)] #no restriction by default, ofp_port.OFPP_NONE

#reply from switch [actually same with ofp_stats_request] len = 4 bytes
class ofp_stats_reply(Packet):
    name = "OpenFlow Stats Reply"
    fields_desc=[ ShortEnumField("type", 0, ofp_stats_types),
                  ShortField("flag", 0)]

#full message: ofp_flow_status()/ofp_flow_wildcards()/ofp_match()/ofp_status_data()/ofp_action_header()
class ofp_flow_stats(Packet):
    name = "OpenFlow Flow Stats"
    fields_desc=[ ShortField("length", 0),
                  BitField("table_id", 0, 8),
                  BitField("pad", 0, 8)]# following match strcture
    
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


####################
# Useful Functions #
####################

"""
0    none    "OFPT_HELLO",               8 bytes
1    okay    "OFPT_ERROR",               8 + 12 bytes
2    none    "OFPT_ECHO_REQUEST",
3    none    "OFPT_ECHO_REPLY",
4            "OFPT_VENDOR",
5    okay    "OFPT_FEATURES_REQUEST",
6    okay    "OFPT_FEATURES_REPLY",
7            "OFPT_GET_CONFIG_REQUEST",
8            "OFPT_GET_CONFIG_REPLY",
9            "OFPT_SET_CONFIG",
10   okay    "OFPT_PACKET_IN",
11           "OFPT_FLOW_REMOVED",
12           "OFPT_PORT_STATUS",
13   okay    "OFPT_PACKET_OUT",# with action header
14   okay    "OFPT_FLOW_MOD",
15           "OFPT_PORT_MOD",
16           "OFPT_STATS_REQUEST",
17           "OFPT_STATS_REPLY",
18           "OFPT_BARRIER_REQUEST",
19           "OFPT_BARRIER_REPLY",
20           "OFPT_QUEUE_GET_CONFIG_REQUEST",
21           "OFPT_QUEUE_GET_CONFIG_REPLY"
"""


def parse(unparsed):
    if len(unparsed) < 8:
        return ''  #indicating unparsed pkt is not of packet
    else:
        header = ofp_header(unparsed[:8]) #first 8 bytes are ofp_header, else are header.payload 
        if header.type == 0:
            print "OFPT_HELLO" # only 8 bytes
            #return header
        
        elif header.type == 1:
            print "OFPT_ERROR"
            error = ofp_error_msg(unparsed[8:20])
            #return header/error
        
        elif header.type == 2:
            print "OFPT_ECHO_REQUEST"
            #return header
        
        elif header.type == 3:
            print "OFPT_ECHO_REPLY"
            #return header
        
        elif header.type == 4:
            print "OFPT_VENDOR"
        
        elif header.type == 5:
            print "OFPT_FEATURES_REQUEST"
        
        elif header.type == 6:
            print "OFPT_FEATURES_REPLY"
        
        elif header.type == 7:
            print "OFPT_GET_CONFIG_REQUEST"
        
        elif header.type == 8:
            print "OFPT_GET_CONFIG_REPLY"
        
        elif header.type == 9:
            print "OFPT_SET_CONFIG"
        
        elif header.type == 10:
            print "OFPT_PACKET_IN"
        
        elif header.type == 11:
            print "OFPT_FLOW_REMOVED"
        
        elif header.type == 12:
            print "OFPT_PORT_STATUS"
        
        elif header.type == 13:
            print "OFPT_PACKET_OUT"
        
        elif header.type == 14:
            print "OFPT_FLOW_MOD"
        
        elif header.type == 15:
            print "OFPT_PORT_MOD"
        
        elif header.type == 16:
            print "OFPT_STATS_REQUEST"
        
        elif header.type == 17:
            print "OFPT_STATS_REPLY"
        
        elif header.type == 18:
            print "OFPT_BARRIER_REQUEST"
        
        elif header.type == 19:
            print "OFPT_BARRIER_REPLY"
        
        elif header.type == 20:
            print "OFPT_QUEUE_GET_CONFIG_REQUEST"
        
        elif header.type == 21:
            print "OFPT_QUEUE_GET_CONFIG_REPLY"
    
    
if __name__ == '__main__':
    a = ofp_header()
    a.show()
    a.type = 3
    a.show()
    print 'can only change type to another number'
    a.tpye = "OFPT_STATS_REPLY"
    a.show()
    a.type = 17
    a.show()

    print "\n testing for the OFP_FEATURES_REPLY msg"
    b = ofp_header()/ofp_features_reply()
    # before stringify the packet, must assign the labels that marked as 'None'
    b.datapath_id = 00000001
    b.capabilities = 123
    b.actions = 1
    b.n_buffers = 32
    b.show()
    c = str(b)
    print len(c)
    c = c + "AAAAAAAAAAAAAAAAAAAAAAA"
    d = ofp_header(c)
    d.show()
    print len(c)
    
    #if using part of received data, length can be devide by 8 is a must
    d = ofp_features_reply(c[0:39])
    d.show()
    
    #loading scapy packet
    print "-----------------"
    Ether().show()