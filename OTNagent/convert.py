# convert from ofp -> ofcp
# or back from ofcp -> ofp

import libopenflow_old as of
import libopenflow as ofc
from scapy.all import *
import functools
import Queue
import setting 

#####################################of2ofc() uses for coverting the of packets to ofc's################################

def of2ofc(msg, buffer, dpid):
    print "of->ofc converting"
    if isinstance(msg, of.ofp_header):#it is a of packet.
        if isinstance(msg.payload, of.ofp_packet_in):
            # Save the buffer_id from pkt_in message. As 1. of.pkt_out message needs buffer_id
            # 2. the in_port is only one kind of pkt, this method seems okay in linear or ring topo
            
            #only need the ofp_header()/ofp_packet_in() part of the msg
            print "packet in from port", msg.payload.in_port
            buffer[msg.payload.in_port] = msg.payload.buffer_id
            
        if isinstance(msg.payload, of.ofp_flow_mod):
            #basic structure: of.ofp_header()/of.ofp_flow_wildcards()/of.ofp_match()/of.ofp_flow_mod()/other_ofp_actions()
            #select info from match (VLAN) and actions (just copy)
            pass
        if isinstance(msg.payload, of.ofp_features_reply):
            print"it is a ofp_features_reply packet"
            #basic structure:0fc.ofp_header()/ofc.ofp_cfeatures_reply()/ofc.ofp_phy_cport()/sup_wave_port_bandwidth()[n] 
            pkt_parsed = msg.payload                        #feature_reply
            port_info = msg.payload.payload
            
            port_raw=str(port_info)
            port_num = len(port_raw)/48  

            phy_port = {}
            phy_cport = {}
            MyPort = {}

            sw = setting.creat_sw(pkt_parsed.datapath_id)  

            cfeatures_reply = ofc.ofp_cfeatures_reply(datapath_id = pkt_parsed.datapath_id,
                                                  n_buffers = pkt_parsed.n_buffers,
                                                  n_tables = pkt_parsed.n_tables,
                                                  n_cports = port_num,
                                                  #features

                                                  OFPC_OTN_SWITCH = sw.type_otn,      #1<<31  if it is a otn switch
                                                  OFPC_WAVE_SWITCH = sw.type_wave,    #1<<30
                                                  OFPC_IP_SWITCH = sw.type_ip,      #1<<29

                                                  OFPC_ARP_MATCH_IP = pkt_parsed.OFPC_ARP_MATCH_IP,
                                                  OFPC_QUEUE_STATS = pkt_parsed.OFPC_QUEUE_STATS,   #1<<6 Queue statistics
                                                  OFPC_IP_STREAM = pkt_parsed.OFPC_IP_STREAM,       #1<<5 Can reassemble IP fragments
                                                  OFPC_RESERVED = pkt_parsed.OFPC_RESERVED,         #1<<4 Reserved, must be zero
                                                  OFPC_STP = pkt_parsed.OFPC_STP,                   #1<<3 802.1d spanning tree
                                                  OFPC_PORT_STATS =pkt_parsed.OFPC_PORT_STATS,      #1<<2 Port statistics
                                                  OFPC_TABLE_STATS = pkt_parsed.OFPC_TABLE_STATS,   #1<<1 Table statistics
                                                  OFPC_FLOW_STATS = pkt_parsed.OFPC_FLOW_STATS,     #1<<0 Flow statistics
                                                  actions = pkt_parsed.actions)
            for i in xrange(port_num):  
                phy_port[i] = of.ofp_phy_port(port_raw[i*48:i*48+48]) 

                MyPort[i] = setting.creat_port(pkt_parsed.datapath_id, phy_port[i].port_no)

                phy_cport[i] =  ofc.ofp_phy_cport(port_no = phy_port[i].port_no, 
                                                  hw_addr = phy_port[i].hw_addr,
                                                  port_name = phy_port[i].port_name,
                                                  #config 
                                                  not_defined = phy_port[i].not_defined,
                                                  OFPPC_NO_PACKET_IN = phy_port[i].OFPPC_NO_PACKET_IN,
                                                  OFPPC_NO_FWD = phy_port[i].OFPPC_NO_FWD,
                                                  OFPPC_NO_FLOOD = phy_port[i].OFPPC_NO_FLOOD,
                                                  OFPPC_NO_RECV_STP =phy_port[i].OFPPC_NO_RECV_STP,
                                                  OFPPC_NO_RECV = phy_port[i].OFPPC_NO_RECV,
                                                  OFPPC_NO_STP = phy_port[i].OFPPC_NO_STP,
                                                  OFPPC_PORT_DOWN =phy_port[i].OFPPC_PORT_DOWN,
                                                  #state 
                                                  
                                                  OFPPS_LINK_DOWN = 0,
                                                  
                                                  curr = 0,
                                                  advertised = 0,
                                                  supported = 0,
                                                  peer = 0,
                                                  #expend for circuit switch ports.
                                                  OFPST_FIBER = MyPort[i].OFPST_FIBER,   # 1<<15 can switch circuits based on SM/MM fiber
                                                  OFPST_WAVE = MyPort[i].OFPST_WAVE,     # 1<<14 can switch circuits based on ITU-T lambdas
                                                  OFPST_T_OTN = MyPort[i].OFPST_T_OTN,   # 1<<13 can switch circuits based on OTN standard
                                                  OFPST_T_SDH = MyPort[i].OFPST_T_SDH,  # 1<<12 can switch circuits based on SDH standard
                                                  OFPST_T_SONET = MyPort[i].OFPST_T_SONET,  # 1<<11 can switch circuits based on SONET standard
                                                  #NOT_DEFINED = 0,  # Not used
                                                  OFPST_ETH = MyPort[i].OFPST_ETH,  # 1<<4 can switch packets based on ETH headers
                                                  OFPST_VLAN = MyPort[i].OFPST_VLAN,  # 1<<3 can switch packets based on VLAN tags
                                                  OFPST_MPLS = MyPort[i].OFPST_MPLS,  # 1<<2 can switch packets based on MPLS labels
                                                  OFPST_IP = MyPort[i].OFPST_IP,  # 1<<1 can switch packets based on IP headers 
                                                  OFPST_L4 = MyPort[i].OFPST_L4,  # 1<<0 can switch packets based on TCP/UDP headers

                                                  SUPP_SW_GRAN = MyPort[i].SUPP_SW_GRAN,         #use for defined something ,waiting a second.
                                                  sup_sdh_port_bandwidth = MyPort[i].sup_sdh_port_bandwidth,
                                                  sup_otn_port_bandwidth = MyPort[i].sup_otn_port_bandwidth,
                                                  peer_port_no = MyPort[i].peer_port_no,
                                                  peer_datapath_id = MyPort[i].peer_datapath_id)\
                                /ofc.sup_wave_port_bandwidth(center_freq_lmda = MyPort[i].center_freq_lmda,
                                                             num_lmda = MyPort[i].num_lmda,
                                                             freq_space_lmda = MyPort[i].freq_space_lmda
                                                             )
                cfeatures_reply =cfeatures_reply/phy_cport[i]    
                
            cfeatures_reply = ofc.ofp_header(type = 24, length =port_num*74+32,)/cfeatures_reply
            return cfeatures_reply 

######################################ofc2of() uses for coverting the ofc packets to of's#########################################


def ofc2of(msg, buffer, dpid):
    print "ofc->ofconverting"
    if isinstance(msg, ofc.ofp_header):
        if isinstance(msg.payload, ofc.ofp_cflow_mod):
            #self.buffer[(pkt_in_msg.in_port, id)] = [pkt_in_msg.buffer_id, rmsg/pkt_in_msg/pkt_parsed]
            #basic structure: ofp_header()/ofp_cflow_mod()/ofp_connect_wildcards()/ofp_connect()/other_ofp_actions()
            #select info from connect (port info) and actions (just copy)
            #WDM: num_wave -> vlan id
            #OTN: supp_sw_otn_gran->different map function ; bitmap->calculate vlan id
            #ODU0 = 0, ODU1 = 1 ...
            
            # [port + id] --> [buffer_id + pkt_in_msg]
            if (msg.payload.payload.payload.in_port, msg.xid, dpid) not in buffer:
                #Do not change the match and wildcards.
                print "not in the buffer"
                flow_mod = of.ofp_flow_wildcards(OFPFW_NW_TOS=1,
                                                  OFPFW_DL_VLAN_PCP=1,
                                                  OFPFW_NW_DST_MASK=0,
                                                  OFPFW_NW_SRC_MASK=0,
                                                  OFPFW_TP_DST=1,
                                                  OFPFW_TP_SRC=1,
                                                  OFPFW_NW_PROTO=1,
                                                  OFPFW_DL_TYPE=1,
                                                  OFPFW_DL_VLAN=1,
                                                  OFPFW_IN_PORT=1,
                                                  OFPFW_DL_DST=1,
                                                  OFPFW_DL_SRC=1)\
                           /of.ofp_match(in_port=msg.payload.payload.payload.in_port)\
                           /of.ofp_flow_mod(cookie=0,
                                            command=0,
                                            idle_timeout=0,
                                            hard_timeout=0,
                                            out_port=msg.payload.payload.payload.payload.port,
                                            buffer_id=0xffff,
                                            flags=1)
                port = msg.payload.payload.payload.payload.port
                if msg.payload.payload.payload.nport_out:
                    odu = sup2odu[msg.payload.payload.payload.supp_sw_otn_gran_out]
                    vid =  ofc2of_dict_odu[odu](msg.payload.payload.payload.nport_out)
                    print "vid", vid
                    flow_mod_msg = of.ofp_header(type=14,length=104,xid=msg.xid)/flow_mod/of.ofp_action_header(type=0)/of.ofp_action_output(type=0, port=port, len=8)/of.ofp_action_header(type =1)/of.ofp_action_vlan_vid(vlan_vid = vid)
                    return flow_mod_msg 
                elif msg.payload.payload.payload.wport_out:
                    vid =  ofc2of_dict_wave(msg.payload.payload.payload.num_wave_out)
                    print "vid", vid
                    flow_mod_msg = of.ofp_header(type=14,length=104,xid=msg.xid)/flow_mod/of.ofp_action_header(type=0)/of.ofp_action_output(type=0, port=port, len=8)/of.ofp_action_header(type =1)/of.ofp_action_vlan_vid(vlan_vid = vid)
                    return flow_mod_msg 
                else:
                    flow_mod_msg = of.ofp_header(type=14,length=88,xid=msg.xid)/flow_mod/of.ofp_action_header(type=0)/of.ofp_action_output(type=0, port=port, len=8)
                    return flow_mod_msg 
###############################################use the packet_in to send the flow##############################################
            else:
                buffer_id, pkt = buffer[(msg.payload.payload.payload.in_port, msg.xid, dpid)]
                del buffer[(msg.payload.payload.payload.in_port, msg.xid, dpid)]
                pkt_parsed = pkt.payload.payload

#####################################################pkt_parsed is a Ethernet packet############################################
            
                if isinstance(pkt_parsed.payload, of.IP) or isinstance(pkt_parsed.payload.payload, of.IP):
########################################################TCP OR UDP OR SCTP(L4)##################################################
                    if isinstance(pkt_parsed.payload.payload, of.TCP) or isinstance(pkt_parsed.payload.payload, of.UDP) or isinstance(pkt_parsed.payload.payload, of.SCTP) :
                        print "it is TCP or UDP or SCTP packet"
                        if  pkt_parsed.type ==0x8100:
                            print "pkt_parsed.payload.vlan",pkt_parsed.payload.vlan
                            flow_mod =of.ofp_flow_wildcards(OFPFW_NW_TOS=1,
                                                              OFPFW_DL_VLAN_PCP=1,
                                                              OFPFW_NW_DST_MASK=0,
                                                              OFPFW_NW_SRC_MASK=0,
                                                              OFPFW_TP_DST=1,
                                                              OFPFW_TP_SRC=1,
                                                              OFPFW_NW_PROTO=1,
                                                              OFPFW_DL_TYPE=1,
                                                              OFPFW_DL_VLAN=1,
                                                              OFPFW_IN_PORT=1,
                                                              OFPFW_DL_DST=1,
                                                              OFPFW_DL_SRC=1)\
                                       /of.ofp_match(in_port=msg.payload.payload.payload.in_port,
                                                     dl_src=pkt_parsed.src,
                                                     dl_dst=pkt_parsed.dst,
                                                     dl_type=pkt_parsed.type,
                                                     dl_vlan=pkt_parsed.payload.vlan,
                                                     nw_tos=pkt_parsed.payload.tos,
                                                     nw_proto=pkt_parsed.payload.proto,
                                                     nw_src=pkt_parsed.payload.src,
                                                     nw_dst=pkt_parsed.payload.dst,
                                                     tp_src = pkt_parsed.payload.payload.sport,
                                                     tp_dst = pkt_parsed.payload.payload.dport)\
                                       /of.ofp_flow_mod(cookie=0,
                                                        command=0,
                                                        idle_timeout=10,
                                                        hard_timeout=30,
                                                        out_port=msg.payload.payload.payload.payload.port,
                                                        buffer_id=buffer_id,
                                                        flags=1)
                            port = msg.payload.payload.payload.payload.port
                            if msg.payload.payload.payload.nport_out:
                                odu = sup2odu[msg.payload.payload.payload.supp_sw_otn_gran_out]
                                vid =  ofc2of_dict_odu[odu](msg.payload.payload.payload.nport_out)
                                print "vid", vid
                                flow_mod_msg = of.ofp_header(type=14,length=104,xid=pkt.xid)/flow_mod/of.ofp_action_header(type=0)/of.ofp_action_output(type=0, port=port, len=8)/of.ofp_action_header(type =1)/of.ofp_action_vlan_vid(vlan_vid = vid)
                                return flow_mod_msg
                            elif msg.payload.payload.payload.wport_out:
                                vid =  ofc2of_dict_wave(msg.payload.payload.payload.num_wave_out)
                                print "vid", vid
                                flow_mod_msg = of.ofp_header(type=14,length=104,xid=pkt.xid)/flow_mod/of.ofp_action_header(type=0)/of.ofp_action_output(type=0, port=port, len=8)/of.ofp_action_header(type =1)/of.ofp_action_vlan_vid(vlan_vid = vid)
                                return flow_mod_msg
                            else:
                                flow_mod_msg = of.ofp_header(type=14,length=88,xid=pkt.xid)/flow_mod/of.ofp_action_header(type=0)/of.ofp_action_output(type=0, port=port, len=8)
                                return flow_mod_msg
                        else:                                           
                            flow_mod = of.ofp_flow_wildcards(OFPFW_NW_TOS=1,
                                                              OFPFW_DL_VLAN_PCP=1,
                                                              OFPFW_NW_DST_MASK=0,
                                                              OFPFW_NW_SRC_MASK=0,
                                                              OFPFW_TP_DST=1,
                                                              OFPFW_TP_SRC=1,
                                                              OFPFW_NW_PROTO=1,
                                                              OFPFW_DL_TYPE=1,
                                                              OFPFW_DL_VLAN=1,
                                                              OFPFW_IN_PORT=1,
                                                              OFPFW_DL_DST=1,
                                                              OFPFW_DL_SRC=1)\
                                       /of.ofp_match(in_port=msg.payload.payload.payload.in_port,
                                                     dl_src=pkt_parsed.src,
                                                     dl_dst=pkt_parsed.dst,
                                                     dl_type=pkt_parsed.type,
                                                     nw_tos=pkt_parsed.payload.tos,
                                                     nw_proto=pkt_parsed.payload.proto,
                                                     nw_src=pkt_parsed.payload.src,
                                                     nw_dst=pkt_parsed.payload.dst,
                                                     tp_src = pkt_parsed.payload.payload.sport,
                                                     tp_dst = pkt_parsed.payload.payload.dport)\
                                       /of.ofp_flow_mod(cookie=0,
                                                        command=0,
                                                        idle_timeout=10,
                                                        hard_timeout=30,
                                                        out_port=msg.payload.payload.payload.payload.port,
                                                        buffer_id=buffer_id,
                                                        flags=1)
                            port = msg.payload.payload.payload.payload.port
                            if msg.payload.payload.payload.nport_out:
                                odu = sup2odu[msg.payload.payload.payload.supp_sw_otn_gran_out]
                                vid =  ofc2of_dict_odu[odu](msg.payload.payload.payload.nport_out)
                                print "vid", vid
                                flow_mod_msg = of.ofp_header(type=14,length=104,xid=pkt.xid)/flow_mod/of.ofp_action_header(type=0)/of.ofp_action_output(type=0, port=port, len=8)/of.ofp_action_header(type =1)/of.ofp_action_vlan_vid(vlan_vid = vid)
                                return flow_mod_msg                                
                            elif msg.payload.payload.payload.wport_out:
                                vid =  ofc2of_dict_wave(msg.payload.payload.payload.num_wave_out)
                                print "vid", vid
                                flow_mod_msg = of.ofp_header(type=14,length=104,xid=pkt.xid)/flow_mod/of.ofp_action_header(type=0)/of.ofp_action_output(type=0, port=port, len=8)/of.ofp_action_header(type =1)/of.ofp_action_vlan_vid(vlan_vid = vid)
                                return flow_mod_msg
                            else:
                                flow_mod_msg = of.ofp_header(type=14,length=88,xid=pkt.xid)/flow_mod/of.ofp_action_header(type=0)/of.ofp_action_output(type=0, port=port, len=8)
                                return flow_mod_msg
#######################################################IP(L3)##########################################################################
                    else:
                        if  pkt_parsed.type ==0x8100:
                            print "it is just a IP packet "
                            print "pkt_parsed.payload.vlan",pkt_parsed.payload.vlan
                            flow_mod = of.ofp_flow_wildcards(OFPFW_NW_TOS=1,
                                                              OFPFW_DL_VLAN_PCP=1,
                                                              OFPFW_NW_DST_MASK=0,
                                                              OFPFW_NW_SRC_MASK=0,
                                                              OFPFW_TP_DST=1,
                                                              OFPFW_TP_SRC=1,
                                                              OFPFW_NW_PROTO=1,
                                                              OFPFW_DL_TYPE=1,
                                                              OFPFW_DL_VLAN=1,
                                                              OFPFW_IN_PORT=1,
                                                              OFPFW_DL_DST=1,
                                                              OFPFW_DL_SRC=1)\
                                       /of.ofp_match(in_port=msg.payload.payload.payload.in_port,
                                                     dl_src=pkt_parsed.src,
                                                     dl_dst=pkt_parsed.dst,
                                                     dl_type=pkt_parsed.type,
                                                     dl_vlan=pkt_parsed.payload.vlan,
                                                     nw_tos=pkt_parsed.payload.tos,
                                                     nw_proto=pkt_parsed.payload.proto,
                                                     nw_src=pkt_parsed.payload.src,
                                                     nw_dst=pkt_parsed.payload.dst,
                                                     tp_src = 0,
                                                     tp_dst = 0)\
                                       /of.ofp_flow_mod(cookie=0,
                                                        command=0,
                                                        idle_timeout=10,
                                                        hard_timeout=30,
                                                        out_port=msg.payload.payload.payload.payload.port,
                                                        buffer_id=buffer_id,
                                                        flags=1)
                            port = msg.payload.payload.payload.payload.port
                            if msg.payload.payload.payload.nport_out:
                                odu = sup2odu[msg.payload.payload.payload.supp_sw_otn_gran_out]
                                vid =  ofc2of_dict_odu[odu](msg.payload.payload.payload.nport_out)
                                print "vid", vid
                                flow_mod_msg = of.ofp_header(type=14,length=104,xid=pkt.xid)/flow_mod/of.ofp_action_header(type=0)/of.ofp_action_output(type=0, port=port, len=8)/of.ofp_action_header(type =1)/of.ofp_action_vlan_vid(vlan_vid = vid)
                                return flow_mod_msg
                            elif msg.payload.payload.payload.wport_out:
                                vid =  ofc2of_dict_wave(msg.payload.payload.payload.num_wave_out)
                                print "vid", vid
                                flow_mod_msg = of.ofp_header(type=14,length=104,xid=pkt.xid)/flow_mod/of.ofp_action_header(type=0)/of.ofp_action_output(type=0, port=port, len=8)/of.ofp_action_header(type =1)/of.ofp_action_vlan_vid(vlan_vid = vid)
                                return flow_mod_msg
                            else:
                                flow_mod_msg = of.ofp_header(type=14,length=88,xid=pkt.xid)/flow_mod/of.ofp_action_header(type=0)/of.ofp_action_output(type=0, port=port, len=8)
                                return flow_mod_msg
                        else:                                           
                            flow_mod = of.ofp_flow_wildcards(OFPFW_NW_TOS=1,
                                                              OFPFW_DL_VLAN_PCP=1,
                                                              OFPFW_NW_DST_MASK=0,
                                                              OFPFW_NW_SRC_MASK=0,
                                                              OFPFW_TP_DST=1,
                                                              OFPFW_TP_SRC=1,
                                                              OFPFW_NW_PROTO=1,
                                                              OFPFW_DL_TYPE=1,
                                                              OFPFW_DL_VLAN=1,
                                                              OFPFW_IN_PORT=0,
                                                              OFPFW_DL_DST=1,
                                                              OFPFW_DL_SRC=1)\
                                       /of.ofp_match(in_port=msg.payload.payload.payload.in_port,
                                                     dl_src=pkt_parsed.src,
                                                     dl_dst=pkt_parsed.dst,
                                                     dl_type=pkt_parsed.type,
                                                     nw_tos=pkt_parsed.payload.tos,
                                                     nw_proto=pkt_parsed.payload.proto,
                                                     nw_src=pkt_parsed.payload.src,
                                                     nw_dst=pkt_parsed.payload.dst,
                                                     tp_src = 0,
                                                     tp_dst = 0)\
                                       /of.ofp_flow_mod(cookie=0,
                                                        command=0,
                                                        idle_timeout=10,
                                                        hard_timeout=30,
                                                        out_port=msg.payload.payload.payload.payload.port,
                                                        buffer_id=buffer_id,
                                                        flags=1)
                            port = msg.payload.payload.payload.payload.port
                            if msg.payload.payload.payload.nport_out:
                                odu = sup2odu[msg.payload.payload.payload.supp_sw_otn_gran_out]
                                vid =  ofc2of_dict_odu[odu](msg.payload.payload.payload.nport_out)
                                print "vid", vid
                                flow_mod_msg = of.ofp_header(type=14,length=104,xid=pkt.xid)/flow_mod/of.ofp_action_header(type=0)/of.ofp_action_output(type=0, port=port, len=8)/of.ofp_action_header(type =1)/of.ofp_action_vlan_vid(vlan_vid = vid)
                                return flow_mod_msg
                            elif msg.payload.payload.payload.wport_out:
                                vid =  ofc2of_dict_wave(msg.payload.payload.payload.num_wave_out)
                                print "vid", vid
                                flow_mod_msg = of.ofp_header(type=14,length=104,xid=pkt.xid)/flow_mod/of.ofp_action_header(type=0)/of.ofp_action_output(type=0, port=port, len=8)/of.ofp_action_header(type =1)/of.ofp_action_vlan_vid(vlan_vid = vid)
                                return flow_mod_msg
                            else:
                                flow_mod_msg = of.ofp_header(type=14,length=88,xid=pkt.xid)/flow_mod/of.ofp_action_header(type=0)/of.ofp_action_output(type=0, port=port, len=8)
                                return flow_mod_msg
    
##################################################### The rule of converting######################################################

buffer_id = {}

sup2odu = { 0:0
            1:0,  #"ODU0"   #use for convert by port info
            2:1,  #"ODU1"
            4:2,  #"ODU2"
            16:3  #"ODU3"
}
of2ofc_dict = {
               }

ofc2of_dict_odu = { 0: lambda x:x+2000,
                    1: lambda x:x+2100,
                    2: lambda x:x+2200,
                    3: lambda x:x+2300}

ofc2of_dict_wave = lambda x:x+3000


##################################The code below is just for test,and you have no need to read it.#################################


if __name__ == "__main__":
    # this convert (can) only match in-coming port and vlan
    
    # 1. packet_in message
    pkt_in_msg = ofc.ofp_header(type=6,length=104)/ofc.ofp_cfeatures_reply(datapath_id=1)/ofc.ofp_phy_cport()/ofc.sup_wave_port_bandwidth()
    #pkt_in_msg.show()
    ofc_pkt = of2ofc(pkt_in_msg, pkt_in_msg.datapath_id, 10) # get buffer_id
    print ofc_pkt
    """
    ofc_pkt = ofc.ofp_header()\
          /ofc.ofp_cflow_mod()\
          /ofc.ofp_connect_wildcards()\
          /ofc.ofp_connect(nport_in=1, supp_sw_otn_gran_in=1, in_port=1)\
          /of.ofp_action_header(type=3)\
          /of.ofp_action_output(type=0, port=0xfffb, len=8)
    #ofc_pkt.show()
    """
    print buffer_id

    # 2. parse ofc message
   # of_pkt = ofc2of(ofc_pkt, buffer_id, dpid) 
    
    # 3. print of message
   # of_pkt.show()
    
    """
    print ofc2of_dict_odu[0](1)
    print ofc2of_dict_odu[0](30)
    print ofc2of_dict_odu[1](1)
    print ofc2of_dict_odu[2](1)
    print ofc2of_dict_odu[3](1)
    
    print ofc2of_dict_wave(80)
    """