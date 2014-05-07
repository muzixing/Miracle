from OpenFlow import libopenflow as of

"""
TODO:switch the packets by mactoport table.
Author:Licheng
Time:2014/5/7

"""

mactoport = {}

def __init__():
	pass

def switch(pkt,*args):
	#pkt.show()
	rmsg = pkt

	pkt_in_msg = pkt.payload
	pkt_parsed = pkt.payload.payload
	
	mactoport[pkt_parsed.src] = pkt_in_msg.in_port

	if pkt_parsed.dst == "ff:ff:ff:ff:ff:ff":	
		#pkt_parsed.show()	
		pkt_out = of.ofp_header()/of.ofp_pktout_header()/of.ofp_action_output()
		pkt_out.payload.payload.port = 0xfffb
		pkt_out.payload.buffer_id = pkt_in_msg.buffer_id
		pkt_out.payload.in_port = pkt_in_msg.in_port
		pkt_out.payload.actions_len = 8
		pkt_out.length = 24
		#pkt_out.show()
		print "MULTICAST"
		return pkt_out
	else:
		print "create_flow"
		return create_flow(pkt)

def create_flow(pkt):
	wildcards = of.ofp_flow_wildcards(	OFPFW_NW_TOS=1,
										OFPFW_DL_VLAN_PCP=1,
										OFPFW_NW_DST_MASK=63,
										OFPFW_NW_SRC_MASK=63,
										OFPFW_TP_DST=1,
										OFPFW_TP_SRC=1,
										OFPFW_NW_PROTO=1,
										OFPFW_DL_TYPE=1,
										OFPFW_DL_VLAN=1,
										OFPFW_IN_PORT=0,
										OFPFW_DL_DST=1,
										OFPFW_DL_SRC=1)
	match = of.packet2match(pkt)
	#print type(match)
	rmsg = pkt#of.ofp_header(data[0:8])
	pkt_in_msg = pkt.payload#of.ofp_packet_in(data[8:])
	pkt_parsed = pkt_in_msg.payload#of.Ether(pkt_in_msg.load)
	if pkt_parsed.dst in mactoport:
		out_port = mactoport[pkt_parsed.dst]
	else:
		out_port = 0xfffb
	flow_mod = of.ofp_flow_mod(	cookie=0,
								command=0,
								idle_timeout=10,
								hard_timeout=30,
								out_port=out_port,
								buffer_id=pkt_in_msg.buffer_id,
								flags=1)
	action = of.ofp_action_header(type=0,len=8)/of.ofp_action_output(type=0, port=out_port)
	ofp_header = of.ofp_header(type = 14,length = 88,xid = rmsg.xid)
	flow_mod = ofp_header/wildcards/match/flow_mod/action
	return flow_mod