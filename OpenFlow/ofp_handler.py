import libopenflow as of
from scapy.all import *
from OTNagent import MySetting 
import sys
sys.path.append('.')
from coreapps import l2_learning

"""
TODO:Define the OpenFlow packets handler functions
Author:Licheng
Time:2014/5/5

"""



sock_dpid = {}
fd_map = {}
features_info = {} 

########################################################################################

def hello_handler(data,*arg):
	rmsg = of.ofp_header(data)
	if rmsg.version == 1:
		#print ">>>OFPT_HELLO"
		return of.ofp_header(data)
	else:
		#print ">>>HELLO_ERROR"
		return None
	
def error_handler(data, *arg):
	body = data[8:]
	#print ">>>OFPT_ERROR"
	of.ofp_error_msg(body).show()
	return None

def echo_request_handler(data,*arg):
	#print ">>>OFPT_ECHO_REQUEST"
	rmsg = of.ofp_header(data)
	msg = of.ofp_header(type = 3,xid=rmsg.xid)
	#msg.show()
	return msg

def echo_reply_handler(data,*arg):
	#print ">>>OFPT_ECHO_REPLY"
	return None

def vendor_handler(data,*arg):
	#print ">>>OFPT_VENDOR"
	return None

def features_request_handler(data,*arg):
	rmsg = of.ofp_header(data)
	#print ">>>OFPT_FEATURES_REQUEST"
	return of.ofp_header(type =5,xid =1)#xid =0

def features_reply_handler(data,fd):
	#print ">>>OFPT_FEATURES_REPLY"
	body = data[8:]
	msg = of.ofp_features_reply(body[0:24])                     #length of reply msg
	sock_dpid[fd]=msg.datapath_id 
	"""
	port_info_raw = str(body[24:])                              #we change it into str so we can manipulate it.
	port_info = {}

	#print ">>>port number:",len(port_info_raw)/48, "total length:", len(port_info_raw)
	for i in range(len(port_info_raw)/48):
	    port= of.ofp_phy_port(port_info_raw[0+i*48:48+i*48])
	    #port.show()
	    #print port.port_no
	    port_info[port.port_no]= port                           #save port_info by port_no

	                         #sock_dpid[fd] comes from here.
	features_info[msg.datapath_id] =(msg, port_info)            #features_info[dpid] = (sw_features, port_info{})
	"""
	return None

def packet_in_handler(data,fd):
	rmsg =of.ofp_header(data[0:8])
	body = data[8:]
	pkt_in_msg = of.ofp_packet_in(body)
	pkt_parsed = of.Ether(pkt_in_msg.load)
	pkt = rmsg/pkt_in_msg/pkt_parsed
	dpid = sock_dpid[fd]     #if there is not the key of sock_dpid[fd] ,it will be an error.

	return l2_learning.switch(pkt,dpid)

def barrier_handler(data,*arg):
	#print ">>>OFPT_BARRIER_REQUEST"
	rmsg =of.ofp_header(data[0:8])
	body = data[8:]
	msg = of.ofp_header(type = 18,xid = rmsg.xid) 
	return msg

def flow_removed_handler(data,*arg):
	#print ">>>OFPT_FLOW_REMOVED"
	return None

def port_status_handler(data,*arg):
	#print ">>>OFPT_PORT_STATUS"
	return None
def packet_out_handler(data,*arg):
	#print ">>>OFPT_PACKET_OUT"
	return None

def flow_mod_handler(data, *arg):
	#print ">>>OFPT_FLOW_MOD"
	#we can do some thing here.
	return None

def port_mod_handler(data ,*arg):
	#print ">>>OFPT_PORT_MOD"
	return None

def stats_request_handler(data, *arg):
	#print ">>>OFPT_STATS_REQUEST"
	return None

def stats_reply_handler(data,*arg):
	#print ">>>OFPT_STATS_REPLY:%d",len(data)
	rmsg = of.ofp_header(data[0:8])
	body = data[8:]
	# 1. parsing ofp_stats_reply
	reply_header = of.ofp_stats_reply(body[:4])
	#reply_header.show()
	# 2.parsing ofp_flow_stats msg
	if reply_header.type == 0:
		reply_desc = of.ofp_desc_stats(body[4:])
		reply.show()

	elif reply_header.type == 1 and len(data)>92:
		reply_body_data1 = of.ofp_flow_stats(body[4:8])
		reply_body_data1.show()
		# match field in ofp_flow_stats
		reply_body_wildcards = of.ofp_flow_wildcards(body[8:12])
		reply_body_match = of.ofp_match(body[12:48])
		# second part in ofp_flow_stats
		reply_body_data2 = of.ofp_flow_stats_data(body[48:92])
		# 3.parsing actions
		reply_body_action = []
		if len(body[92:])>8:                         #it is very important!
			num = len(body[92:])/8
			for x in xrange(num):
				reply_body_action.append(of.ofp_action_output(body[92+x*8:100+x*8]))
				msg = reply_header/reply_body_data1/reply_body_wildcards/reply_body_match/reply_body_data2
				msg.show()

	elif reply_header.type == 2:
		reply_aggregate = of.ofp_aggregate_stats_reply(body[4:])
		reply_aggregate.show()

	elif reply_header.type == 3:
		#table_stats
		length = rmsg.length - 12
		num = length/64
		for i in xrange(num):
			table_body = body[4+i*64:i*64+68]
			reply_table_stats = of.ofp_table_stats(table_body[:36])
			table_wildcards = of.ofp_flow_wildcards(table_body[36:40])
			reply_table_stats_data = of.ofp_table_stats_data(table_body[40:64])
			msg_tmp = reply_header/reply_table_stats/table_wildcards/reply_table_stats_data
			msg = rmsg/msg_tmp
			msg.show() 
	elif reply_header.type == 4:
		#port stats reply
		length = rmsg.length - 12
		num = length/104
		for i in xrange(num):
			offset = 4+i*104
			reply_port_stats = of.ofp_port_stats_reply(body[offset:(offset+104)])
			msg_tmp = reply_header/reply_port_stats
			msg = rmsg/msg_tmp
			msg.show()
	elif reply_header.type == 5:
		#queue reply
		length = rmsg.length - 12
		num = length/32
		if num:                     #if the queue is empty ,you need to check it !
			for i in xrange(num):
				offset = 4+i*32
				queue_reply = of.ofp_queue_stats(body[offset:offset+32])
				msg_tmp = reply_header/queue_reply
				msg = rmsg/msg_tmp
				msg.show()
	elif reply_header.type == 0xffff:
		#vendor reply
		msg = rmsg/reply_header/of.ofp_vendor(body[4:])
	return None

def barrier_request_handler(data,*arg):
	#print ">>>OFPT_BARRIER_REQUEST"
	#no message body, the xid is the previous barrier request xid
	return None

def barrier_reply_handler(data, *arg):
	#print ">>>OFPT_BARRIER_REPLY: ", rmsg.xid, "Successful"
	return None

def get_config_request_handler(data, *arg):
	#print ">>>OFPT_QUEUE_GET_CONFIG_REQUEST"
	#not finished yet.
	return None

def get_config_reply_handler(data,*arg):
	#print ">>>OFPT_QUEUE_GET_CONFIG_REPLY"
	#not finished yet
	return None

def cfeatrues_reply_handler(data, fd, *arg):
	#print ">>>OFPT_CFEATURES_REPLY"
	body = data[8:]
	msg = of.ofp_cfeatures_reply(body[0:24])
	#bind the dpid and type  (type,  dpid)

	Type = msg.OFPC_OTN_SWITCH*4 +msg.OFPC_WAVE_SWITCH*2 + msg.OFPC_IP_SWITCH

	sock_dpid[fd]=[Type, msg.datapath_id]

	port_info_raw = body[24:]            
	port_info = {}
	#print ">>>port number:",len(port_info_raw)/72, "total length:", len(port_info_raw)
	for i in range(len(port_info_raw)/72):
		port_info[i] = of.ofp_phy_cport(port_info_raw[i*72:72+i*72])
		#print ">>>port_no:",port_info[i].port_no,"i:",i

	return None

def send_stats_request_handler(Type, flow=None, port =None):
	if flow == None:
		flow = of.ofp_header()/of.ofp_flow_wildcards()/of.ofp_match()/of.ofp_flow_mod()
	flow =str(flow)
	ofp_flow_wildcards=of.ofp_flow_wildcards(flow[8:12])
	ofp_match =of.ofp_match(flow[12:48])
	ofp_flow_mod =of.ofp_flow_mod(flow[48:72])
	if len(flow)>=88:
		action_header = of.ofp_action_header(flow[72:80])
		action_output = of.ofp_action_output(flow[80:88])
	#we need to send the stats request packets periodically
	msg = { 0: of.ofp_header(type = 16, length = 12)/of.ofp_stats_request(type = 0),                            #Type of  OFPST_DESC (0) 
			1: of.ofp_header(type = 16, length = 56)/of.ofp_stats_request(type =1)/ofp_flow_wildcards/ofp_match/of.ofp_flow_stats_request(out_port = ofp_flow_mod.out_port),                  #flow stats
			2: of.ofp_header(type = 16, length =56)/of.ofp_stats_request(type = 2)/ofp_flow_wildcards/ofp_match/of.ofp_aggregate_stats_request(),                                  # aggregate stats request
			3: of.ofp_header(type = 16, length = 12)/of.ofp_stats_request(type = 3),                            #Type of  OFPST_TABLE (0) 
			4: of.ofp_header(type = 16, length =20)/of.ofp_stats_request(type = 4)/of.ofp_port_stats_request(port_no = port),   # port stats request    
			5: of.ofp_header(type = 16, length =20)/of.ofp_stats_request(type =5)/of.ofp_queue_stats_request(), #queue request
			6: of.ofp_header(type = 16, length = 12)/of.ofp_stats_request(type = 0xffff)                        #vendor request
			}
	#print ">>>OFPT_STATS_REQUEST"
	return msg[Type]




