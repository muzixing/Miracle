from OpenFlow import libopenflow as of
from threading import Timer
import copy
from database import timer_list as timer_list

"""
TODO:ARP agent to reply ARP REQUEST
Author:Licheng
Time:2014/5/8

"""

idle_time = 600  #Refreshing ARP entry every 600 seconds.
ARP_TABLE = {}#Using for record the ARP

#______________________________________

def __init__():
	pass

def arp_delete(psrc):
	#print ">>>Delete the ARP record"
	del ARP_TABLE[psrc]

def arp_add(psrc,*hwsrc):
	#print ">>>Add the ARP record"
	ARP_TABLE[psrc] = hwsrc
	#arp_timer =Timer(idle_time,arp_delete,psrc)
	#arp_timer.start()
	#timer_list.timer_list.append(arp_timer) 

def arp_reply_handler(pkt):
	pkt_in_msg =pkt.payload
	pkt_parsed =pkt_in_msg.payload
	
	if pkt_parsed.payload.psrc not in ARP_TABLE:
		arp_add(pkt_parsed.payload.psrc,pkt_parsed.payload.hwsrc) 		#add arp record
	if pkt_parsed.payload.pdst in ARP_TABLE:
		ETHER = copy.deepcopy(pkt_parsed)
		ETHER.dst = pkt_parsed.payload.hwsrc
		ETHER.src = pkt_parsed.payload.hwdst
		ETHER.payload.op = 2#reply
		ETHER.payload.hwdst = pkt_parsed.payload.hwsrc
		ETHER.payload.hwsrc = ARP_TABLE[pkt_parsed.payload.pdst]
		ETHER.payload.psrc = pkt_parsed.payload.pdst
		ETHER.payload.pdst = pkt_parsed.payload.psrc

		pkt_out = of.ofp_header()/of.ofp_pktout_header()/of.ofp_action_output()/ETHER
		pkt_out.payload.payload.port = pkt_in_msg.in_port
		pkt_out.payload.buffer_id = pkt_in_msg.buffer_id
		pkt_out.payload.in_port = pkt_in_msg.in_port
		pkt_out.payload.actions_len = 8
		pkt_out.length = len(pkt_out)
		return pkt_out
	else:
		return None

