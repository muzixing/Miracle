from OpenFlow import libopenflow as of
from threading import Timer

"""
TODO:Database for flow entry
Author:Licheng
Time:2014/5/9

"""
flow_table_cache = {}  #use for store flow_mod
dpidtoflow = []

def __init__():
	pass



def flow_delete(*dpid):
	print ">>>Delete the flow entry"
	del flow_table_cache[dpid]

def flow_add(flow,*dpid):

	if dpid not in flow_table_cache:
		print ">>>Add the flow entry" ,dpid
		dpidtoflow.append(flow)
		flow_table_cache[dpid] =dpidtoflow
		print flow_table_cache
		flow_timer =Timer(flow.payload.payload.payload.hard_timeout,flow_delete,dpid)
		flow_timer.start() 