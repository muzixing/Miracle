
from pox.core import core
import pox.openflow.libopenflow_01 as off
from pox.lib.revent import *
from pox.lib.recoco import *
import threading
import thread
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.ipv4 import ipv4

import struct
log = core.getLogger()

import libopenflow as oof  
import errno
import functools
import tornado.ioloop as ioloop
import socket
import libopencflow as of
import stats_request as stats
import MySetting 
import Queue
import time
message_queue_map = {}
period = MySetting.period


import tables
import route
import discovery as dc
create_topo = dc.Discovery()#create an instance to complete the topo-discovery

global ip_type
ip_type = {}#switch type between two ip
global stype
stype = '0'#default switch type, for all flows
global ip_stats
ip_stats = {}#save the stats info from switches for load balancing
global switch_load
switch_load = tables.switch_load#max load for link switching
global time_list
time_list = []#record the time when last stats_request was sent

# dpid->type    
switch_info = {0:"ip", 1:"ip", 2:"wave", 3:"wave+ip",   4:"otn", 5:"otn+ip", 6:"otn+wave", 7: "wave+otn+ip"} # 1 otn; 2 otn->wave; 3 wave

class Input (EventMixin,threading.Thread):
   """
   This component is to deal with your input, while another process is handling
   whatever sent by trans_agent(obtain information from switches)
   """

   def __init__(self):
     threading.Thread.__init__(self)
     print("here?")
     #Task.__init__(self)
     # Note! We can't start our event loop until the core is up. Therefore, 
     # we'll add an event handler.
     self.listenTo(core)

   def _handle_GoingUpEvent (self, event):
     """
     Takes a second parameter: the GoingUpEvent object (which we ignore)
     """ 
     # This causes us to be added to the scheduler's recurring Task queue
     self.start() 

   def run(self):
     while core.running:
       """
       This looks almost exactly like python's select.select, except that it's
       it's handled cooperatively by recoco.

       In this field, you could design your own CLI.
       """
       
       string = raw_input("\n------------------------------\n1.info(ports)\n2.switch\n3.topo\n4.flow(flow type,dpid, type=0 flow, type=1 cflow)\n5.add link-type(add ip1,ip2,type(IP=1, OTN=2))\n6.stype(BOTH=0, IP=1, OTN=2, for all)\n7.create link(create ip1,ip2)\n8.delete(del ip1,ip2)\n?")
       string = string.split(' ')
       if string[0] == 'info':
         action = 1
         print tables.info_map
         print "\n\n\n"
       elif string[0] == 'switch':
         action = 2
         print tables.switch_map
         print "\n\n\n"
       elif string[0] == 'topo':
         action = 3
         print tables.topo_map
         print "\n\n\n"
       elif string[0] == 'flow':
         action = 4
         string = string[1].split(',')
         flow_type = string[0]
         dpid = int(string[1])
         if flow_type == '0':
           print "flows in dpid:", dpid, "\n"
           if dpid in tables.flow_map.iterkeys():
             for flow in tables.flow_map[dpid]:
               flow.show()
         elif flow_type == '1':
           print "cflows in dpid:", dpid, "\n"
           if dpid in tables.cflow_map.iterkeys():
             for link, cflow in tables.cflow_map[dpid]:
               cflow.show()
         else:
           print "wrong type!\n"
         print "\n\n\n"
       elif string[0] == 'add':
         action = 5
         global ip_type
         string = string[1].split(',')
         ip1 = string[0]
         ip2 = string[1]
         ip_type[(ip1,ip2)] = string[2]
         ip_type[(ip2,ip1)] = string[2]
       elif string[0] == 'stype':
         action = 6
         global stype
         stype = string[1]
       
       elif string[0] == 'create':#could not be completed with buffer_id
         action = 7
         string = string[1].split(',')
         src = string[0]
         dst = string[1]
         
         road, link, route_type = route.add_link(src,dst,'1')
         for dpid in road:
           if dpid in link.iterkeys():
             src_port, dst_port = link[dpid][0], link[dpid][1]
             header = of.ofp_header(type = 14, length = 88, xid = dpid)
             wildcards = of.ofp_flow_wildcards(OFPFW_NW_TOS = 1, OFPFW_DL_VLAN_PCP = 1,
                         OFPFW_NW_DST_MASK = 0, OFPFW_NW_SRC_MASK = 0,
                         OFPFW_TP_DST = 1,      OFPFW_TP_SRC = 1,
                         OFPFW_NW_PROTO = 1,    OFPFW_DL_TYPE = 1,
                         OFPFW_DL_DST = 1,      OFPFW_DL_SRC = 1,
                         OFPFW_DL_VLAN = 1,     OFPFW_IN_PORT = 0)
             match = of.ofp_match(in_port = src_port,
                         nw_src = src, nw_dst =dst)
             flow_mod = of.ofp_flow_mod(buffer_id = -1, idle_timeout = 0, hard_timeout = 0, flags = 1, out_port = dst_port)
             action_header = oof.ofp_action_header(type = 0)
             action_output = of.ofp_action_output(type = 0, port = dst_port, len = 8)
             msg = header/wildcards/match/flow_mod/action_header/action_output
             for fd,dp in tables.sock_dpid.items():
               if dpid == dp[1]:
                 sock = tables.fd_map[fd]
                 break
             sock.send(str(msg))
       elif string[0]  == 'del':
         action = 8
         #todo: delete the flows in swithes whenever you want
         string = string[1].split(',')
         src = string[0]
         dst = string[1]
         if (src,dst) not in ip_type.iterkeys():
           print "there is no flow for ", src, " and ", dst, "\n"
         else:
           remove_type = ip_type[src,dst]
	   if remove_type == '1':#for ip, flow in tables.flow_map
             for link, road in tables.road_map.items():
               if link == (src,dst):#find the link, from src to dst
                 for dpid in road:#delete the related flow in every switches
                   for fd,dp in tables.sock_dpid.items():
                     if dpid == dp[1]:#find dpid-sock
                       sock = tables.fd_map[fd]
                       break
                   if dpid in tables.flow_map.iterkeys():
                     for item in tables.flow_map[dpid]:
                       if item.payload.payload.nw_src == src and item.payload.payload.nw_dst == dst:
                         data = str(item)
                         header = of.ofp_header(data[0:8])
                         header.length = 72
                         wildcards = of.ofp_flow_wildcards(data[8:12])
                         match = of.ofp_match(data[12:48])
                         flow_mod = of.ofp_flow_mod(data[48:72])
                         flow_mod.command = 4
                         msg = header/wildcards/match/flow_mod
                         sock.send(str(msg))
                         break
                 break
                                  
           elif remove_type == '2':#for otn, cflow in tables.cflow_map
             pass
   
       elif string[0] == '0':
         print "stop input function...\n"
         return
       else:
         log.warning("Character string cannot be identified!")
         continue
       print action
       

#The followings are all about how can our controller deal with the information


def handle_connection(connection, address):
  print "1 connection,", connection, address

def client_handler(address, fd, events):
  global ip_type
  sock = tables.fd_map[fd]
  if events & io_loop.READ:
    data = sock.recv(16384)
    if data == '':
      print "connection dropped"
      #when switch is dropped, the outdated information should be deleted
      io_loop.remove_handler(fd)
      if fd in tables.fd_map.iterkeys() and fd in tables.sock_dpid.iterkeys():
        dpid = tables.sock_dpid[fd][1]
        tables.sock_dpid.pop(fd)
        tables.fd_map.pop(fd)
      
        for link in tables.topo_map.iterkeys():
          if tables.topo_map[link]['status'] != -1 and (link[0] == dpid or link[2] == dpid):
            tables.topo_map[link]['status'] = -1#the link will not be re-counted
            dc.topo_flag += 2#when topo_flag>0, controller will stop dealing with packet
        tables.switch_map.pop(dpid)
        if dpid in tables.info_map.iterkeys():
          tables.info_map.pop(dpid)
        if dpid in tables.flow_map.iterkeys():
          tables.flow_map.pop(dpid)
      
        create_topo._connection_down(dpid)#renew the topo in discovery.py
        create_topo._sender._connection_down(dpid)
        
    if len(data)<8:
      print "not a openflow message"
    else:
      if len(data)>8:
        rmsg = of.ofp_header(data[0:8])
        body = data[8:]
      else:
        rmsg = of.ofp_header(data)

      if rmsg.type == 0:
        print "OFPT_HELLO"
        msg = of.ofp_header(type = 5)#we send the features_request here.
        print "OFPT_FEATURES_REQUEST"
        io_loop.update_handler(fd, io_loop.WRITE)
        message_queue_map[sock].put(data)
        message_queue_map[sock].put(str(msg))

      elif rmsg.type == 1:
        print "OFPT_ERROR"
        of.ofp_error_msg(body).show()

      elif rmsg.type == 2:
        #since the ECHO is too frequent, the print is canceled
        #print "OFPT_ECHO_REQUEST"
        msg = of.ofp_header(type=3, xid=rmsg.xid)
        message_queue_map[sock].put(str(msg))
        io_loop.update_handler(fd, io_loop.WRITE)

      elif rmsg.type == 3:
        print "OFPT_ECHO_REPLY"

      elif rmsg.type == 4:
        print "OFPT_VENDOR"

      elif rmsg.type == 5:
        print "OFPT_FEATURES_REQUEST"

      elif rmsg.type == 6:
        print "OFPT_FEATURES_REPLY"
        msg = of.ofp_features_reply(body[0:24])                   #length of reply msg
        tables.sock_dpid[fd]=[0, msg.datapath_id]                             #sock_dpid[fd] comes from here.

        port_info_raw = str(body[24:])                            #we change it into str so we can manipulate it.
        port_info = {}
        print "port number:",len(port_info_raw)/48, "total length:", len(port_info_raw)
        for i in range(len(port_info_raw)/48):
          port_info[i] = of.ofp_phy_port(port_info_raw[0+i*48:48+i*48])
          print port_info[i].port_no     
                
      elif rmsg.type == 10:
        #print "OFPT_PACKET_IN"
        pkt_in_msg = of.ofp_packet_in(body)#buffer_id+in_port
        raw = pkt_in_msg.load
        pkt_ = ethernet(raw)#this method can be located in pox
        pkt_parsed = of.Ether(raw)
        dpid = tables.sock_dpid[fd][1]
        if pkt_.effective_ethertype == 0x88cc:#deal with the LLDP for topo
          create_topo._handle_openflow_PacketIn(pkt_in_msg, pkt_, dpid)
        if dc.topo_flag:#when the topo is not completed, do nothing
          pass
        else:      
          if pkt_.effective_ethertype == 0x0806:
            #the ARP table is maintained for hosts' MAC in tables.py
            print "\n\nARP\n\n"
            request = pkt_parsed.next         
            if request.opcode == arp.REQUEST:
              reply = arp()
              reply.hwtype = request.hwtype
              reply.prototype = request.prototype
              reply.hwlen = request.hwlen
              reply.protolen = request.protolen
              reply.opcode = arp.REPLY
              reply.hwdst = request.hwsrc
              reply.protodst = request.protosrc
              reply.protosrc = request.protodst
              reply.hwsrc = tables.get_mac(request.protodst.toStr())
              #reply.hwsrc = tables.ip_mac[request.protodst]
              e_dpid = tables.sock_dpid[fd][1]
              for p,v in tables.switch_map[e_dpid]['port'].items():
                if v.port_no == pkt_in_msg.in_port:
                  e_src = v.hw_addr
              e = ethernet(type = pkt_parsed.type, src = e_src, dst = pkt_parsed.src)
              e.set_payload(reply)               
              msg = off.ofp_packet_out()
              msg.data = e.pack()
              msg.actions.append(off.ofp_action_output(port = off.OFPP_IN_PORT))#port problem
              msg.in_port = pkt_in_msg.in_port
              msg = msg.pack()

              io_loop.update_handler(fd, io_loop.WRITE)
              message_queue_map[sock].put(str(msg))
          elif pkt_.effective_ethertype == 0x8100:
            #to detect VLAN packets
            print "VLAN:\n"
            packet = pkt_.next
            print packet.__dict__
          elif pkt_.effective_ethertype == 0x0800:
            #print "\n\nIP\n\n"
            #use the packet to produce flow_mod
            packet = pkt_.next
            if isinstance(packet, ipv4):
              src = packet.srcip.toStr()
              dst = packet.dstip.toStr()
              dpid = tables.sock_dpid[fd][1]
              #the routing type of the link(src,dst) is based on s_type
              if (src, dst) in ip_type.iterkeys():
                s_type = ip_type[(src,dst)]
			  elif stype != '0':
                s_type = stype
              else:
                s_type = '0'
              #src_mac = tables.switch_map[dpid]['port'][src_port].hw_addr
              #dst_mac = tables.switch_map[dpid]['port'][dst_port].hw_addr
              road, rlink, route_type = route.add_link(src, dst, s_type)
              #establish info for barrier
              if (src,dst) not in tables.road_map.iterkeys():
                tables.road_map[(src,dst)] = road
              if (src,dst) not in tables.barrier_map.iterkeys():
                tables.barrier_map[(src,dst)] = {}
              if dpid not in tables.barrier_map[(src,dst)].iterkeys():
                tables.barrier_map[(src,dst)][dpid] = rmsg.xid
              if route_type == 0:#ip link, send flow
                ip_type[(src,dst)] = '1'
                if dpid in rlink.iterkeys():
                  src_port, dst_port = rlink[dpid][0], rlink[dpid][1] 
                  print "flow from ", src, " to ", dst, "\n"
                  print "dpid:",dpid," inport:",src_port," outport:",dst_port, "\n"
                  print "-------------------------"
                  header = of.ofp_header(type=14, length = 88, xid=rmsg.xid)
                  wildcards = of.ofp_flow_wildcards(OFPFW_NW_TOS=1,      OFPFW_DL_VLAN_PCP=1,
                                              OFPFW_NW_DST_MASK=63, OFPFW_NW_SRC_MASK=63,
                                              OFPFW_TP_DST=1,      OFPFW_TP_SRC=1,
                                              OFPFW_NW_PROTO=1,    OFPFW_DL_TYPE=1,
                                              OFPFW_DL_DST=0,      OFPFW_DL_SRC=0,
                                              OFPFW_DL_VLAN=1,     OFPFW_IN_PORT=0)
                  match = of.ofp_match(in_port=pkt_in_msg.in_port,
                          dl_src = pkt_parsed.src, dl_dst = pkt_parsed.dst,
                          dl_type = pkt_parsed.type,
                          nw_tos = pkt_parsed.payload.tos, 
                          nw_proto = pkt_parsed.payload.proto,
                          nw_src=src,  nw_dst=dst)
                  flow_mod = of.ofp_flow_mod(buffer_id = pkt_in_msg.buffer_id, idle_timeout = 0, hard_timeout = 30, flags = 1, cookie = rmsg.xid, out_port = dst_port)
                  action_header = oof.ofp_action_header(type = 0)
                  action_output = of.ofp_action_output(type = 0, port = dst_port, len = 8)
                  msg = header/wildcards/match/flow_mod/action_header/action_output
                  #here is to renew the flow_map
                  if dpid not in tables.flow_map.iterkeys():
                    tables.flow_map[dpid] = []
                    tables.flow_map[dpid].append(msg)
                  else:
                    for flow in tables.flow_map[dpid]:
                      flow_match = of.ofp_match((str(flow))[12:48])
                      if match == flow_match:
                        tables.flow_map[dpid].remove(flow)
                        break
                    tables.flow_map[dpid].append(msg)
                message_queue_map[sock].put(str(msg))
                io_loop.update_handler(fd, io_loop.WRITE)

              elif route_type == 1:#otn or wavelenth
                ip_type[(src,dst)] = '2'
                if dpid in rlink.iterkeys():
                  src = packet.srcip.toStr()
                  dst = packet.dstip.toStr()
                  src_port, dst_port = rlink[dpid][0], rlink[dpid][1]
                  if (src,dst) not in tables.source_map.iterkeys():
                    tables.source_map[(src,dst)] = {}
                  if dpid not in tables.source_map[(src,dst)].iterkeys():
                    tables.source_map[(src,dst)][dpid] = {}
                  if src_port not in tables.source_map[(src,dst)][dpid].iterkeys():
                    tables.source_map[(src,dst)][dpid][src_port] = []
                  if dst_port not in tables.source_map[(src,dst)][dpid].iterkeys():
                    tables.source_map[(src,dst)][dpid][dst_port] = []
                  if dpid == road[-1]:#src host port has no slot
                    src_slot = -1
                  else:
                    for i in xrange(0,80):
                      if tables.info_map[dpid][src_port][i]['status'] == 0:
                        tables.info_map[dpid][src_port][i]['status'] = 1
                        src_slot = i
                        tables.source_map[(src,dst)][dpid][src_port].append(i)
                        break
                  if dpid == road[0]:#dst host port has no slot:
                    dst_slot = -1
                  else:
                    for i in xrange(0,80):
                      if tables.info_map[dpid][dst_port][i]['status'] == 0:
                        tables.info_map[dpid][dst_port][i]['status'] = 1
                        dst_slot = i
                        tables.source_map[(src,dst)][dpid][dst_port].append(i)
                        break

                  cflow_mod = of.ofp_header(type=0xff, xid=rmsg.xid)\
                       /of.ofp_cflow_mod(command=0)\
                       /of.ofp_connect_wildcards()\
                       /of.ofp_connect(in_port = pkt_in_msg.in_port)\
                       /of.ofp_action_output(type=0, port=dst_port, len=8)
                  type = switch_info[tables.sock_dpid[fd][0]]

                  if route_type == 1:#for OTN
                    if src_slot == -1:
                      cflow_mod.payload.payload.payload.nport_in = 81
                    else:
                      cflow_mod.payload.payload.payload.nport_in = src_slot
                    if dst_slot == -1:
                      cflow_mod.payload.payload.payload.nport_out = 81
                    else:  
                      cflow_mod.payload.payload.payload.nport_out = dst_slot
                    cflow_mod.payload.payload.payload.supp_sw_otn_gran_out = tables.switch_map[dpid]['port'][dst_port].SUPP_SW_GRAN
                    cflow_mod.payload.payload.payload.sup_otn_port_bandwidth_out = tables.switch_map[dpid]['port'][dst_port].sup_otn_port_bandwidth

                  elif route_type == 2:#for wavelength
                    cflow_mod.payload.payload.payload.wport_in = src_slot
                    cflow_mod.payload.payload.payload.wport_out = dst_slot
                  
                  #this field is used to record cflow, but I have no ideal about how to delete the outdate flow---------------------
                  
                  if dpid not in tables.cflow_map.iterkeys():#cflow_map,12.19 
                    tables.cflow_map[dpid] = {}
                  tables.cflow_map[dpid][(src,dst)] = cflow_mod

                  print "cflow from ", src, " to ", dst, "\n"
                  print "dpid:", dpid, " in_port:", cflow_mod.payload.payload.payload.in_port, " out_port:", cflow_mod.payload.payload.payload.payload.port, "\n"
                  print "------------------------"
                  message_queue_map[sock].put(str(cflow_mod))
                  io_loop.update_handler(fd, io_loop.WRITE)
              

              #send barrier
              msg = of.ofp_header(type = 18,xid = rmsg.xid) 
              message_queue_map[sock].put(str(msg))
              io_loop.update_handler(fd, io_loop.WRITE)

      elif rmsg.type == 11: 
        print "OFPT_FLOW_REMOVED"
      elif rmsg.type == 12:
        print "OFPT_PORT_STATUS"
      elif rmsg.type == 13:
        print "OFPT_PACKET_OUT"
      elif rmsg.type == 14:
        print "OFPT_FLOW_MOD"
      elif rmsg.type == 15:
        print "OFPT_PORT_MOD"
      elif rmsg.type == 16:
        print "OFPT_STATS_REQUEST"
                
      elif rmsg.type == 17 and len(data)> 12:
        print "OFPT_STATS_REPLY"
        # 1. parsing ofp_stats_reply
        reply_header = of.ofp_stats_reply(body[:4])
        # 2.parsing ofp_flow_stats msg
        if reply_header.type == 0:
          reply_desc = of.ofp_desc_stats(body[4:])
          reply.show()
        elif reply_header.type == 1 and len(data)>92:
          #here informatioin is used for flow stats
          reply_body_data1 = of.ofp_flow_stats(body[4:8])
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

          #the followings are about Load Balancing
          if fd in tables.fd_map.iterkeys() and fd in tables.sock_dpid.iterkeys():
            dpid = tables.sock_dpid[fd][1]
          if dpid in tables.flow_map.iterkeys():
            src_mac = reply_body_match.dl_src
            dst_mac = reply_body_match.dl_dst
            for flow in tables.flow_map[dpid]:
              if flow.payload.payload.dl_src == src_mac and flow.payload.payload.dl_dst == dst_mac:
                src_ip = flow.payload.payload.nw_src
                dst_ip = flow.payload.payload.nw_dst
                pair = (src_ip,dst_ip)
                flow_time = float(reply_body_data2.duration_sec) + float(reply_body_data2.duration_nsec/1000000000)
                flow_data = float(reply_body_data2.byte_count)
                if pair not in ip_stats.iterkeys():
                  ip_stats[pair] = {}
                  ip_stats[pair][0] = {}
                  ip_stats[pair][0]['flow_time'] = flow_time
                  ip_stats[pair][0]['flow_data'] = flow_data
                else:
                  if 1 in ip_stats[pair].iterkeys():#have a pair
                    ip_stats[pair][0]['flow_time'] = ip_stats[pair][1]['flow_time']
                    ip_stats[pair][0]['flow_data'] = ip_stats[pair][1]['flow_data']
                  else:
                    ip_stats[pair][1] = {}
                  ip_stats[pair][1]['flow_time'] = flow_time
                  ip_stats[pair][1]['flow_data'] = flow_data
                  if flow_time != ip_stats[pair][0]['flow_time']:
                    load = (flow_data - ip_stats[pair][0]['flow_data']) / (flow_time - ip_stats[pair][0]['flow_time'])
                    print "now the link ", pair, " load is ", load, "(byte/s)\n"
                    global switch_load
                    if load > switch_load:#change to cflow
                      ip_type[pair] = '2'
                      #todo:flow_mod(delete)

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

      elif rmsg.type == 18:
        print "OFPT_BARRIER_REQUEST"
      #no message body, the xid is the previous barrier request xid
      elif rmsg.type == 19:
        barrier = 0
        dpid = tables.sock_dpid[fd][1]
        for a,b in tables.barrier_map.items():
          for k,v in b.items():
            if k == dpid and v == rmsg.xid:
              if dpid == tables.road_map[a][0]:#if the barrier is from the dst switch, then the road is completed   
                barrier = 1
                print "road ", a, " is completed!\n"
                tables.barrier_map.pop(a)
          if barrier:
            break
          
        #print "OFPT_BARRIER_REPLY: ", rmsg.xid, "Successful"
      elif rmsg.type == 20:
        print "OFPT_QUEUE_GET_CONFIG_REQUEST"
      elif rmsg.type == 21:
        print "OFPT_QUEUE_GET_CONFIG_REPLY"
      elif rmsg.type == 24:
        print "OFPT_CFEATURES_REPLY"
        msg = of.ofp_cfeatures_reply(body[0:24])#length of reply msg
        #bind the bpid and type  (type,  dpid)
        #OTN:WAVE:IP  b'000'
        TYPE = msg.OFPC_IP_SWITCH + msg.OFPC_WAVE_SWITCH * 2 + msg.OFPC_OTN_SWITCH * 4
        tables.sock_dpid[fd] = [TYPE, msg.datapath_id]#IP only
        port_info_raw = body[24:]
        port_info = {}
        port_i = {}
        print "port number:",len(port_info_raw)/72, "total length:", len(port_info_raw)
        for i in range(len(port_info_raw)/72):
          port_info[i] = of.ofp_phy_cport(port_info_raw[i*72:72+i*72])
          port_i[port_info[i].port_no] = port_info[i]

        switch_type = tables.sock_dpid[fd][0]#features recorded in switch_map
        tables.switch_map[msg.datapath_id] = {'features':msg, 'type':switch_type, 'port':port_i}
        tables.info_map[msg.datapath_id] = {} 
 
        #start to discovery
        lldp_flow = create_topo._connection_up(msg.datapath_id)
        
        message_queue_map[sock].put(str(lldp_flow))
        io_loop.update_handler(fd, io_loop.WRITE)#discovery-handle
        
        create_topo._sender._connection_up(msg.datapath_id, port_info)
  
  now_time = time.time()
  global time_list
  time_list.append(now_time)
  if len(time_list) == 1:
    pass
  elif len(time_list) == 2:
    slot = time_list[1] - time_list[0]
    if slot < period:
      time_list.pop(1)
    if slot > period:
      time_list.pop(0)
      if fd in tables.sock_dpid.iterkeys():
        dpid = tables.sock_dpid[fd][1]
        if dpid in tables.flow_map.iterkeys():
          for flow in tables.flow_map[dpid]:
            if flow.type != 0xff:
              message_queue_map[sock].put(str(stats.send(1,flow))) 
              io_loop.update_handler(fd, io_loop.WRITE)
         
#------------------------------------------------------We finish the actions of manipulateing___________________________

  if events & io_loop.WRITE:
    try:
      next_msg = message_queue_map[sock].get_nowait()
    except Queue.Empty:
      #print "%s queue empty" % str(address)
      io_loop.update_handler(fd, io_loop.READ)   
    else:
      #print 'sending "%s" to %s' % (of.ofp_header(next_msg).type, address)
      sock.send(next_msg)




def agent(sock, fd, events):
  #print fd, sock, events
  try:
    connection, address = sock.accept()
  except socket.error, e:
    if e.args[0] not in (errno.EWOULDBLOCK, errno.EAGAIN):
      raise
    return
  connection.setblocking(0)
  handle_connection(connection, address)
  tables.fd_map[connection.fileno()] = connection
  client_handle = functools.partial(client_handler, address)
  io_loop.add_handler(connection.fileno(), client_handle, io_loop.READ)
  print "in agent: new switch", connection.fileno(), client_handle
  message_queue_map[connection] = Queue.Queue()

def new_sock(block):
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.setblocking(block)
  return sock


#the followings are preparations for switch handlers
sock = new_sock(0)
sock.bind(("", 6635))
sock.listen(6635)
	  
io_loop = ioloop.IOLoop.instance()
callback = functools.partial(agent, sock)
print sock, sock.getsockname()
io_loop.add_handler(sock.fileno(), callback, io_loop.READ)


try:
  thread.start_new_thread(io_loop.start,())
except KeyboardInterrupt:
  io_loop.stop()
  print "quit"


def launch ():
  core.registerNew(Input)
