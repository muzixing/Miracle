# Copyright 2011-2013 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

# This file is loosely based on the discovery component in NOX.

"""
This module discovers the connectivity between OpenFlow switches by sending
out LLDP packets. To be notified of this information, listen to LinkEvents
on core.openflow_discovery.

It's possible that some of this should be abstracted out into a generic
Discovery module, or a Discovery superclass.
"""
import libopencflow as ofc
import libopenflow as of
#from pox.lib.revent import *
from pox.lib.recoco import Timer
from pox.lib.util import dpid_to_str, str_to_bool
from pox.core import core
import pox.openflow.libopenflow_01 as off
import pox.lib.packet as pkt

import struct
import time
from collections import namedtuple
from random import shuffle

log = core.getLogger()

import tables

global topo_flag
topo_flag = tables.switch_number#indicate whether the topo-discovery is completed or not

class LLDPSender (object):
  """
  Sends out discovery packets
  """

  SendItem = namedtuple("LLDPSenderItem", ('dpid','port_num','packet'))

  #NOTE: This class keeps the packets to send in a flat list, which makes
  #      adding/removing them on switch join/leave or (especially) port
  #      status changes relatively expensive. Could easily be improved.

  def __init__ (self, send_cycle_time, ttl = 120):
    """
    Initialize an LLDP packet sender

    send_cycle_time is the time (in seconds) that this sender will take to
      send every discovery packet.  Thus, it should be the link timeout
      interval at most.

    ttl is the time (in seconds) for which a receiving LLDP agent should
      consider the rest of the data to be valid.  We don't use this, but
      other LLDP agents might.  Can't be 0 (this means revoke).
    """
    # Packets remaining to be sent in this cycle
    self._this_cycle = []

    # Packets we've already sent in this cycle
    self._next_cycle = []

    self._timer = None
    self._ttl = ttl
    self._send_cycle_time = send_cycle_time
  '''
  def _handle_openflow_PortStatus (self, event):
    """
    Track changes to switch ports
    """
    if event.added:
      self.add_port(event.dpid, event.port, event.ofp.desc.hw_addr)
    elif event.deleted:
      self.del_port(event.dpid, event.port)

  '''	  
  def _connection_up (self, dpid, port_info):#okay, data in features is needed here
    self.del_switch(dpid, set_timer = False)
    
    ports = [(p.port_no, p.hw_addr) for p in port_info.itervalues()]

    for port_num, port_addr in ports:
      self.add_port(dpid, port_num, port_addr, set_timer = False)
    self._set_timer()

  def _connection_down (self, dpid):#okay
    self.del_switch(dpid)

  def del_switch (self, dpid, set_timer = True):#okay
    self._this_cycle = [p for p in self._this_cycle if p.dpid != dpid]
    self._next_cycle = [p for p in self._next_cycle if p.dpid != dpid]
    if set_timer: self._set_timer()

  def del_port (self, dpid, port_num, set_timer = True):#the value of OFPP_MAX should be confirmed
    if port_num > off.OFPP_MAX: return
    self._this_cycle = [p for p in self._this_cycle
                        if p.dpid != dpid or p.port_num != port_num]
    self._next_cycle = [p for p in self._next_cycle
                        if p.dpid != dpid or p.port_num != port_num]
    if set_timer: self._set_timer()

  def add_port (self, dpid, port_num, port_addr, set_timer = True):#the value of OFPP_MAX should be confirmed
    if port_num > off.OFPP_MAX: return
    self.del_port(dpid, port_num, set_timer = False)
    self._next_cycle.append(LLDPSender.SendItem(dpid, port_num,
          self.create_discovery_packet(dpid, port_num, port_addr)))
    if set_timer: self._set_timer()

  def _set_timer (self):#okay
    if self._timer: self._timer.cancel()
    self._timer = None
    num_packets = len(self._this_cycle) + len(self._next_cycle)
    if num_packets != 0:
      self._timer = Timer(self._send_cycle_time / float(num_packets),
                          self._timer_handler, recurring=True)

  def _timer_handler (self):#okay, return to the packet which will be sent
    """
    Called by a timer to actually send packets.

    Picks the first packet off this cycle's list, sends it, and then puts
    it on the next-cycle list.  When this cycle's list is empty, starts
    the next cycle.
    """
    if len(self._this_cycle) == 0:
      self._this_cycle = self._next_cycle
      self._next_cycle = []
      shuffle(self._this_cycle)
    item = self._this_cycle.pop(0)
    self._next_cycle.append(item)
    for fd in tables.sock_dpid:
      if tables.sock_dpid[fd][1] == item.dpid:
        tables.fd_map[fd].send(item.packet)
        break

  def create_discovery_packet (self, dpid, port_num, port_addr):#okay
    """
    Build discovery packet
    """

    chassis_id = pkt.chassis_id(subtype=pkt.chassis_id.SUB_LOCAL)
    chassis_id.id = bytes('dpid:' + hex(long(dpid))[2:-1])
    # Maybe this should be a MAC.  But a MAC of what?  Local port, maybe?

    port_id = pkt.port_id(subtype=pkt.port_id.SUB_PORT, id=str(port_num))

    ttl = pkt.ttl(ttl = self._ttl)

    sysdesc = pkt.system_description()
    sysdesc.payload = bytes('dpid:' + hex(long(dpid))[2:-1])

    discovery_packet = pkt.lldp()
    discovery_packet.tlvs.append(chassis_id)
    discovery_packet.tlvs.append(port_id)
    discovery_packet.tlvs.append(ttl)
    discovery_packet.tlvs.append(sysdesc)
    discovery_packet.tlvs.append(pkt.end_tlv())

    eth = pkt.ethernet(type=pkt.ethernet.LLDP_TYPE)
    eth.src = port_addr
    eth.dst = pkt.ETHERNET.NDP_MULTICAST
    eth.payload = discovery_packet

    po = off.ofp_packet_out(action = off.ofp_action_output(port=port_num))
    po.data = eth.pack()
    return po.pack()

'''
class LinkEvent (object):
  """
  Link up/down event
  """
  def __init__ (self, add, link):
    #Event.__init__(self)
    self.link = link
    self.added = add
    self.removed = not add

  def port_for_dpid (self, dpid):
    if self.link.dpid1 == dpid:
      return self.link.port1
    if self.link.dpid2 == dpid:
      return self.link.port2
    return None
'''

class Discovery (object):
  """
  Component that attempts to discover network toplogy.

  Sends out specially-crafted LLDP packets, and monitors their arrival.
  """

  _flow_priority = 65000     # Priority of LLDP-catching flow (if any)
  _link_timeout = 10         # How long until we consider a link dead
  _timeout_check_period = 10  # How often to check for timeouts

  Link = namedtuple("Link",("dpid1","port1","dpid2","port2"))

  def __init__ (self, install_flow = True, explicit_drop = True,
                link_timeout = None, eat_early_packets = False):
    self._eat_early_packets = eat_early_packets
    self._explicit_drop = explicit_drop
    self._install_flow = install_flow
    if link_timeout: self._link_timeout = link_timeout

    self.adjacency = {} # From Link to time.time() stamp
    self._sender = LLDPSender(self.send_cycle_time)

    # Listen with a high priority (mostly so we get PacketIns early)
    #core.listen_to_dependencies(self,
        #listen_args={'openflow':{'priority':0xffffffff}})

    #Timer(self._timeout_check_period, self._expire_links, recurring=True)

  @property
  def send_cycle_time (self):
    return self._link_timeout / 2.0

  def _connection_up (self, dpid):#features are needed here, named msg, then send the msg to related dpid
    if self._install_flow:
      # Make sure we get appropriate traffic
      log.debug("Installing flow for %s", dpid_to_str(dpid))
   
      match = off.ofp_match(dl_type = pkt.ethernet.LLDP_TYPE,
                           dl_dst = pkt.ETHERNET.NDP_MULTICAST)
      msg = off.ofp_flow_mod()
      msg.priority = self._flow_priority
      msg.match = match
      msg.actions.append(off.ofp_action_output(port = off.OFPP_CONTROLLER))
      msg = msg.pack()
      return msg

  def _connection_down (self, dpid):
    # Delete all links on this switch
    self._delete_links([link for link in self.adjacency
                        if link.dpid1 == dpid
                        or link.dpid2 == dpid])
  '''
  def _expire_links (self):
    """
    Remove apparently dead links
    """
    now = time.time()

    expired = [link for link,timestamp in self.adjacency.iteritems()
               if timestamp + self._link_timeout < now]
    if expired:
      for link in expired:
        log.info('link timeout: %s.%i -> %s.%i' %
                 (dpid_to_str(link.dpid1), link.port1,
                  dpid_to_str(link.dpid2), link.port2))

      self._delete_links(expired)
  '''
  def _handle_openflow_PacketIn (self, msg, packet, dpid):
    """
    Receive and process LLDP packets
    """
    global topo_flag
    if (packet.effective_ethertype != pkt.ethernet.LLDP_TYPE
        or packet.dst != pkt.ETHERNET.NDP_MULTICAST):#there should be confirmed. use which filed of packet
      '''
      if not self._eat_early_packets: return
      if not event.connection.connect_time: return
      enable_time = time.time() - self.send_cycle_time - 1
      if event.connection.connect_time > enable_time:
        return EventHalt
      '''
      return
    '''
    if self._explicit_drop:
      if msg.buffer_id is not None:
        log.debug("Dropping LLDP packet %i", msg.buffer_id)
        msg1 = off.ofp_packet_out()
        msg1.buffer_id = msg.buffer_id
        msg1.in_port = msg.in_port
        #event.connection.send(msg)----- use tornado to send
    '''
    lldph = packet.find(pkt.lldp)
    if lldph is None or not lldph.parsed:
      log.error("LLDP packet could not be parsed")
      print "lldp error, please check the log-info.\n"
      return
    if len(lldph.tlvs) < 3:
      log.error("LLDP packet without required three TLVs")
      print "lldp error, please check the log-info.\n"
      return
    if lldph.tlvs[0].tlv_type != pkt.lldp.CHASSIS_ID_TLV:
      log.error("LLDP packet TLV 1 not CHASSIS_ID")
      print "lldp error, please check the log-info.\n"
      return
    if lldph.tlvs[1].tlv_type != pkt.lldp.PORT_ID_TLV:
      log.error("LLDP packet TLV 2 not PORT_ID")
      print "lldp error, please check the log-info.\n"
      return
    if lldph.tlvs[2].tlv_type != pkt.lldp.TTL_TLV:
      log.error("LLDP packet TLV 3 not TTL")
      print "lldp error, please check the log-info.\n"
      return

    def lookInSysDesc ():
      r = None
      for t in lldph.tlvs[3:]:
        if t.tlv_type == pkt.lldp.SYSTEM_DESC_TLV:
          # This is our favored way...
          for line in t.payload.split('\n'):
            if line.startswith('dpid:'):
              try:
                return int(line[5:], 16)
              except:
                pass
          if len(t.payload) == 8:
            # Maybe it's a FlowVisor LLDP...
            # Do these still exist?
            try:
              return struct.unpack("!Q", t.payload)[0]
            except:
              pass
          return None

    originatorDPID = lookInSysDesc()

    if originatorDPID == None:
      # We'll look in the CHASSIS ID
      if lldph.tlvs[0].subtype == pkt.chassis_id.SUB_LOCAL:
        if lldph.tlvs[0].id.startswith('dpid:'):
          # This is how NOX does it at the time of writing
          try:
            originatorDPID = int(lldph.tlvs[0].id[5:], 16)
          except:
            pass
      if originatorDPID == None:
        if lldph.tlvs[0].subtype == pkt.chassis_id.SUB_MAC:
          # Last ditch effort -- we'll hope the DPID was small enough
          # to fit into an ethernet address
          if len(lldph.tlvs[0].id) == 6:
            try:
              s = lldph.tlvs[0].id
              originatorDPID = struct.unpack("!Q",'\x00\x00' + s)[0]
            except:
              pass

    if originatorDPID == None:
      log.warning("Couldn't find a DPID in the LLDP packet")
      print "lldp error, please check the log-info.\n"
      return
    '''
    if originatorDPID not in core.openflow.connections:
      log.info('Received LLDP packet from unknown switch')
      return EventHalt
	'''

    # Get port number from port TLV
    if lldph.tlvs[1].subtype != pkt.port_id.SUB_PORT:
      log.warning("Thought we found a DPID, but packet didn't have a port")
      print "lldp error, please check the log-info.\n"
      return
    originatorPort = None
    if lldph.tlvs[1].id.isdigit():
      # We expect it to be a decimal value
      originatorPort = int(lldph.tlvs[1].id)
    elif len(lldph.tlvs[1].id) == 2:
      # Maybe it's a 16 bit port number...
      try:
        originatorPort  =  struct.unpack("!H", lldph.tlvs[1].id)[0]
      except:
        pass
    if originatorPort is None:
      log.warning("Thought we found a DPID, but port number didn't " +
                  "make sense")
      print "lldp error, please check the log-info.\n"
      return

    if (dpid, msg.in_port) == (originatorDPID, originatorPort):
      log.warning("Port received its own LLDP packet; ignoring")
      return
    #here, link will be added into topo-table
    link = Discovery.Link(originatorDPID, originatorPort, dpid,
                          msg.in_port)
    if link not in self.adjacency:#-------establish the topo_map
      self.adjacency[link] = time.time()
      log.info('link detected: %s.%i -> %s.%i' %
               (dpid_to_str(link.dpid1), link.port1,
                dpid_to_str(link.dpid2), link.port2))
      pairs = (link.dpid1, link.port1, link.dpid2, link.port2)
      pairs_ = (link.dpid2, link.port2, link.dpid1, link.port1)
     
      if pairs_ not in tables.topo_map:
        tables.topo_map[pairs] = {'type':0, 'bandwidth':0, 'payload':0, 'status':0, "bit_map":b'0000000000'}
        dpid1 = pairs[0]
        port1 = pairs[1]
        dpid2 = pairs[2]
        port2 = pairs[3]
        if tables.switch_map[dpid1]['port'][port1].OFPST_T_OTN and tables.switch_map[dpid2]['port'][port2].OFPST_T_OTN:#OTN-LINK
          tables.topo_map[pairs]['type'] = 1
          #print tables.topo_map[pairs]['type']
          tables.topo_map[pairs]['bandwidth'] = tables.switch_map[dpid1]['port'][port1].sup_otn_port_bandwidth
          #print tables.topo_map[pairs]['bandwidth']
          if tables.switch_map[dpid1]['port'][port1].SUPP_SW_GRAN == 1:
            slot_n = int(tables.topo_map[pairs]['bandwidth']/1.25)
            #print "slot_n: %d" % slot_n
            tables.topo_map[pairs]["bit_map"] = b'0' * slot_n
            tables.info_map[dpid1][port1] = {}
            tables.info_map[dpid2][port2] = {}
            for i in xrange(0, slot_n):
              tables.info_map[dpid1][port1][i] = {'type':0, 'service':0, 'status':0}
              tables.info_map[dpid2][port2][i] = {'type':0, 'service':0, 'status':0}
      topo_flag -= 1
      #print tables.topo_map

    else:
      # Just update timestamp
      self.adjacency[link] = time.time()
    #attention:link is a namedtuple. We can get information just like "link.dpid1"
    #print(links.value() for links in self.adjacency)

    return# Probably nobody else needs this event

  def _delete_links (self, links):
    global topo_flag
    for link in links:
      del self.adjacency[link]
      if topo_flag:
        pair = (link.dpid1, link.port1, link.dpid2, link.port2)
        if pair in tables.topo_map.iterkeys():
          tables.topo_map.pop(pair)

  def is_edge_port (self, dpid, port):
    """
    Return True if given port does not connect to another switch
    """
    for link in self.adjacency:
      if link.dpid1 == dpid and link.port1 == port:
        return False
      if link.dpid2 == dpid and link.port2 == port:
        return False
    return True

