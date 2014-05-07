"""
In this agent, the Tornado TCP server will use one process to manage all the classes.
Therefore, the total throughput of this script will be affected.  
"""
import errno
import functools
import tornado.ioloop as ioloop
import socket
import libopenflow_old as of
import libopenflow as ofc
import convert
import time

import Queue

#create a connection between socket fd of (controller, sw) and sw class 
fdmap = {}
num = 0

"""
Print connection information
"""
def print_connection(connection, address):
        print "connection:", connection, address

"""
Create a new socket
The parameter ``block`` determine if the return socket is blocking
or nonblocking socket. Use '1' when creating a socket which connect
a controller.
"""
def new_sock(block):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(block)
    return sock

"""
The switch class maintains the connection between controller and individual 
switches. For each OpenFlow switch, this transparent agent create a object of this 
class. 
"""
class switch():
    def __init__(self, sock_sw, sock_con):
        self.sock_sw    = sock_sw
        self.sock_con   = sock_con
        self.fd_sw      = sock_sw.fileno()
        self.fd_con     = sock_con.fileno()
        self.queue_con  = Queue.Queue()
        self.queue_sw   = Queue.Queue()
        self.buffer     = {}
        self.counter    = 0
        self.dpid       = 0
        self.flow_cache = []#use for save the flow
        
    def controller_handler(self, address, fd, events):
        if events & io_loop.READ:
            data = self.sock_con.recv(1024)
            if data == '':
                print "controller disconnected"
                io_loop.remove_handler(self.fd_con)
                print "closing connection to switch"
                self.sock_sw.close()
                io_loop.remove_handler(self.fd_sw)
            else:
                rmsg = of.ofp_header(data[0:8])
                # Here, we can manipulate OpenFlow packets from CONTROLLER.
                if rmsg.type == 0xff:                           #cflow_mod   
                    header = ofc.ofp_header(data[0:8])
                    
                    cflow_mod = ofc.ofp_cflow_mod(data[8:16])
                    cflow_connect_wildcards = ofc.ofp_connect_wildcards(data[16:18])
                    cflow_connect = ofc.ofp_connect(data[18:92])
                    ofp_action_output= ofc.ofp_action_output(data[92:])

                    msg = header/cflow_mod/cflow_connect_wildcards/cflow_connect/ofp_action_output
                    msg.show()
                    data = convert.ofc2of(msg, self.buffer, self.dpid) 
                    
                    self.flow_cache.append([time.time(),data])

                elif rmsg.type == 14:
                    print "send flow_mod"
                    #header = of.ofp_header(data[0:8])
                    #wildcards=of.ofp_flow_wildcards(data[8:12])
                    #match=of.ofp_match(data[12:48])
                    #flow_mod =of.ofp_flow_mod(data[48:72])
                    #action_header = of.ofp_action_header(data[72:80])
                    #action_output =of.ofp_action_output(data[80:88])
                    #data1 =header/wildcards/match/flow_mod/action_header/action_output
                    #self.flow_cache.append([time.time(),data1])
                #full message for flow status request: ofp_stats_rqeuest()/ofp_flow_wildcards()/ofp_match()/ofp_flow_stats_request()
                elif rmsg.type == 16 and 0: #do nothing and send it .
                    header = ofc.ofp_header(data[0:8])
                    ofp_stats_request = ofc.ofp_stats_request(data[8:12])
                    if ofp_stats_request.type == 1:
                        ofp_flow_wildcards = ofc.ofp_flow_wildcards(data[12:16])
                        data_match = ofc.ofp_match(data[16:52])
                        ofp_flow_stats_request = ofc.ofp_flow_stats_request(data[52:56])
                        for f in self.flow_cache:
                            flow = str(f[1])
                            ofp_flow_wildcards = ofc.ofp_flow_wildcards(flow[8:12])
                            ofp_flow_match = ofc.ofp_match(flow[12:48])
                            ofp_flow_stats_request.out_put = of.ofp_action_output(flow[80:88]).port
                            data = ofc.ofp_header(type = 16, length = 56)/ofp_stats_request/ofp_flow_wildcards/ofp_flow_match/ofp_flow_stats_request

                            #we try to delete the flow by this code.
                            #data = of.ofp_header(type=14,length=88)/ofp_flow_wildcards/ofp_flow_match/of.ofp_flow_mod(command=3,flags=1)
                            #print 'delete matching flow'

                            io_loop.update_handler(self.fd_sw, io_loop.WRITE)
                            self.queue_sw.put(str(data))#put it into the queue of packet which need to send to Switch.  
                    elif ofp_stats_request.type == 0:
                        print "send the ofp_stats_request(type = 0)"
                    elif ofp_stats_request.type ==2:
                        print "aggregate request"
                        ofp_flow_wildcards = ofc.ofp_flow_wildcards(data[12:16])
                        data_match = ofc.ofp_match(data[16:52])
                        ofp_aggregate_stats_request = ofc.ofp_aggregate_stats_request(data[52:56])
                        flow =  str(self.flow_cache)
                        wildcards = ofc.ofp_flow_wildcards(flow[8:12])
                        match = ofc.ofp_match(flow[12:48])

                        data = header/ofp_stats_request/wildcards/match/ofp_aggregate_stats_request
                    elif ofp_stats_request.type ==3:
                        print "table request"
                    elif ofp_stats_request.type ==4:
                        print "port request"
                    elif ofp_stats_request.type ==5:
                        print "queue request" 
                    elif ofp_stats_request.type ==0xffff:
                        print "vendor request"
                #There are no need to change other packets,just send them!
                io_loop.update_handler(self.fd_sw, io_loop.WRITE)
                self.queue_sw.put(str(data))
    
        if events & io_loop.WRITE:
            try:
                next_msg = self.queue_con.get_nowait()
            except Queue.Empty:
                io_loop.update_handler(self.fd_con, io_loop.READ)
            else:
                self.sock_con.send(next_msg)
#####################delete the flow cache by hard_timeout###################
        for f in self.flow_cache:
            if fresh(f):
                self.flow_cache.remove(f)
#######################################################################
    def switch_handler(self, address, fd, events):
        if events & io_loop.READ:
            data = self.sock_sw.recv(1024)
            if data == '':
                print "switch disconnected"
                io_loop.remove_handler(self.fd_sw)
                print "closing connection to controller"
                self.sock_con.close()
                io_loop.remove_handler(self.fd_con)
            else:
                rmsg = of.ofp_header(data[0:8])

                if rmsg.type == 6:
                    print "OFPT_FEATURES_REPLY"                                                  #Actually,we just need to change here.
                    header = of.ofp_header(data[0:8]) 
                    print "ofp_features_reply.xid ", header.xid
                    msg = of.ofp_features_reply(data[8:32])     #all sw type should make the convertion. Because our protocol need to use in all nets.
                    msg_port = data[32:]
                    msg = header/msg/msg_port                     
                    self.dpid=msg.datapath_id       #record the dpid
                    data = convert.of2ofc(msg, self.buffer, self.dpid)   
                    
                elif rmsg.type == 10:
                    pkt_in_msg = of.ofp_packet_in(data[8:18])
                    pkt_parsed = of.Ether(data[18:])
                    self.counter+=1
                    #[port + id+ dpid] --> [buffer_id + pkt_in_msg]
                    if isinstance(pkt_parsed.payload, of.IP) or isinstance(pkt_parsed.payload.payload, of.IP):
                        self.buffer[(pkt_in_msg.in_port, self.counter, self.dpid)] = [pkt_in_msg.buffer_id, rmsg/pkt_in_msg/pkt_parsed] # bind buffer id with in port 
                    rmsg.xid = self.counter                 # use the counter to check the buffer
                    data = rmsg/pkt_in_msg/pkt_parsed

                elif rmsg.type ==11:
                    match = ofc.ofp_match(data[12:48])                  #data[8:12]is wildcards
                    for flow in  self.flow_cache:
                        if match == ofc.ofp_match(str(flow[1])[12:48]):
                            self.flow_cache.remove(flow)                #delete the flow
                elif rmsg.type == 17:
                    print "stats_reply" ,len(data)
                    body = data[8:]
                    reply_header = of.ofp_stats_reply(body[:4])
                    if reply_header.type == 1 and len(data)>91:
                        reply_body_match = ofc.ofp_match(body[12:48])
                        reply_body_data2 = ofc.ofp_flow_stats_data(body[48:92])
                        if reply_body_data2.byte_count == 0 and reply_body_data2.packet_count == 0:  #it is a junck flow,delete it!
                            for flow in  self.flow_cache: 
                                if reply_body_match == ofc.ofp_match(str(flow[1])[12:48]):
                                    self.flow_cache.remove(flow)    
                io_loop.update_handler(self.fd_con, io_loop.WRITE)
                self.queue_con.put(str(data))
    
        if events & io_loop.WRITE:
            try:
                next_msg = self.queue_sw.get_nowait()
            except Queue.Empty:
                #print "%s queue empty" % str(address)
                io_loop.update_handler(self.fd_sw, io_loop.READ)
            else:
                #print 'sending "%s" to %s' % (of.ofp_type[of.ofp_header(next_msg).type], self.sock_sw.getpeername())
                self.sock_sw.send(next_msg)

"""
For the callback function of socket listening, the agent function will first
try to accept the connection started by switch. And if the connection is successful,
this function will continue on creating another socket to connect the controller.
If the controller cannot be reached, there will be ``ECONNREFUSED`` error. 

After all these things are done, we will have two sockets, one from OpenFlow switch, another 
one to controller. Send these two sockets as parameter, a new switch object can be 
created. Before exit the agent function, this function will add ``new_switch.switch_handler``
and ``new_switch.controller_handler`` to callback function of their own socket.
"""
def agent(sock, fd, events):
    #TODO: create a new class for switches. when a switch connected to agent, new class
    #also, the sw is connected to controller using another socket.
    #print fd, sock, events
    #1. accept connection from switch
    try:
        connection, address = sock.accept()
    except socket.error, e:
        if e.args[0] not in (errno.EWOULDBLOCK, errno.EAGAIN):
            raise
        return
    connection.setblocking(0)
    
    #2. connecting to controller
    #no idea why, but when not blocking, it says: error: [Errno 36] Operation now in progress
    sock_control = new_sock(1)
    try:
        sock_control.connect((controllerIP,controllerPort))
    except socket.error, e:
        if e.args[0] not in (errno.ECONNREFUSED, errno.EINPROGRESS):
            raise
        if e.args[0] == errno.ECONNREFUSED:
            print "cannot establish connection to controller, please check your config."
        return
    sock_control.setblocking(0)
    #3. create sw class object
    global num
    num = num + 1
    new_switch = switch(connection, sock_control)
    print "switch instance No.", num
    fdmap[connection.fileno()] = new_switch
    fdmap[sock_control.fileno()] = new_switch
    
    controller_handler = functools.partial(new_switch.controller_handler, address)
    io_loop.add_handler(sock_control.fileno(), controller_handler, io_loop.READ)
    print "agent: connected to controller"
    
    switch_handler = functools.partial(new_switch.switch_handler, address)
    io_loop.add_handler(connection.fileno(), switch_handler, io_loop.READ)
    print "agent: connected to switch", num
    
def fresh(f_list):
    if int(time.time()-f_list[0])>f_list[1].payload.payload.payload.hard_timeout:
        return 1
    else:
        return 0
    
if __name__ == '__main__':
    """
    For Tornado, there usually is only one thread, listening to the socket
    below. And also, this code block uses ``ioloop.add_handler()`` function
    to register a callback function if ``ioloop.READ`` event happens.
    
    When a new request from of switch, it will trigger ``ioloop.READ`` event
    in Tornado. And Tornado will execute the callback function ``agent()``.
    """
    sock = new_sock(0)
    sock.bind(("", 6633))
    sock.listen(6633)
    num = 0
    controllerIP = "192.168.0.2"
    controllerPort = 6635
    io_loop = ioloop.IOLoop.instance()
    callback = functools.partial(agent, sock)
    print sock, sock.getsockname()
    io_loop.add_handler(sock.fileno(), callback, io_loop.READ)
    io_loop.start()