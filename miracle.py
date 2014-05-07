import errno
import functools
import tornado.ioloop as ioloop
import socket
from scapy import *
import Queue
import time
import sys
sys.path.append('.')

from  OpenFlow import libopenflow as of
from  OpenFlow import stats_request as stats
import OpenFlow.ofp_handler as ofp_handler
import OTNagent.MySetting as MySetting

"""
TODO:Define the OpenFlow packets handler functions
Author:Licheng
Time:2014/5/5

"""



fd_map = {}
message_queue_map = {}
period = MySetting.period

global cookie
cookie = 0
global ready
ready = 0
count = 1
######################################################################################################################                
def handle_connection(connection, address):
        print "1 connection,", connection, address
def client_handler(address, fd, events):
    sock = fd_map[fd]
    if events & io_loop.READ:
        data = sock.recv(1024)
        if data == '':
            print "connection dropped"
            io_loop.remove_handler(fd)
        if len(data)<8:
            print "not a openflow message"
        else:
            if len(data)>=8:
                rmsg = of.ofp_header(data[0:8])
                #rmsg.show()
                body = data[8:]
            handler = { 0:ofp_handler.hello_handler,
                        1:ofp_handler.error_handler,
                        2:ofp_handler.echo_request_handler,
                        3:ofp_handler.echo_reply_handler,
                        4:ofp_handler.echo_reply_handler,
                        5:ofp_handler.features_request_handler,
                        6:ofp_handler.features_reply_handler,
                        7:None,
                        8:None,
                        9:None,
                        10:ofp_handler.packet_in_handler,
                        11:ofp_handler.flow_removed_handler,
                        12:ofp_handler.port_status_handler,
                        13:ofp_handler.packet_out_handler,
                        14:ofp_handler.flow_mod_handler,
                        15:ofp_handler.port_mod_handler,
                        16:ofp_handler.stats_request_handler,
                        17:ofp_handler.stats_reply_handler,#body
                        18:ofp_handler.barrier_request_handler,
                        19:ofp_handler.barrier_reply_handler,
                        20:ofp_handler.get_config_request_handler,
                        21:ofp_handler.get_config_reply_handler,
                        24:ofp_handler.cfeatrues_reply_handler #body
                        }
            if rmsg.type == 0:
                msg = handler[0] (data)
                message_queue_map[sock].put(str(msg))
                message_queue_map[sock].put(str(of.ofp_header(type = 5)))
            elif rmsg.type == 6:
                handler[6] (data,fd)
                global ready
                ready = 1
            else:
                msg = handler[rmsg.type] (data,fd)
                message_queue_map[sock].put(str(msg))
            io_loop.update_handler(fd, io_loop.WRITE)
        
        global count
        if ready and count % period == 0:
            #print "send stats_requests"
            flow =of.ofp_header()/of.ofp_flow_wildcards()/of.ofp_match()/of.ofp_flow_mod()
            message_queue_map[sock].put(str(ofp_handler.send_stats_request_handler(1,flow)))  #the parameter is the type of stats request
            count = 1
        count+=1
        

    #################################   We finish the actions of manipulateing  ################################

    if events & io_loop.WRITE:
        try:
            next_msg = message_queue_map[sock].get_nowait()
        except Queue.Empty:
            #print "%s queue empty" % str(address)
            io_loop.update_handler(fd, io_loop.READ)
        else:
            #print 'sending "%s" to %s' % (of.ofp_header(next_msg).type, address)
            sock.send(next_msg)

def connection_up(sock, fd, events):
    #print fd, sock, events
    try:
        connection, address = sock.accept()
    except socket.error, e:
        if e.args[0] not in (errno.EWOULDBLOCK, errno.EAGAIN):
            raise
        return
    connection.setblocking(0)
    handle_connection(connection, address)
    fd_map[connection.fileno()] = connection
    connection_handler = functools.partial(client_handler, address)
    io_loop.add_handler(connection.fileno(), connection_handler, io_loop.READ)
    print "in connection_up: new switch", connection.fileno(), connection_handler
    message_queue_map[connection] = Queue.Queue()

def new_sock(block):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(block)
    return sock

if __name__ == '__main__':
    sock = new_sock(0)
    sock.bind(("", 6633))
    sock.listen(6633)
    
    io_loop = ioloop.IOLoop.instance()
    #callback = functools.partial(connection_ready, sock)
    callback = functools.partial(connection_up, sock)
    print sock, sock.getsockname()
    io_loop.add_handler(sock.fileno(), callback, io_loop.READ)
    try:
        io_loop.start()
    except KeyboardInterrupt:
        io_loop.stop()
        print "quit" 
