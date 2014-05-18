import errno
import functools
import socket
import threading
import Queue
import time
import sys

from threading import Timer
from scapy import *


from  OpenFlow import libopenflow as of
import OpenFlow.ofp_handler as ofp_handler
import database.timer_list as timer_list
sys.path.append('.')
"""
TODO:class miracle
Author:Licheng
Time:2014/5/17

"""

class connection(object):
    """connection class"""
    def __init__(self,fd,connection):
        self.fd = fd
        self.connection = connection
        self.fd_lock = threading.RLock()
        self.message_queue =Queue.Queue()
        self.message_queue_lock = threading.RLock()  

class miracle_thread(threading.Thread):  
    def __init__(self, func, args, name=""):  
        threading.Thread.__init__(self)  
        self.name = name  
        self.func = func  
        self.args =args
    def run(self):  
        self.res = self.func(*self.args)

class miracle(object):
    """miracle is a mini controller"""
    def __init__(self, run):
        self.run = run


    run = 1
    fd_map = {}
    message_queue_map = {}

    fd_lock = threading.RLock()
    queue_lock = threading.RLock()
    sock_lock = threading.RLock()

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

    def handle_connection(self,connection, address):
            print ">>>connection up,", connection, address

    def recv_message(self,fd_map,message_queue_map):
        while self.run:
            #print "run recv_message"
            try:    
                for fd in fd_map:
                    #print "try_recv_message "
                    self.fd_lock.acquire()
                    sock = fd_map[fd]
                    self.fd_lock.release()

                    self.queue_lock.acquire()
                    data = sock.recv(1024)
                    self.queue_lock.release()

                    if data == '':
                        print ">>>Connection dropped"
                        self.fd_lock.acquire()
                        fd_map.remove(fd)
                        self.fd_lock.release()
                    if len(data)<8:
                        print ">>>Length of packet is too short"
                    else:
                        if len(data)>=8:
                            rmsg = of.ofp_header(data[0:8])
                            body = data[8:]
                        if rmsg.type == 0:
                            msg = self.handler[0] (data)
                            self.queue_lock.acquire()
                            message_queue_map[sock].put(str(msg))
                            message_queue_map[sock].put(str(of.ofp_header(type = 5)))
                            self.queue_lock.release()
                        elif rmsg.type == 6:
                            self.handler[6] (data,fd)
                        else:
                            msg = self.handler[rmsg.type] (data,fd)
                            queue_lock.acquire()
                            message_queue_map[sock].put(str(msg))
                            queue_lock.release()
            except KeyboardInterrupt:
                print ">>>quit"
                sys.exit(0)

    def send_message(self,message_queue_map):
        while self.run:
            self.queue_lock.acquire()
            for sock in message_queue_map:
                
                try:
                    #print "try send_message"
                    next_msg = message_queue_map[sock].get_nowait()
                except KeyboardInterrupt:
                    print ">>>quit"
                    sys.exit(0)
                except Queue.Empty:
                    pass
                else:
                    print "send_next_msg"
                    #self.sock_lock.acquire()
                    sock.send(next_msg)
                    #self.sock_lock.release()
            self.queue_lock.release()

    def connection_up(self, sock):
        def accept_loop():
            try:
                connection, address = sock.accept()
                
            except KeyboardInterrupt:
                print ">>>quit"
                sys.exit(0)
            except socket.error, e:
                if e.args[0] not in (errno.EWOULDBLOCK, errno.EAGAIN):
                    raise
                return
            self.handle_connection(connection, address)
            connection.setblocking(0)
            self.fd_lock.acquire()
            self.fd_map[connection.fileno()] = connection
            self.fd_lock.release()

            self.queue_lock.acquire()
            self.message_queue_map[connection] = Queue.Queue()
            self.queue_lock.release()
            #sleep(1)
        while self.run:
            try:
                accept_loop()
            except KeyboardInterrupt:
                print "break"
                sys.exit(0)
                break

    def new_sock(self,block):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(block)
        return sock  

    def start_up(self,port = 6633,listen =100):
        sock = self.new_sock(0)
        sock.bind(("", 6633))
        sock.listen(listen)

        threads = []
        t_connection = miracle_thread(func = self.connection_up, args =(sock,),name = "connection")
        #t_connection = threading.Thread(target=self.connection_up, args=(sock,)) 
        threads.append(t_connection)
        #t_recv = threading.Thread(target=self.recv_message, args=(self.fd_map,self.message_queue_map))
        t_recv = miracle_thread(func=self.recv_message, args=(self.fd_map,self.message_queue_map),name = "recv_message") 
        threads.append(t_recv)
        #t_send = threading.Thread(target=self.send_message, args=(self.message_queue_map,))
        t_send = miracle_thread(func=self.send_message, args=(self.message_queue_map,),name = "send_message") 
        threads.append(t_send)

        #t_connection.start()
        for thread in threads:  
            thread.start()
            print "start"
        for thread in threads:  
            thread.join()
            print "join"
        
if __name__ == '__main__':
    miracle_muti = miracle(1)
    try:
        miracle_muti.start_up()
    except KeyboardInterrupt:
        print ">>>quit" 
        sys.exit(0)
