import errno
import functools
import socket
import select
import threading
import Queue
import time,signal,os,traceback
import sys
from threading import Timer
from scapy import *

from  OpenFlow import libopenflow as of
import OpenFlow.ofp_handler as ofp_handler
import database.timer_list as timer_list
sys.path.append('.')
"""
TODO: Multithread miracle
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

    def recv_handler(self,fd_map,message_queue_map):
        for fd in fd_map.keys():
            self.fd_lock.acquire()
            sock = fd_map[fd]
            self.fd_lock.release()

            self.sock_lock.acquire()
            print "sock_lock by recv_message"
            data = sock.recv(1024)
            self.sock_lock.release()
            print "sock_unlock by recv_message"

            if data == '':
                print ">>>Connection dropped"
                self.fd_lock.acquire()
                del fd_map[fd]
                #sock.close()
                self.fd_lock.release()
                self.queue_lock.acquire()
                del message_queue_map[sock]
                self.queue_lock.release()
            if len(data)<8:
                print ">>>Length of packet is too short"
            else:
                if len(data)>=8:
                    rmsg = of.ofp_header(data[0:8])
                    body = data[8:]
                if rmsg.type == 0:
                    msg = self.handler[0] (data)
                    self.queue_lock.acquire()
                    print "hello queue_lock by recv_message"
                    message_queue_map[sock].put(str(msg))
                    message_queue_map[sock].put(str(of.ofp_header(type = 5)))
                    self.queue_lock.release()
                    print "hello queue_unlock by recv_message"
                elif rmsg.type == 6:
                    self.handler[6] (data,fd)
                else:
                    msg = self.handler[rmsg.type] (data,fd)
                    queue_lock.acquire()
                    print "other queue_lock by recv_message"
                    message_queue_map[sock].put(str(msg))
                    queue_lock.release()
                    print "other queue_unlock by recv_message"

    def recv_message(self,fd_map,message_queue_map):
        while self.run:
            try:
                self.recv_handler(fd_map,message_queue_map)
            except socket.error, e:
                print e
                continue

    def send_message(self,message_queue_map):
        while self.run:
            for sock in message_queue_map.keys():
                try:
                    self.queue_lock.acquire(1)
                    #print "queue_lock by send_message"
                    next_msg = message_queue_map[sock].get_nowait()
                    self.queue_lock.release()
                    print "queue_unlock by send_message"
                except Queue.Empty:
                    self.queue_lock.release()
                    #print "queue_unlock by queue_empty"
                    continue
                else:
                    print "send_next_msg"
                    self.sock_lock.acquire()
                    sock.send(next_msg)
                    self.sock_lock.release()

    def connection_up(self, listener, sockets):
        def accept_loop():
            rlist, wlist, elist = select.select(sockets, [], sockets, 120)
            print("select works")
            for new_socket in rlist:
                if new_socket is listener:
                    try:
                        connection, address = new_socket.accept()
                    except socket.error, e:
                        if e.args[0] not in (errno.EWOULDBLOCK, errno.EAGAIN):
                            raise
                        return
                    connection.setblocking(0)#if I set it  as 0 ,and then I will got the error 11:resource is unavliable.
                    sockets.append(connection)
                else:
                    self.handle_connection(connection, address)
                    self.fd_lock.acquire()
                    self.fd_map[connection.fileno()] = connection
                    self.fd_lock.release()

                    self.queue_lock.acquire()
                    self.message_queue_map[connection] = Queue.Queue()
                    self.queue_lock.release()
                    sleep(1)
        while self.run:
            try:
                accept_loop()
            except KeyboardInterrupt:
                sys.exit(0)

    def new_sock(self,block):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(block)
        return sock  

    def start_up(self,port = 6633,listen =100):
        listener = self.new_sock(0)
        listener.bind(("", 6633))
        listener.listen(listen)

        threads = []
        sockets = []
        sockets.append(listener)

        t_connection = miracle_thread(func = self.connection_up, args =(listener,sockets,),name = "connection")
        threads.append(t_connection)
        t_recv = miracle_thread(func=self.recv_message, args=(self.fd_map,self.message_queue_map),name = "recv_message") 
        threads.append(t_recv)
        t_send = miracle_thread(func=self.send_message, args=(self.message_queue_map,),name = "send_message") 
        threads.append(t_send)

        #t_connection.start()
        for thread in threads:  
            thread.start()
            print "start"
        for thread in threads:  
            thread.join()
            print "join"

class Watcher:  
    """this class solves two problems with multithreaded 
    programs in Python, (1) a signal might be delivered 
    to any thread (which is just a malfeature) and (2) if 
    the thread that gets the signal is waiting, the signal 
    is ignored (which is a bug). 
 
    The watcher is a concurrent process (not thread) that 
    waits for a signal and the process that contains the 
    threads. 
    """  
  
    def __init__(self):  
        """ Creates a child thread, which returns.  The parent 
            thread waits for a KeyboardInterrupt and then kills 
            the child thread. 
        """  
        self.child = os.fork()  
        if self.child == 0:  
            return  
        else:  
            self.watch()  
  
    def watch(self):  
        try:  
            os.wait()  
        except KeyboardInterrupt:
            print "\n"
            self.kill()  
        sys.exit()  
  
    def kill(self):  
        try:  
            os.kill(self.child, signal.SIGKILL)  
        except OSError: pass  

if __name__ == '__main__':
    miracle_muti = miracle(1)
    try:
        Watcher()
        miracle_muti.start_up()
    except KeyboardInterrupt:
        sys.exit(0)
