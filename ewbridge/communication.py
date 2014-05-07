import socket
import thread
import logging
from pox.messenger import lib_ewbridge as ofpew
from pox.messenger import  OpenFlow_EWbridge as ew_handler

"""
Author: muzi
Date: 2014/4/12

#TODO: We start a passive TCP on a POX as a server.
       In the same time ,we can also start a active TCP to connect the server POX,so we build the connection between two POX.

"""

#handle the socket
def socket_handler(socket,(remoteHost,remotePort)):
  data = socket.recv(1024)
  #handle the messenges.
  if data == '':
      print "nothing received"
  if len(data)<8:
      print "not a openflow ewbridge message"
  else:
      msg = str(ew_handler.msg_handler(data))   #handle the data received.
      if len(msg)>0:
          socket.send(msg)

#TODO run a passive TCP sever 
def distributed_server(port):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(('0.0.0.0',port))
    s.listen(16)
    while True:
      logging.getLogger("boot run TCP server").debug("Server running")
      print ("\n *****Server starting ******\n")
      fd,(remoteHost, remotePort) = s.accept()

      print ("%s:%s connected" %(remoteHost,remotePort))
      thread.start_new_thread(socket_handler,(fd,(remoteHost,remotePort),))
    fd.close()
    s.close()
#TODO run a  TCP client
def distributed_client(server_ip,server_port):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.setblocking(1)
    sock.connect((server_ip,server_port))
    #we need to change it into ofpew,send hello to the server and start the communication.

    print "\n***** Client Starting*****\n"
    msg = ofpew.ofpew_header(type = 0,length = 8)

    sock.send(str(msg)) # say hello to server controller.

    while 1:
        data = sock.recv(1024)
        if data =="":
            #print ("Receive nothing")
            pass
        else:
            if len(data)<8:
                print "not a openflow ewbridge message"
            else:
              	msg = str(ew_handler.msg_handler(data))   #handle the data received.
                if len(msg)>=8:
                    sock.send(msg)
        echo_request = str(ew_handler.send_echo_handler())  #send echo request priodic.
        if len(echo_request)==8:
            sock.send(echo_request)


if __name__ == "__main__":
    print "Build the connection between two POX"
    pass

