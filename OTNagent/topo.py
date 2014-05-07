#!/usr/bin/python
"""
	This is a topu of our test. It shows that how to add an interface(for example a real hardware interface) to a network after the network is created.
    This code writed by li cheng, after learning mininet of sprient's.
"""
import re
from mininet.cli import CLI
from mininet.log import setLogLevel, info,error
from mininet.net import Mininet
from mininet.link import Intf
from mininet.topolib import TreeTopo
from mininet.util import quietRun
from mininet.node import RemoteController, OVSKernelSwitch
def checkIntf(intf):
	#make sure intface exists and is not configured.
	if(' %s:'% intf) not in quietRun('ip link show'):
		error('Error:', intf, 'does not exist!\n' )
		exit(1)
	ips = re.findall( r'\d+\.\d+\.\d+\.\d+', quietRun( 'ifconfig ' + intf ) )
	if ips:
		error("Error:", intf, 'has an IP address,'
			'and is probably in use!\n')
		exit(1)
if __name__ == "__main__":
	setLogLevel("info")
	OVSKernelSwitch.setup()
	"""intfName_1 = "eth2"
	intfName_3 = "eth3"
	info("****checking****", intfName_1, '\n')
	checkIntf(intfName_1)
	info("****checking****", intfName_3, '\n')
	checkIntf(intfName_3)
	"""
	info("****creating network****\n")
	net = Mininet(listenPort = 6633)

	mycontroller = RemoteController("muziController", ip = "127.0.0.1")

	switch_1 = net.addSwitch('s1')
	switch_2 = net.addSwitch('s2')
	switch_3 = net.addSwitch('s3')
	#switch_4 = net.addSwitch('s4')
	h1 = net.addHost('h1')
	h2 = net.addHost('h2')



	net.controllers = [mycontroller]

	#_intf_1 = Intf(intfName_1, node = switch_1, port = 1)

	net.addLink(switch_1, switch_2, 2, 1)# node1, node2, port1, port2
	net.addLink(switch_2, switch_3, 2, 1)
	#net.addLink(switch_1, switch_4, 3, 1)

	net.addLink(switch_1, h1, 1)
	net.addLink(switch_2, h2, 2)

	#_intf_3 = Intf(intfName_3, node = switch_3, port = 2)

	#net.addLink(switch_4, switch_3, 2, 3)

	#info("*****Adding hardware interface ", intfName_1, "to switch:" ,switch_1.name, '\n')
	#info("*****Adding hardware interface ", intfName_3, "to switch:" ,switch_3.name, '\n')

	info("Node: you may need to reconfigure the interfaces for the Mininet hosts:\n", net.hosts, '\n')

	net.start()
	CLI(net)
	net.stop()
