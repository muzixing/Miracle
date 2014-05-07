sock_dpid = {}
#{file_no:[switch_type, dpid]}

fd_map = {}
#{file_no:socket}

switch_map = {}
#{dpid:{'features':features_reply, 'type':switch_type, 'port':port_info}}

info_map = {}
#{dpid:{port:{slot_no:{'type':slot_type, 'service':slot_ser, 'status':slot_status}}}}

topo_map = {}
#{(dpid1,port1,dpid2,port2):{'type':link_type, 'bandwidth':BW, "payload":PL, 'status':link_status, 'bit_map':map of slots}}

source_map = {}
#{(src,dst):{dpid:{port:[slot]}}}

road_map = {}
#{(src,dst):road[]}

barrier_map = {}
#{(src,dst):{dpid1:xid1,dpid2:xid2.....}]}

flow_map = {}
#{dpid:flow_mod}

cflow_map = {}
#{dpid:{(src,dst):cflow_mod}}

service_map = {}

switch_number = 8#switch_number is the number of links, both directions are included
switch_load = 1000#max load for a link(byte/s)

from pox.lib.addresses import EthAddr, IPAddr
#for static APR
ip_mac={IPAddr('192.85.1.1'):EthAddr('00:10:95:00:00:01'),
        IPAddr('192.85.1.3'):EthAddr('00:10:95:00:00:03'),
        IPAddr('192.0.1.1'):EthAddr('00:10:94:00:00:01'),
        IPAddr('192.0.1.3'):EthAddr('00:10:94:00:00:03')}
#for static host info(dpid,port)
ip_dpid_port = {'192.85.1.3':[3,2], '192.85.1.1':[3,2], 
                '192.0.1.1':[1,1],  '192.0.1.3':[1,1]}

#to get a range of ip-mac pairs
def get_mac(ip):
  string = ip.split('.')
  ip_to_int_3 = int(string[3])
  ip_to_int_2 = int(string[2])
  ip_to_int_1 = int(string[1])
  
  if ip_to_int_1 == 0:#192.'0'.1.1
    mac = '00:10:94'
  elif ip_to_int_1 == 85:#192.85.1.1
    mac = '00:10:95'
  
  #count
  mac_num_1 = hex(ip_to_int_3 - 1)
  mac_num_2 = hex(ip_to_int_2 - 1)
  mac = mac + ":00:" + str(mac_num_2) + ":" + str(mac_num_1)
  print mac
  return EthAddr(mac)
  

MAX = 65535
#every link's value for route
route_map = [[MAX,MAX,MAX,MAX,MAX],
             [MAX,0,1,MAX,2],
             [MAX,1,0,1,MAX],
             [MAX,MAX,1,0,2],
             [MAX,2,MAX,2,0],]
'''
route_map = [[MAX,MAX,MAX,MAX,MAX,MAX],
             [MAX,0,10,MAX,30,100],
             [MAX,10,0,50,MAX,MAX],
             [MAX,MAX,50,0,20,10],
             [MAX,30,MAX,20,0,60],
             [MAX,100,MAX,10,60,0],]
'''
        
if __name__ == '__main__':
  pass
