import tables
import copy
import socket
import libopenflow as of
import libopencflow as ofc

global src_dpid_port
src_dpid_port = []
global dst_dpid_port
dst_dpid_port = []

def Dj_route(src, dst, points):
  global src_dpid_port
  global dst_dpid_port
  #initialize the dpid-port info for src and dst hosts
  if src[0:5] == '192.0':
    src_dpid_port = [1,1]
    dst_dpid_port = [3,2]
  elif src[0:6] == '192.85':
    src_dpid_port = [3,2]
    dst_dpid_port = [1,1]
  #print src_dpid_port
  #print dst_dpid_port
  src_dpid = src_dpid_port[0]
  dst_dpid = dst_dpid_port[0]
  #src_dpid = tables.ip_dpid_port[src][0]
  #dst_dpid = tables.ip_dpid_port[dst][0]
  remain = points[:]
  remain.remove(src_dpid)
  pre = {}
  pre[1] = src_dpid
  dis = {}
  dis[1] = {}

  for i in remain:#initial the distance, from 1 to i
    dis[1][i] = tables.route_map[src_dpid][i]

  #decide the road
  for i in xrange(2, len(points)+1):
    MIN = tables.MAX
    #copy,for list:a = range(10),b = a[:]
    #for dict, dict2 = copy.deepcopy(dict1)
    dis[i] = copy.deepcopy(dis[i-1])
    for j in remain:
      if j in pre.itervalues():
        pass
      else:
        if MIN > dis[i-1][j]:
          MIN = dis[i-1][j]
          k = j
          pre[i] = j
    for j in remain:
      if dis[i-1][k] + tables.route_map[k][j] < dis[i-1][j]:
        dis[i][j] = dis[i-1][k] + tables.route_map[k][j]
  road = []
  road.append(dst_dpid)

  while dst_dpid != src_dpid:
    MIN = tables.MAX
    for k,v in dis.items():
      if MIN > v[dst_dpid]:
        MIN = v[dst_dpid]
        next = pre[k]
    road.append(next)
    dst_dpid = next
  return road

def add_link(src, dst, s_type):
  global src_dpid_port
  global dst_dpid_port
  points = []
  #pick the switches which could support related net, OTN-ONLY, IP-ONLY or both
  if s_type == '0':#both
    for k,v in tables.sock_dpid.items():
      if v[1] not in points:
        points.append(v[1])
  elif s_type == '1':#IP
    for k,v in tables.sock_dpid.items():
      if ((v[0] == 1) or (v[0] == 5)) and (v[1] not in points):
        points.append(v[1])
  elif s_type == '2':#OTN
    for k,v in tables.sock_dpid.items():
      if ((v[0] == 4) or (v[0] == 5)) and (v[1] not in points):
        points.append(v[1])

  if points == []:
    print "command error!could not initial a topomap!please re-input\n"
    return [],{},0

  else:
    road = Dj_route(src, dst, points)#Attention please, the road is from dst to src
    for k,v in tables.topo_map.items():
      if (k[0], k[2]) == (road[0], road[1]) or (k[2], k[0]) == (road[0], road[1]):
        route_type = v['type']
        if route_type == 0:
          name = 'IP'
        elif route_type == 1:
          name = 'OTN'
        print "route_type: ",name, "\n"#the type decides to send flow or cflow

    now_sock = {}#get the socket of switches that in road
    for k,v in tables.sock_dpid.items():
      if v[1] in road:
        now_sock[v[1]] = k
    print "the flow road is(from dst to src):", road, "\n"
    
    dst_ = dst_dpid_port[1]
    #dst_ = tables.ip_dpid_port[dst][1]
    link = {}
    for i in xrange(0, len(road)-1):
      for k,v in tables.topo_map.items():#find dst-port, src-port
        if (k[0], k[2]) == (road[i], road[i+1]):
          dst_port = k[1]
          src_port = k[3]
        elif (k[2], k[0]) == (road[i], road[i+1]):
          dst_port = k[3]
          src_port = k[1]
      link[road[i]] = [dst_port, dst_]
      dst_ = src_port
    
    dst_port = src_dpid_port[1]
    #dst_port = tables.ip_dpid_port[src][1]
    link[road[-1]] = [dst_port, dst_]
    print "switches' inport and outport(dpid, in, out):", link, "\n"
    return road, link, route_type

        
if __name__ == '__main__':
  pass
