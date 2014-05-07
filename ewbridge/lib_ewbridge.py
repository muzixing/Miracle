import sys
sys.path.append('/opt/local/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/site-packages/')
from scapy.all import *

"""
Author: muzi
Date: 2014/4/12

TODO:Defined the data structure of EWbridge.

"""

#uint8_t => XByteField
#uint16_t => ShortField, BitFieldLenField('name', None, 16, length_of='varfield'),BitField('name', None, 16)

#uint32_t => IntField, BitFieldLenField('name', None, 32, length_of='varfield'), BitFieldLenField('name', None, 32)



ofpew_type = {  0: "OFPEW_HELLO",   	 #Hello for negociating version.
				1: "OFPEW_ERROR",   
				2: "OFPEW_ECHO_REQUEST", #For KEEP_ALIVE
            	3: "OFPEW_ECHO_REPLY",   
            	4: "OFPEW_VENDOR",       #Info of vendor,can be use for extension.
            	5: "OFPEW_UPDATE",		 #Notification of changing topo or other messenge.
            	6: "OFPEW_NOTIFICATION", #Using for notification.
            	7: "OFPEW_REFRESH_VIEW",     #To get the topo messenge.
            	8: "OFPEW_GOING_DOWN",	 #Notification of going down.
          	  }

ofpew_error_type = {  	0: "OFPEW_HELLO_FAILED",		#veision negociating failed.
                   	  	1: "OFPEW_BAD_REQUEST",			#No surpport request.
                   	  	2: "OFPEW_DOWN",				#The peer is down
                   	   	3: "OFPEW_PERMISSION_DENIED",	
                	}

ofpew_notification_type = {	0: "NO_DEFINED",
						  }                

ofpew_hello_failed_code = { 0: "OFPEWHFC_INCOMPATIBLE", #same mean as ofp.
                          	1: "OFPEWHFC_EPERM",
                          }

ofpew_bad_request_code = {  0: "OFPEWBRC_BAD_VERSION",
                         	1: "OFPEWBRC_BAD_TYPE",
                         	2: "OFPEWBRC_BAD_VENDOR",
                         	3: "OFPEWBRC_BAD_SUBTYPE",
                         	4: "OFPEWBRC_BAD_LEN",
                         	5: "OFPEWBRC_UNKNOWN",
                       	}

ofpew_down_code = { 0: "OFPEWHFC_UNREACHED", 
                  }

ofpew_permission_denied_code = {  	0: "OFPEWHF_PERMISSION_DENIED", 
                          		}             

ofpew_down_reason = {	0: "OFP_POWER_OFF",
						1: "OFP_RESTART",
						2: "OFP_CRASH",
					}

ofpew_entity_type = {	0: "OFPEW_PHYSICAL",
						1: "OFPEW_VIRTUAL",
					}

ofpew_version = {	0: "1.0",
					1: "1.1",
					2: "1.2",
					3: "1.3",
					4: "1.4",
				}

ofpew_is_edge = {	0: "Normal",
					1: "is_edge",
				}

ofpew_active = {	0: "active",
					1: "NO_DEFINED",
				}				

################################
# OpenFlow EWbridge Header #
################################
#type = 0
#length =8bytes.
class ofpew_header(Packet):     
    name = "OpenFlow_EWbridge Header "
    fields_desc=[ XByteField("version", 1),
                  ByteEnumField("type", 0, ofpew_type),
                  ShortField("length", 8),
                  IntField("xid", 1) ]     


################################
# OpenFlow EWbridge Messages #
################################

#type = 1
#length =12bytes.
class ofpew_error_msg(Packet):
    name = "OpenFlow_EWbridge Error Message"
    fields_desc=[ ShortEnumField("type", 0, ofpew_error_type),
                  ShortField("code", 0),                       #need to parse with type field, use another function
                  StrFixedLenField("data", None, length=8)]
bind_layers( ofpew_header, ofpew_error_msg, type=1 )

#type =2

#no messenge body but only type.

#type =3

#the same as the request.

#type=4
#length =8bytes.
class ofpew_vendor(Packet):
  name = "OpenFlow_EWbridge vendor"
  fields_desc=[ BitField("vendor", 0, 32),
  				BitField("pad", 0, 32),#padding for 64bits.
  				]

#type = 5
#length =8bytes.
class ofpew_update(Packet):
	name = "OpenFlow_EWbridge update"
	fields_desc = [	BitField("network_number", 0, 32),
					BitField("pad", 0, 32),#padding for 64bits.
					]

#type =6
#length =4bytes.
class ofpew_notification(Packet):
	name = "OpenFlow_EWbridge notification"
	fields_desc = [	#still no messenge
					ByteEnumField("notice_type", 0, ofpew_notification_type),
					X3BytesField("pad", 0),

					#With some body we haven't defined yet.
					]		
#type = 7					
#ofpew_refresh_view  without any body. Just has a header. 

#type = 8
#length =4bytes.
class ofpew_going_down(Packet):
	name = "OpenFlow_EWbridge going_down"
	fields_desc = [	ByteEnumField("reason", 0, ofpew_down_reason),
					X3BytesField("pad", 0),  #padding for 64bits.
					]					

########################################

#Network veiw messenge body.

########################################

#length =16bytes.
class ofpew_network_view(Packet):     
	name = "OpenFlow_EWbridge network view"
	fields_desc = [	BitField("node_number", 0 ,32),
					BitField("link_number", 0 ,32),
					BitField("port_number", 0 ,32),
					BitField("flow_path_number", 0 ,32),
					#we can add more type information of network view.
					]

#length =28bytes.
class ofpew_node(Packet):
	name = "OpenFlow_EWbridge node"
	fields_desc = [	BitField('datapath_id', None, 64),
					ByteEnumField("type", 0 , ofpew_entity_type),
					X3BytesField("pad", 0),
					IPField("ip","0.0.0.0"),
					MACField("hw_addr", "00:00:00:00:00:00"),
					BitField("port_number", 0, 32),  				#just the number of port in using ,not all port's number.
					ByteEnumField("of_version", 0 , ofpew_version),
					ByteEnumField("is_edge", 0 , ofpew_is_edge),
					#Others
					]	

#length =36bytes.
class ofpew_port(Packet):
	name = "OpenFlow_EWbridge port"
	fields_desc = [	
					BitField('port_id', None, 64),
					ByteEnumField("type", 0 , ofpew_entity_type),
					X3BytesField("pad", 0),
					BitField("node_id", None , 64),
					IPField("ip", "0.0.0.0"),  #if it has a ip.
					MACField("hw_addr", "00:00:00:00:00:00"),
					ByteEnumField("active", 0, ofpew_active),
					ByteEnumField("is_edge", 0, ofpew_entity_type),
					ShortField("dl_vlan", 0xffff),   
					BitField("pad", 0, 16),  #padding for 32bits.
					# others
					]						

#length =48bytes.					
class ofpew_link(Packet):
	name = "OpenFlow_EWbridge link"
	fields_desc = [	BitField('link_id', 0, 64),
					ByteEnumField("type", 0 , ofpew_entity_type),				
					ByteEnumField("is_interdomain_link", 0, ofpew_entity_type),
					BitField("pad", 0, 16),
					BitField("src_node_id", None , 64),
					BitField('src_port_id', None, 64),
					BitField("dst_node_id", None , 64),
					BitField('dst_port_id', None, 64),
					BitField("bandwidth", 0 ,32),
					
					#others

					]			
#length =60bytes.
class ofpew_flow_path(Packet):
	name = "OpenFlow_EWbridge flow_path"
	fields_desc = [	BitField('flow_path_id', 0, 64),
					ByteEnumField("type", 0 , ofpew_entity_type),
					X3BytesField("pad", 0), #padding for 32bits.
					#the start point.
					BitField('src_in_port_id', None, 64),
					BitField('src_node_id', None, 64),
					BitField('src_out_port_id', None, 64),
					#the end point.
					BitField('dst_in_port_id', None, 64),
					BitField('dst_node_id', None, 64),
					BitField('dst_out_port_id', None, 64),
					#others
					]			

