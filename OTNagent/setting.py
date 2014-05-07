from scapy.all import *
import MySetting as M

class  sw():
	def __init__(self,sw_type, sw_no):
		self.sw_type = sw_type
		self.sw_no = sw_no
		if sw_no not in self.sw_type:
			sw_no = 1
		self.type_otn = sw_type[sw_no][0]
		self.type_wave = sw_type[sw_no][1]
		self.type_ip = sw_type[sw_no][2]


class  MyPort():
	def __init__(self, f, wave, sw_no, port_no):
		self.f = f
		self.wave =wave
		self.sw_no = sw_no
		self.port_no = port_no
		if port_no not in self.f[sw_no]:
			port_no = 65534   #default
#####################port_info##########################
		self.OFPST_FIBER = f[sw_no][port_no][0]     
		self.OFPST_WAVE = f[sw_no][port_no][1]      
		self.OFPST_T_OTN = f[sw_no][port_no][2]     
		self.OFPST_T_SDH = f[sw_no][port_no][3]     
		self.OFPST_T_SONET = f[sw_no][port_no][4]   
		self.OFPST_ETH = f[sw_no][port_no][5]       
		self.OFPST_VLAN = f[sw_no][port_no][6]      
		self.OFPST_MPLS = f[sw_no][port_no][7]      
		self.OFPST_IP = f[sw_no][port_no][8]        
		self.OFPST_L4 = f[sw_no][port_no][9]      
		self.SUPP_SW_GRAN = f[sw_no][port_no][10]  
		self.sup_sdh_port_bandwidth = f[sw_no][port_no][11]
		self.sup_otn_port_bandwidth = f[sw_no][port_no][12]
		self.peer_port_no = f[sw_no][port_no][13]
		self.peer_datapath_id = f[sw_no][port_no][14]

#######################wave sw##########################
		self.center_freq_lmda = wave[sw_no][port_no][0]
		self.num_lmda = wave[sw_no][port_no][1]
		self.freq_space_lmda = wave[sw_no][port_no][2]
########################################################
def creat_port(sw_no, port_no):
	return MyPort(M.features, M.f_wave, sw_no, port_no)
def creat_sw(sw_no):
	return sw(M.sw_type, sw_no)
########################################################
if __name__ == '__main__':
	pass