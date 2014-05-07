import libopenflow as of
def send(Type, flow_1, port =None):
    flow =str(flow_1)
    ofp_flow_wildcards=of.ofp_flow_wildcards(flow[8:12])
    ofp_match =of.ofp_match(flow[12:48])
    ofp_flow_mod =of.ofp_flow_mod(flow[48:72])
    if len(flow)>=88:
        action_header = of.ofp_action_header(flow[72:80])
        action_output = of.ofp_action_output(flow[80:88])
    #we need to send the stats request packets periodically
    msg = { 0: of.ofp_header(type = 16, length = 12)/of.ofp_stats_request(type = 0),                            #Type of  OFPST_DESC (0) 
            1: of.ofp_header(type = 16, length = 56)/of.ofp_stats_request(type =1)/ofp_flow_wildcards/ofp_match/of.ofp_flow_stats_request(out_port = ofp_flow_mod.out_port),                  #flow stats
            2: of.ofp_header(type = 16, length =56)/of.ofp_stats_request(type = 2)/ofp_flow_wildcards/ofp_match/of.ofp_aggregate_stats_request(),                                  # aggregate stats request
            3: of.ofp_header(type = 16, length = 12)/of.ofp_stats_request(type = 3),                            #Type of  OFPST_TABLE (0) 
            4: of.ofp_header(type = 16, length =20)/of.ofp_stats_request(type = 4)/of.ofp_port_stats_request(port_no = port),   # port stats request    
            5: of.ofp_header(type = 16, length =20)/of.ofp_stats_request(type =5)/of.ofp_queue_stats_request(), #queue request
            6: of.ofp_header(type = 16, length = 12)/of.ofp_stats_request(type = 0xffff)                        #vendor request
        }
    return msg[Type]