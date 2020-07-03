module FlowMeter;

export {
    # Create an ID for the new Log stream
    redef enum Log::ID += { LOG };

    # define a record to hold all the calculate statistical values of a vector
    type statistics_info: record {
        min: double &log;
        max: double &log;
        tot: double &log;
        avg: double &log;
        std: double &log;
    };

    # Define the datarecord which should be saved to the Log File
    type Features: record {
        uid:               string  &log;
        flow_duration:     interval &log;
        fwd_pkts_tot:      count &log;
        bwd_pkts_tot:      count &log;
        fwd_data_pkts_tot: count &log;
        bwd_data_pkts_tot: count &log;
        fwd_pkts_per_sec:  double &log;
        bwd_pkts_per_sec:  double &log;
        flow_pkts_per_sec: double &log;
        down_up_ratio:     double &log;
        fwd_header_size_tot:    count &log;
        fwd_header_size_min:    count &log;
        fwd_header_size_max:    count &log;
        bwd_header_size_tot:    count &log;
        bwd_header_size_min:    count &log;
        bwd_header_size_max:    count &log;
        flow_FIN_flag_count:    count &log;
        flow_SYN_flag_count:    count &log;
        flow_RST_flag_count:    count &log;
        fwd_PSH_flag_count:    count &log;
        bwd_PSH_flag_count:    count &log;
        flow_ACK_flag_count:    count &log;
        fwd_URG_flag_count:    count &log;
        bwd_URG_flag_count:    count &log;
        flow_CWR_flag_count:    count &log;
        flow_ECE_flag_count:    count &log;
        fwd_pkts_payload:  FlowMeter::statistics_info &log;
        bwd_pkts_payload:  FlowMeter::statistics_info &log;
        flow_pkts_payload: FlowMeter::statistics_info &log;
        fwd_iat:           FlowMeter::statistics_info &log;
        bwd_iat:           FlowMeter::statistics_info &log;
        flow_iat:          FlowMeter::statistics_info &log;
        payload_bytes_per_second:  double &log;
        fwd_subflow_pkts:  double &log;
        bwd_subflow_pkts:  double &log;
        fwd_subflow_bytes: double &log;
        bwd_subflow_bytes: double &log;
        fwd_bulk_bytes:    double &log;
        bwd_bulk_bytes:    double &log;
        fwd_bulk_packets:  double &log;
        bwd_bulk_packets:  double &log;
        fwd_bulk_rate:     double &log;
        bwd_bulk_rate:     double &log;
        active:            FlowMeter::statistics_info &log;
        idle:              FlowMeter::statistics_info &log;
        fwd_init_window_size: count &log;
        bwd_init_window_size: count &log;
        fwd_last_window_size: count &log;
        bwd_last_window_size: count &log;
    };
}

# double table to map the uid and fwd/bwd to the count holding the packet count for that uid and direction
global packet_count: table[string] of table[string] of count;
# double table to map the uid and the flag name to the count holding the count of that flag type for that uid
global flag_count: table[string] of table[string] of count;
# double table to map the uid and the direction combined with the operation to the count holding the header size info for that uid
global header_count: table[string] of table[string] of count;
# double table to map the uid and the direction combined with the operation to the count holding the header size info for that uid
global data_packet_count: table[string] of table[string] of count;
# double table to map the uid and the fwd/bwd to the vector holding the different payload sizes for that uid and direction
global payload_vector: table[string] of table[string] of vector of count;
# double table to map the uid and the fwd/bwd to the vector holding the time of the previous packet
global last_packet_time: table[string] of table[string] of time;
# table to map uid to the number of subflows for that uid
global num_subflows: table[string] of count;
# table to map uid to the bool showing if are currently in a new active phase
global new_active_phase: table[string] of bool;
# table to map uid to a vector containing the length of all active phases
global active_vector: table[string] of vector of double;
# table to map uid to a vector containing all idle phases
global idle_vector: table[string] of vector of double;
# double table to map the uid and the fwd/bwd/flow to the vector of IAT of the packets for that uid and direction
global iat_vector: table[string] of table[string] of vector of double;
# double table to map the uid and the fwd/bwd to the number of bulk packets for that uid and direction
global bulk_counter:table[string] of table[string] of count;
# double table to map the uid and the fwd/bwd to the number of bulk bytes for that uid and direction
global bulk_bytes: table[string] of table[string] of count;
# double table to map the uid and the fwd/bwd to the number of bulk packets for that uid and direction
global bulk_packets: table[string] of table[string] of count;
# double table to map the uid and the fwd/bwd to the duration of bulk transmissions for that uid and direction
global bulk_time: table[string] of table[string] of double;
# table to map the uid to a bool which keeps track if the previous packet was in the fwd direction
global previous_was_fwd: table[string] of bool;
# double table to map the uid and fwd/bwd to the size of the first and last  window size seen for that uid and direction
global window_size: table[string] of table[string] of count;



# definition of the bitmasks for testing if a flag is set
const  FIN=1;
const  SYN=2;
const  RST=4;
const  PSH=8;
const  ACK=16;
const  URG=32;
const  ECE=64;
const  CWR=128;

# constant defining the maximum iat between two packets before they are counted to different subflows
const subflow_max_iat = 1 sec &redef;

# constant defining the maximum IAT between two packets so that they are still considered to be part of the same active phase
const active_timeout = 5 sec &redef;

# constant defining the maximum IAT between two packets so that they are still considered to be part of the same bulk transmission
const bulk_timeout = 1 sec &redef;

# constant defining the minimal number of packets which have to be transmitted to count as a bulk transmission
const bulk_min_length = 5 &redef;

# struct to hold the calculation from the IAT, using a record as this allows to test for the existence of the value
type inter_arrival_time: record {
    fwd: interval &optional;
    bwd: interval &optional;
    flow: interval &optional;
};

# function to calculate the inter arrival times
# warning: this function relies on the timestamps stored in last_packet_time to get the time of the previous packets,
#          so don't update them before calling this function and this function does NOT update them so this has to be
#          done separately!
# uid: the id string of the current flow
# returns: return an inter_arrival_time record where fwd is the IAT of the current packet and the last fwd packet,
#          bwd is the IAT of the last bwd packet and the current packet and flow is the IAT of the last packet and this packet.
function calculate_iat(uid: string): FlowMeter::inter_arrival_time {
    local iat = FlowMeter::inter_arrival_time();

    # check if previously already a fwd packet has been seen, if yes calcualte the IAT between this packet and the last fwd packet
    if("fwd" in last_packet_time[uid]){
        iat$fwd = network_time() - last_packet_time[uid]["fwd"];
    }

    # check if previously already a bwd packet has been seen, if yes calcualte the IAT between this packet and the last bwd packet
    if ( "bwd" in  last_packet_time[uid]){
        iat$bwd = network_time() - last_packet_time[uid]["bwd"];
    }

    # if an IAT for both direction exist keep the smaller one as flow IAT, else keep which ever exists
    if (iat?$fwd && iat?$bwd){
        iat$flow = iat$fwd > iat$bwd ? iat$bwd : iat$fwd;
    }
    else if( iat?$fwd){
        iat$flow=iat$fwd;
    }
    else if( iat?$bwd){
        iat$flow=iat$bwd;
    }

    return iat;
}

# function to check if the passed flag is set
# flag: bitmask of the flag to check
# p:    the packet headers (pkt_hdr object)
# returns: True if the flag is set False otherwise
function is_flag_set( p:pkt_hdr, flag: count ): bool{
    return ( p$tcp$flags & flag >0);
}

# function to perform the statistical analysis of a vector of counts
# vec: vector containing counts which should be analysed
# returns: FlowMeter::statistics_info containing the measures if the vector has length 0 all values will be 0
function generate_stats_count(vec: vector of count): FlowMeter::statistics_info{
    local stat = FlowMeter::statistics_info($min=0, $max=0, $tot=0, $avg=0, $std=0);
    # get the length of the vector
    local len = |vec|;

    # if the vector is empty return the 0 statistics
    if( len == 0){
        return stat;
    }

    # initialize the min value with the first entry, otherwise it would be stuck at 0
    stat$min=vec[0];

    # loop over the vector and get the sum, max and min of the vector
    for (p in vec){
        stat$tot += vec[p];
        if (vec[p] < stat$min){
            stat$min = vec[p];
        }
        if (vec[p] > stat$max){
            stat$max = vec[p];
        }
    }

    # calculate the mean
    stat$avg = stat$tot / len;

    # if the len is 1 the standard deviation can not be calculated return with it set to 0
    if( len ==1){
        return stat;
    }

    # calculate the std dev
    local div_from_mean: double;
    for (p in vec){
        div_from_mean=vec[p]-stat$avg;
        stat$std += div_from_mean * div_from_mean;
    }
    stat$std = stat$std/(len-1);
    stat$std = sqrt(stat$std);

    return stat;
}

# function to perform the statistical analysis of a vector of doubles
# vec: vector containing doubles which should be analysed
# returns: FlowMeter::statistics_info containing the measures if the vector has length 0 all values will be 0
function generate_stats_double(vec: vector of double): FlowMeter::statistics_info{
    local stat = FlowMeter::statistics_info($min=0, $max=0, $tot=0, $avg=0, $std=0);
    # get the length of the vector
    local len = |vec|;

    # if the vector is empty return the 0 statistics
    if( len == 0){
        return stat;
    }

    # initialize the min value with the first entry, otherwise it would be stuck at 0
    stat$min=vec[0];

    # loop over the vector and get the sum, max and min of the vector
    for (p in vec){
        stat$tot += vec[p];
        if (vec[p] < stat$min){
            stat$min = vec[p];
        }
        if (vec[p] > stat$max){
            stat$max = vec[p];
        }
    }

    # calculate the mean
    stat$avg = stat$tot / len;

    # if the len is 1 the standard deviation can not be calculated return with it set to 0
    if( len ==1){
        return stat;
    }

    # calculate the std dev
    local div_from_mean: double;
    for (p in vec){
        div_from_mean=vec[p]-stat$avg;
        stat$std += div_from_mean * div_from_mean;
    }
    stat$std = stat$std/(len-1);
    stat$std=sqrt(stat$std);

    return stat;
}

# at the startup of zeek create the Log stream
event zeek_init() &priority=5 {
    Log::create_stream(FlowMeter::LOG, [$columns=Features, $path="flowmeter"]);
}

# update the measures for each new packet
event new_packet (c: connection, p: pkt_hdr) {

    # set bool if this packet is moving in the fwd direction
    local is_fwd = (p?$ip && p$ip$src == c$id$orig_h || p?$ip6 &&p$ip6$src == c$id$orig_h);
    # bool is true if this packet is tcp
    local is_tcp = p?$tcp;
    # bool is true if this packet is udp
    local is_udp = p?$udp;
    # bool is true if this packet is icmp
    local is_icmp = p?$icmp;
    # bool is true if this packet is icmp
    local is_ip6 = p?$ip6;

    # check if the table entries for that uid already exist, if not create them
    if (!(c$uid in packet_count)){
       packet_count[c$uid] = table(["fwd"]=0, ["bwd"]=0);
    }
    if (!(c$uid in flag_count)){
        flag_count[c$uid] = table(["FIN"]=0, ["SYN"]=0, ["RST"]=0, ["fwd,PSH"]=0, ["bwd,PSH"]=0, ["ACK"]=0, ["fwd,URG"]=0, ["bwd,URG"]=0, ["ECE"]=0, ["CWR"]=0);
    }
    if (!(c$uid in header_count)){
       header_count[c$uid] = table(["fwd,tot"]=0, ["fwd,min"]=0, ["fwd,max"]=0, ["bwd,tot"]=0, ["bwd,min"]=0, ["bwd,max"]=0);
    }
    if (!(c$uid in payload_vector)){
       payload_vector[c$uid] = table(["fwd"]=vector(), ["bwd"]=vector() );
    }
    if (!(c$uid in data_packet_count)){
       data_packet_count[c$uid] = table(["fwd"]=0, ["bwd"]=0 );
    }
    # initialising the table as empty allows to test if a packet in fwd resp bwd direction has already been seen
    if (!(c$uid in last_packet_time) ){
       last_packet_time[c$uid] = table();
    }
    # initialize the subflow with 1, as the first packet starts the first subflow
    if (!(c$uid in num_subflows) ){
       num_subflows[c$uid] = 1;
    }
    # start out with an active phase as we have received a package
    if (!(c$uid in new_active_phase) ){
       new_active_phase[c$uid] = T;
    }
    if (!(c$uid in active_vector) ){
       active_vector[c$uid] = vector();
    }
    if (!(c$uid in idle_vector) ){
       idle_vector[c$uid] = vector();
    }
    if (!(c$uid in iat_vector) ){
       iat_vector[c$uid] = table(["fwd"]=vector(), ["bwd"]=vector(), ["flow"]=vector());
    }
    if (!(c$uid in bulk_counter) ){
       bulk_counter[c$uid] = table(["fwd"]=0, ["bwd"]=0);
    }
    if (!(c$uid in bulk_bytes) ){
       bulk_bytes[c$uid] = table(["fwd"]=0, ["fwd,tmp"]=0, ["bwd"]=0, ["bwd,tmp"]=0);
    }
    # initialize them here with 0 as previously no packet has been seen
    if (!(c$uid in bulk_packets) ){
       bulk_packets[c$uid] = table(["fwd"]=0, ["fwd,tmp"]=0, ["bwd"]=0, ["bwd,tmp"]=0);
    }
    if (!(c$uid in bulk_time) ){
       bulk_time[c$uid] = table(["fwd"]=0.0, ["fwd,tmp"]=0.0, ["bwd"]=0.0, ["bwd,tmp"]=0.0);
    }
    if (!(c$uid in previous_was_fwd) ){
       previous_was_fwd[c$uid] = F;
    }
    # start with a window size of 0
    if (!(c$uid in window_size) ){
       window_size[c$uid] = table(["init,fwd"]=0, ["last,fwd"]=0, ["init,bwd"]=0, ["last,bwd"]=0);
    }

    # if the packet is moving in the fwd direction increase the fwd packet counter
    if ( is_fwd ){
        ++packet_count[c$uid]["fwd"];
    }
    # otherwise increase the bwd packet counter
    else {
        ++packet_count[c$uid]["bwd"];
    }

    #initialize header size to 0
    local header_size = 0;
    # if it is a tcp packet get the header size from the tcp header
    if( is_tcp ){
        header_size = p$tcp$hl;
    }
    # udp and icmp have a fixed header length of 8
    if( is_udp || is_icmp){
        header_size = 8;
    }

    # if the packet is moving in the fwd direction add the header size to the fwd header counter
    if( is_fwd ){
        header_count[c$uid]["fwd,tot"] += header_size;

        # if the current header size is smaller or if no header has yet been added (size == 0) than the stored min, then update it
        if(header_count[c$uid]["fwd,min"] > header_size || header_count[c$uid]["fwd,min"]==0){
            header_count[c$uid]["fwd,min"] = header_size;
        }
        # if the current header is larger then the stored max, then update it
        if(header_count[c$uid]["fwd,max"] < header_size){
            header_count[c$uid]["fwd,max"] = header_size;
        }
    }
    # otherwise add the current header size to the bwd header counter
    else{
        header_count[c$uid]["bwd,tot"] += header_size;
        # if the current header size is smaller or if no header has yet been added (size == 0) than the stored min, then update it
        if(header_count[c$uid]["bwd,min"] > header_size || header_count[c$uid]["bwd,min"]==0){
            header_count[c$uid]["bwd,min"] = header_size;
        }
        # if the current header is larger then the stored max, then update it
        if(header_count[c$uid]["bwd,max"] < header_size){
            header_count[c$uid]["bwd,max"] = header_size;
        }
    }

    # initialize the payload size to 0
    local data_size = 0;

    # if it is an ip6 packet take the payload size of the ip6 packet and subtract the header size of the encapsulated protocol
    if( is_ip6 ){
        data_size = p$ip6$len - header_size;
    }
    # if it is an ip4 packet take the packet size of the ip4 packet and subtract the ip4 header size and the header size of the encapsulated protocol
    else{
        data_size = p$ip$len - p$ip$hl - header_size;
    }
    # if the packet is moving in the fwd direction add the data size to the fwd vector
    if ( is_fwd ){
        payload_vector[c$uid]["fwd"] += data_size;
        if(data_size > 0){
            ++data_packet_count[c$uid]["fwd"];
        }
    }
    # otherwise add it to the bwd vector
    else {
        payload_vector[c$uid]["bwd"] += data_size;
        if(data_size > 0){
            ++data_packet_count[c$uid]["bwd"];
        }
    }

    # if this is a tcp packet increase the flag counter of all flags, which are set
    if( is_tcp ){
        if( is_flag_set(p, FIN) ){
            ++flag_count[c$uid]["FIN"];
        }
        if(is_flag_set(p, SYN) ){
            ++flag_count[c$uid]["SYN"];
        }
        if(is_flag_set(p, PSH) ){
            if( is_fwd){
                ++flag_count[c$uid]["fwd,PSH"];
            }
            else{
                ++flag_count[c$uid]["bwd,PSH"];
            }
        }
        if(is_flag_set(p, ACK) ){
            ++flag_count[c$uid]["ACK"];
        }
        if(is_flag_set(p, URG) ){
            if( is_fwd){
                ++flag_count[c$uid]["fwd,URG"];
            }
            else{
                ++flag_count[c$uid]["bwd,URG"];
            }
        }
        if(is_flag_set(p, ECE) ){
            ++flag_count[c$uid]["ECE"];
        }
        if(is_flag_set(p, CWR) ){
            ++flag_count[c$uid]["CWR"];
        }
        if(is_flag_set(p, RST) ){
            ++flag_count[c$uid]["RST"];
        }
    }


    # calculate the IAT of this packet
    local iat = calculate_iat(c$uid);

    # test if already other packets have been seen in this flow and thus the flow IAT could be calculated
    if( iat?$flow){

        # if the packet has a IAT of more than subflow_max_iat consider it a new subflow. -> increase the subflow counter
        if( iat$flow > subflow_max_iat){
            ++num_subflows[c$uid];
        }

        # if the packet has a IAT of more than active_timeout we have an idle phase behind us -> add the flow IAT as new entry
        # to the idle_vector vector. Set the new_active_phase to true as we are now in a new active phase. We can not yet
        # create a new entry for the new active phase, as we don't want to have 0 duration entries for the active phase
        # multiply the IAT by 1000000 to get its value in microsecond
        if (iat$flow > active_timeout){
            idle_vector[c$uid] += (|iat$flow| * 1000000.0);
            new_active_phase[c$uid] = T;
        }
        # if we have received the second packet in this active phase we create an new entry in the active_vector vector, which
        # we set to the value of the IAT of the current packet. new_active_phase we set to false as it is now not a new active
        # phase any more.
        # multiply the IAT by 1000000 to get its value in microsecond
        else if(new_active_phase[c$uid]){
            active_vector[c$uid] += (|iat$flow| * 1000000.0);
            new_active_phase[c$uid] = F;
        }
        # if it is not a new active phase then add the IAT of the current packet to the value of the last active phase
        # multiply the IAT by 1000000 to get its value in microsecond
        else{
            active_vector[c$uid][|active_vector[c$uid]|-1] += |iat$flow| * 1000000.0;
        }

        # add the flow IAT, after converting it to microseconds, to the flow IAT vector
        iat_vector[c$uid]["flow"] += |iat$flow| * 1000000.0;
    }

    # if this packet is in fwd direction and not the first packet in fwd direction and thus fwd IAT exists,
    # add the fwd IAT, after converting it to microseconds, to the fwd IAT vector
    if( is_fwd && iat?$fwd){
        iat_vector[c$uid]["fwd"] += |iat$fwd| * 1000000.0;
    }


    # if this packet is in bwd direction and not the first packet in bwd direction and thus bwd IAT exists,
    # add the bwd IAT, after converting it to microseconds, to the bwd IAT vector
    if( !is_fwd && iat?$bwd){
        iat_vector[c$uid]["bwd"] += |iat$bwd| * 1000000.0;
    }

    # only consider packets with data for the bulk transmission
    if(data_size > 0){
        if( is_fwd){
            # if the previous packet was fwd as this one, the new might be part of a bulk transmission
            if(previous_was_fwd[c$uid]){
                # check if the packets are not spaced further apart as bulk_timeout, as we otherwise don't consider them a bulk transmission
                if(iat?$fwd && iat$fwd < bulk_timeout){
                    # we are currently in a possible bulk transmission, update the values of the current possible bulk transmission
                    ++bulk_packets[c$uid]["fwd,tmp"];
                    bulk_bytes[c$uid]["fwd,tmp"] += data_size;
                    bulk_time[c$uid]["fwd,tmp"] += |iat$fwd|;
                }
                # the new packet arrived later than bulk_timeout thus this terminates the possible previous bulk transmission
                else{
                    # see if we saw at least bulk_min_length packets in the previous possible bulk transmission
                    # if yes it was actually a bulk transmission -> update the main values of bulk
                    # as the previous direction was fwd we only have to check the fwd direction
                    if(bulk_packets[c$uid]["fwd,tmp"] >= bulk_min_length){
                        ++bulk_counter[c$uid]["fwd"];
                        bulk_packets[c$uid]["fwd"] += bulk_packets[c$uid]["fwd,tmp"];
                        bulk_bytes[c$uid]["fwd"] += bulk_bytes[c$uid]["fwd,tmp"];
                        bulk_time[c$uid]["fwd"] += bulk_time[c$uid]["fwd,tmp"];
                    }
                    # reset the tracking parameters for possible fwd bulk transmissions
                    # we already saw one possible packet in this transmission the current one
                    bulk_packets[c$uid]["fwd,tmp"] = 1;
                    bulk_bytes[c$uid]["fwd,tmp"] = data_size;
                    # but since this is the first packet in the bulk transmission, the duration of it is 0
                    bulk_time[c$uid]["fwd,tmp"] = 0.0;
                }
            }
            # the previous packet was in the other direction (bwd)
            else{
                # see if we saw at least bulk_min_length packets in the previous possible bulk transmission
                # if yes it was actually a bulk transmission -> update the main values of bulk
                # as the previous direction was bwd we only have to check the bwd direction
                if(bulk_packets[c$uid]["bwd,tmp"] >= bulk_min_length){
                    ++bulk_counter[c$uid]["bwd"];
                    bulk_packets[c$uid]["bwd"] += bulk_packets[c$uid]["bwd,tmp"];
                    bulk_bytes[c$uid]["bwd"] += bulk_bytes[c$uid]["bwd,tmp"];
                    bulk_time[c$uid]["bwd"] += bulk_time[c$uid]["bwd,tmp"];
                }
                # reset the tracking parameters for possible fwd bulk transmissions
                # we already saw one possible packet in this transmission the current one
                bulk_packets[c$uid]["fwd,tmp"] = 1;
                bulk_bytes[c$uid]["fwd,tmp"] = data_size;
                # but since this is the first packet in the bulk transmission, the duration of it is 0
                bulk_time[c$uid]["fwd,tmp"] = 0.0;
            }
            # mark that the packet was in fwd direction so we can check if the next packet is also in fwd direction
            previous_was_fwd[c$uid] = T;
        }
        else{
            # if the previous packet was also bwd, as this one, the new packet might be part of a bulk transmission
            if(!previous_was_fwd[c$uid]){
                # check if the packets are not spaced further apart as bulk_timeout, as we otherwise don't consider them a bulk transmission
                if(iat?$bwd && iat$bwd < bulk_timeout){
                    # we are currently in a possible bulk transmission, update the values of the current possible bulk transmission
                    ++bulk_packets[c$uid]["bwd,tmp"];
                    bulk_bytes[c$uid]["bwd,tmp"] += data_size;
                    bulk_time[c$uid]["bwd,tmp"] += |iat$bwd|;
                }
                # the new packet arrived later than bulk_timeout thus this terminates the possible previous bulk transmission
                else{
                    # see if we saw at least bulk_min_length packets in the previous possible bulk transmission
                    # if yes it was actually a bulk transmission -> update the main values of bulk
                    # as the previous direction was bwd we only have to check the bwd direction
                    if(bulk_packets[c$uid]["bwd,tmp"] >= bulk_min_length){
                        ++bulk_counter[c$uid]["bwd"];
                        bulk_packets[c$uid]["bwd"] += bulk_packets[c$uid]["bwd,tmp"];
                        bulk_bytes[c$uid]["bwd"] += bulk_bytes[c$uid]["bwd,tmp"];
                        bulk_time[c$uid]["bwd"] += bulk_time[c$uid]["bwd,tmp"];
                    }
                    # reset the tracking parameters for possible fwd bulk transmissions
                    # we already saw one possible packet in this transmission the current one
                    bulk_packets[c$uid]["bwd,tmp"] = 1;
                    bulk_bytes[c$uid]["bwd,tmp"] = data_size;
                    # but since this is the first packet in the bulk transmission, the duration of it is 0
                    bulk_time[c$uid]["bwd,tmp"] = 0.0;
                }
            }
            # the previous packet was in the other direction (fwd)
            else{
                # see if we saw at least bulk_min_length packets in the previous possible bulk transmission
                # if yes it was actually a bulk transmission -> update the main values of bulk
                # as the previous direction was fwd we only have to check the fwd direction
                if(bulk_packets[c$uid]["fwd,tmp"] >= bulk_min_length){
                    ++bulk_counter[c$uid]["fwd"];
                    bulk_packets[c$uid]["fwd"] += bulk_packets[c$uid]["fwd,tmp"];
                    bulk_bytes[c$uid]["fwd"] += bulk_bytes[c$uid]["fwd,tmp"];
                    bulk_time[c$uid]["fwd"] += bulk_time[c$uid]["fwd,tmp"];
                }
                # reset the tracking parameters for possible fwd bulk transmissions
                # we already saw one possible packet in this transmission the current one
                bulk_packets[c$uid]["bwd,tmp"] = 1;
                bulk_bytes[c$uid]["bwd,tmp"] = data_size;
                # but since this is the first packet in the bulk transmission, the duration of it is 0
                bulk_time[c$uid]["bwd,tmp"] = 0.0;
            }
            # mark that the packet was in bwd direction so we can check if the next packet is also in bwd direction
            previous_was_fwd[c$uid] = F;
        }
    }
    # if we have not yet seen a window size (init_window_size == 0) and the current packet is a tcp packet and
    # is in fwd direction update the fwd window size
    if( is_tcp && is_fwd ){
        if(packet_count[c$uid]["fwd"] ==1 ){
            window_size[c$uid]["init,fwd"] = p$tcp$win;
        }
        window_size[c$uid]["last,fwd"] = p$tcp$win;
    }
    # if we have not yet seen a window size (init_window_size == 0) and the current packet is a tcp packet and
    # is in bwd direction update the bwd window size
    if( is_tcp && !is_fwd ){
        if(packet_count[c$uid]["bwd"] ==1 ){
            window_size[c$uid]["init,bwd"] = p$tcp$win;
        }
        window_size[c$uid]["last,bwd"] = p$tcp$win;
    }

    # update the matching time stamp to the timestamp of this packet
    if( is_fwd){
        last_packet_time[c$uid]["fwd"] = network_time();
    }
    else{
        last_packet_time[c$uid]["bwd"] = network_time();
    }
}

# if the connection is finished calculate all the features and write them to the log file
event connection_state_remove(c: connection) {

    # check if the last data transmission was a bulk transfer, if yes update the parameters of the corresponding bulkflow
    if(bulk_packets[c$uid]["fwd,tmp"] >= bulk_min_length){
        ++bulk_counter[c$uid]["fwd"];
        bulk_packets[c$uid]["fwd"] += bulk_packets[c$uid]["fwd,tmp"];
        bulk_bytes[c$uid]["fwd"] += bulk_bytes[c$uid]["fwd,tmp"];
        bulk_time[c$uid]["fwd"] += bulk_time[c$uid]["fwd,tmp"];
    }
    if(bulk_packets[c$uid]["bwd,tmp"] >= bulk_min_length){
        ++bulk_counter[c$uid]["bwd"];
        bulk_packets[c$uid]["bwd"] += bulk_packets[c$uid]["bwd,tmp"];
        bulk_bytes[c$uid]["bwd"] += bulk_bytes[c$uid]["bwd,tmp"];
        bulk_time[c$uid]["bwd"] += bulk_time[c$uid]["bwd,tmp"];
    }

    # get the statistical overview for the payload in fwd and bwd direction
    local payload_sta_fwd=generate_stats_count(payload_vector[c$uid]["fwd"]);
    local payload_sta_bwd=generate_stats_count(payload_vector[c$uid]["bwd"]);

    # merge the fwd vector in the bwd vector, can be done as it is not needed anymore afterwards
    local size_payload_fwd = |payload_vector[c$uid]["fwd"]|;
    local size_payload_bwd = |payload_vector[c$uid]["bwd"]|;
    payload_vector[c$uid]["bwd"][size_payload_bwd:size_payload_bwd+size_payload_fwd]=payload_vector[c$uid]["fwd"];

    # get the statistical overview for the whole flow
    local payload_sta_flow=generate_stats_count(payload_vector[c$uid]["bwd"]);

    # delete the payload vectors as they have ben modified to get the whole flow view! so nobody accidentally uses them again
    delete payload_vector[c$uid];

    # initialize the fwd_pkts_per_sec, bwd_pkts_per_sec, flow_pkts_per_sec and payload_bytes_per_second to 0 in case the division is not possible due to a duration of 0
    local fwd_pkts_per_sec  = 0.0;
    local bwd_pkts_per_sec  = 0.0;
    local flow_pkts_per_sec = 0.0;
    local payload_bytes_per_second  = 0.0;


    # if duration is > 0 usec then calculate correct values for fwd_pkts_per_sec, bwd_pkts_per_sec, flow_pkts_per_sec, payload_bytes_per_second
    # the absolut value of c$duration is taken to get a double instead of an interval
    if(c$duration > 0 usec){
        fwd_pkts_per_sec = packet_count[c$uid]["fwd"] / |c$duration|;
        bwd_pkts_per_sec = packet_count[c$uid]["bwd"] / |c$duration|;
        flow_pkts_per_sec = ( packet_count[c$uid]["fwd"] + packet_count[c$uid]["bwd"] ) / |c$duration|;
        payload_bytes_per_second = payload_sta_flow$tot / |c$duration|;
    }

    # initialize the down_up_ratio to 0 incase the division is not possible due to 0 up packets
    local down_up_ratio = 0.0;

    # if the number of fwd packets is > 0 calculate the correct value for down_up_ratio
    # multiply with 1.0 to have the division take place as doubles and not ints
    if(packet_count[c$uid]["fwd"] > 0){
        down_up_ratio = packet_count[c$uid]["bwd"] / (1.0 * packet_count[c$uid]["fwd"]);
    }

    # initialize all bulk features as 0
    local fwd_bulk_bytes = 0.0;
    local fwd_bulk_packets = 0.0;
    local bwd_bulk_packets = 0.0;
    local bwd_bulk_bytes = 0.0;
    local fwd_bulk_rate = 0.0;
    local bwd_bulk_rate = 0.0;

    # if the number of fwd bulk transmissions is > 0 calculate the correct value for fwd_bulk_bytes and fwd_bulk_packets
    # multiply with 1.0 to have the division take place as doubles and not ints
    if(bulk_counter[c$uid]["fwd"] > 0){
        fwd_bulk_bytes= bulk_bytes[c$uid]["fwd"] / (1.0 * bulk_counter[c$uid]["fwd"]);
        fwd_bulk_packets= bulk_packets[c$uid]["fwd"] / (1.0 * bulk_counter[c$uid]["fwd"]);
    }
    # if the number of bwd bulk transmissions is > 0 calculate the correct value for bwd_bulk_bytes and bwd_bulk_packets
    # multiply with 1.0 to have the division take place as doubles and not ints
    if(bulk_counter[c$uid]["bwd"] > 0){
        bwd_bulk_bytes= bulk_bytes[c$uid]["bwd"] / (1.0 * bulk_counter[c$uid]["bwd"]);
        bwd_bulk_packets= bulk_packets[c$uid]["bwd"] / (1.0 * bulk_counter[c$uid]["bwd"]);
    }
    # if the sum of the durations of all fwd bulk transmissions is > 0 calculate the correct value for fwd_bulk_rate
    if( bulk_time[c$uid]["fwd"] > 0.0){
        fwd_bulk_rate = bulk_bytes[c$uid]["fwd"] / bulk_time[c$uid]["fwd"];
    }
    # if the sum of the durations of all bwd bulk transmissions is > 0 calculate the correct value for bwd_bulk_rate
    if( bulk_time[c$uid]["bwd"] > 0.0){
        bwd_bulk_rate = bulk_bytes[c$uid]["bwd"] / bulk_time[c$uid]["bwd"];
    }

    # fill the Features object for this connection
    local rec = FlowMeter::Features($uid = c$uid, $flow_duration = c$duration, $bwd_pkts_tot=packet_count[c$uid]["bwd"], $fwd_pkts_tot=packet_count[c$uid]["fwd"],
                                           $flow_FIN_flag_count = flag_count[c$uid]["FIN"], $flow_SYN_flag_count = flag_count[c$uid]["SYN"], $flow_RST_flag_count = flag_count[c$uid]["RST"],
                                           $fwd_PSH_flag_count = flag_count[c$uid]["fwd,PSH"], $bwd_PSH_flag_count = flag_count[c$uid]["bwd,PSH"], $flow_ACK_flag_count = flag_count[c$uid]["ACK"],
                                           $fwd_URG_flag_count = flag_count[c$uid]["fwd,URG"], $bwd_URG_flag_count = flag_count[c$uid]["bwd,URG"], $flow_CWR_flag_count = flag_count[c$uid]["ECE"], $flow_ECE_flag_count = flag_count[c$uid]["CWR"],
                                           $fwd_pkts_per_sec = fwd_pkts_per_sec, $bwd_pkts_per_sec = bwd_pkts_per_sec, $flow_pkts_per_sec = flow_pkts_per_sec, $down_up_ratio = down_up_ratio,
                                           $fwd_header_size_tot = header_count[c$uid]["fwd,tot"], $fwd_header_size_min = header_count[c$uid]["fwd,min"], $fwd_header_size_max = header_count[c$uid]["fwd,max"],
                                           $bwd_header_size_tot = header_count[c$uid]["bwd,tot"], $bwd_header_size_min = header_count[c$uid]["bwd,min"], $bwd_header_size_max = header_count[c$uid]["bwd,max"],
                                           $fwd_data_pkts_tot = data_packet_count[c$uid]["fwd"], $bwd_data_pkts_tot = data_packet_count[c$uid]["bwd"], $payload_bytes_per_second = payload_bytes_per_second,
                                           $fwd_pkts_payload = payload_sta_fwd, $bwd_pkts_payload = payload_sta_bwd, $flow_pkts_payload = payload_sta_flow,
                                           $fwd_subflow_pkts = packet_count[c$uid]["fwd"] / (1.0 * num_subflows[c$uid]), $bwd_subflow_pkts = packet_count[c$uid]["bwd"] / (1.0 * num_subflows[c$uid]),
                                           $fwd_subflow_bytes = payload_sta_fwd$tot / num_subflows[c$uid], $bwd_subflow_bytes = payload_sta_bwd$tot / num_subflows[c$uid],
                                           $active=generate_stats_double(active_vector[c$uid]), $idle=generate_stats_double(idle_vector[c$uid]),
                                           $fwd_iat=generate_stats_double(iat_vector[c$uid]["fwd"]), $bwd_iat=generate_stats_double(iat_vector[c$uid]["bwd"]), $flow_iat = generate_stats_double(iat_vector[c$uid]["flow"]),
                                           $fwd_bulk_bytes = fwd_bulk_bytes, $bwd_bulk_bytes = bwd_bulk_bytes, $fwd_bulk_packets =fwd_bulk_packets , $bwd_bulk_packets = bwd_bulk_packets,
                                           $fwd_bulk_rate = fwd_bulk_rate, $bwd_bulk_rate = bwd_bulk_rate, $fwd_init_window_size = window_size[c$uid]["init,fwd"], $bwd_init_window_size = window_size[c$uid]["init,bwd"],
                                           $fwd_last_window_size = window_size[c$uid]["last,fwd"], $bwd_last_window_size = window_size[c$uid]["last,bwd"]);




    # delete the still existing table entries of this connection, as they are now not needed any more
    delete packet_count[c$uid];
    delete flag_count[c$uid];
    delete data_packet_count[c$uid];
    delete header_count[c$uid];
    delete num_subflows[c$uid];
    delete active_vector[c$uid];
    delete idle_vector[c$uid];
    delete new_active_phase[c$uid];
    delete bulk_counter[c$uid];
    delete bulk_bytes[c$uid];
    delete bulk_time[c$uid];
    delete previous_was_fwd[c$uid];
    delete bulk_packets[c$uid];
    delete window_size[c$uid];
    delete iat_vector[c$uid];
    # write the measures of this connection to the log file
    Log::write(FlowMeter::LOG, rec);
}

