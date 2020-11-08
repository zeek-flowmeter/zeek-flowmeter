# Zeek FlowMeter

This project is a port to Zeek of the [CICFlowMeter](https://github.com/ahlashkari/CICFlowMeter) project. Additional features have been integrated, while other duplicates have been removed. 

FlowMeter performs layer 3 and 4 network traffic analysis and generates a set of new features based on timing, volume and metadata. These features are ideal for developing models for traffic classification without using deep packet inspection. 

The advantage of using a standard network analysis framework like Zeek is that it is now possible to integrate the extraction of flow features in a standard solution. The identification of flows is therefore delegated to Zeek. Moreover, `FlowMeter` perform analysis on IPv6 flows too (currently CICFlowMeter do not support IPv6). 

This project adds the `flowmeter.zeek` script and the corresponding module with the name `FlowMeter`. Once activated, the module compute the features listed in the table below and write them into the `flowmeter.log` file. 

### Install Zeek

Standalone Zeek: https://docs.zeek.org/en/current/install/install.html

Docker files for building Zeek in a container: https://github.com/zeek/zeek-docker

## Performances

In order to compute the features, the script performs a resource-intensive calculation at the package level. For this reason, extracting new features from a data stream requires more time. As a result, this type of analysis tool is suitable for offline analytics (`pcap`) but not for analyzing large amounts of live data.

### Comparison with CICFlowMeter

The performances presented are evaluated on a single core (Xeon E5-2660 v2 @ 2.20GHz) and using a 380Mb `pcap` file: 1.3M IP packets, 300k of which IPv6.

* CICFlowMeter (IPv4 only, discarding IPv6 traffic), identified 40k IPv4 flows and computed the features in `29 seconds`.
* Zeek with 25 default plugins and without FlowMeter identified all 50k IPv4 and IPv6 flows and computed the default analysis in `33 seconds`.
* Zeek with 25 default plugins and FlowMeter produced the default output and the `flowmeter.log` (script) in `2 min and 50 second`. 

### Improving performances

* The time required to lookup time for values in a table and the fetch time for values from vectors has not yet been evaluated. Copying the value once into a local variable, perform the calculations and then write the value back to the vector/table could lead to a performance improvement. 

* Move some of the functions to a [compiled function](https://docs.zeek.org/en/current/devel/plugins.html).

* Since Zeek is single-threaded, set up a [Zeek cluster](https://docs.zeek.org/en/current/cluster/). This may require some adjustments in the script to take full and proper advantage of the additional processing power in the cluster.

## Install

### Zeek package manager
To install the package using the Zeek package manager (zkg), run `zkg install .` from within the package directory.

### Manual
To manually adding the package to Zeek, create the folder `<zeekscriptdir>/share/zeek/site/flowmeter` and copy all files in the script folder to that folder. 

    zeekctl config | grep zeekscriptdir
    cp -r zeek-flowmeter/scripts  <zeekscriptdir>/site/flowmeter
    
## Configure

### Add flowmeter to local zeek configuration (optional)
To add FlowMeter to the standard local configuration of zeek, edit `<zeekscriptdir>/site/local.zeek` and add

    @load flowmeter
        
Using the config file has also the advantage of changing the parameters of the FlowMeter module, by adding the following line to the config file `redefine FlowMeter::<parameter name> = <desired value>;`

### Disable Zeek packet checksum verification
Zeek discards packages with an invalid checksum by default. If you need to include invalid packages in the analysis, you need to add the line `redef ignore_checksums=T;` to the config file. Alternatively, the command line option `-C` can be passed to Zeek.

### Example of local.zeek parameter redefinition
    # load the FlowMeter for execution
    @load flowmeter
    
    # redefining the minimal bulk length to 3 packets
    redefine FlowMeter::bulk_min_length = 3;
    
    # disable checksum verification
    redef ignore_checksums=T;
    
### Parameters
* `FlowMeter::subflow_max_iat`: The maximal allowed inter-arrival time between two packets so they are considered to be part of the same subflow. The default value is 1s.
* `FlowMeter::bulk_min_length`: The minimal number of data packets which have to be in a bulk transmission for it to be considered a bulk transmission. The default value is 5 packets.
* `FlowMeter::bulk_timeout`: The maximal allowed inter-arrival time between two data packets so they are considered to be part of the same bulk transmission. The default value is 1s.
* `FlowMeter::active_timeout`: The maximal allowed inter-arrival time between two packets so that the flow is considered to be active. The default value is 5s.
    

## Run
Analyze a `pcap` with FlowMeter from the command line.

    zeek flowmeter -r your.pcap 

Analyze a `pcap` with a local defined FlowMeter, as defined in the `local.zeek` config.

    zeek local -r your.pcap 

## Feature extraction

### Definitions

#### Flow
Zeek is assembling the packets into flows. Each packet of a flow is passed the the FlowMeter script to extract the measures. Information such as IP addresses and ports used in the flow are found in the `conn.log`. For each entry in the `conn.log` an entry with matching `uid` exists in the `flowmeter.log`.

#### Subflow
A subflow is an exchange of packets in a flow, where the inter-arrival time between the packets is less than `subflow_max_iat`. If the inter-arrival time between two packets is larger than `subflow_max_iat`, then the current subflow is terminated and a new subflow starts.

#### Bulk Transmission
A bulk transmission is a continuous transmission of at least `bulk_min_length` data packets (packets carrying payload) from either the source or the destination. A bulk transmission is terminated if the other side transmits a data packet or if the inter-arrival time between two packets is larger than the bulk `bulk_timeout`. If at the termination the bulk flow has not seen more than `bulk_min_length`, then that bulk flow is discarded.

#### Definition of Active and Idle Time
A flow is considered to be active if a successive packet arrives in less than `active_timeout`. If no packet is seen after `active_timeout`, then the flow is considered to have been idle during that period.

### flowmeter.log

| Feature Name                          | Description                                                                                                                                                                                                 | exists in FlowMeter|
| ---                                        | ---                                                                                                                                                                                                             | ---                        |
| uid                                         | The ID of the flow as given by Zeek                                                                                                                                                                      | No |
| flow_duration                        | The length of the flow in seconds (maximal precision ms). If only on packet was seen the duration is 0.                                                            | Yes |
| fwd_pkts_tot                         | The number of packets travelling in the forward direction.                                                                                                                                     | Yes |
| bwd_pkts_tot                        | The number of packets travelling in the backwards direction.                                                                                                                                | Yes |
| fwd_data_pkts_tot                | The number of packets travelling in the forward direction, which have a payload.                                                                                                | Yes |
| bwd_data_pkts_tot               | The number of packets travelling in the backwards direction, which have a payload.                                                                                           | No |
| fwd_pkts_per_sec                 | The average number of forward packets transmitted per second during the flow. If the duration is 0 then this feature is also set to 0.                | Yes |
| bwd_pkts_per_sec                | The average number of backward packets transmitted per second during the flow. If the duration is 0 then this feature is also set to 0.             | Yes |
| flow_pkts_per_sec                | The average number of  packets transmitted per second during the flow. If the duration is 0 then this feature is also set to 0.                             | Yes |
| down_up_ratio                      | The number of backward packets divided by the number of forward packets. If the number of forward packets is 0 this feature is also set to 0. | Yes |
| fwd_header_size_tot             | The total number of bytes the headers of the forward packets contained.                                                                                                               | Yes |
| fwd_header_size_min           | The number of bytes the smallest headers of the forward packets contained.                                                                                                         | Yes |
| fwd_header_size_max           | The number of bytes the largest headers of the forward packets contained.                                                                                                         | Yes |
| bwd_header_size_tot            | The total number of bytes the headers of the backward packets contained.                                                                                                            | Yes |
| bwd_header_size_min           | The number of bytes the smallest headers of the backward packets contained.                                                                                                      | No |
| bwd_header_size_max           | The number of bytes the largest headers of the backward packets contained.                                                                                                      | No |
| fwd_pkts_payload.max         | The largest payload size, in bytes, seen in the forward direction.                                                                                                                               | Yes |
| fwd_pkts_payload.min         |  The smallest payload size, in bytes, seen in the forward direction.                                                                                                                              | Yes |
| fwd_pkts_payload.tot           | The total payload size, in bytes, seen in the forward direction.                                                                                                                                    | Yes |
| fwd_pkts_payload.avg         |  The average payload size, in bytes, seen in the forward direction.                                                                                                                             | Yes |
| fwd_pkts_payload.std         |  The standard deviation of the payload size, in bytes, seen in the forward direction.                                                                                                    | Yes |
| bwd_pkts_payload.max        | The largest payload size, in bytes, seen in the backward direction.                                                                                                                                | Yes |
| bwd_pkts_payload.min        | The smallest payload size, in bytes, seen in the backward direction.                                                                                                                              | Yes |
| bwd_pkts_payload.tot          | The total payload size, in bytes, seen in the backward direction.                                                                                                                                      | Yes |
| bwd_pkts_payload.avg        | The average payload size, in bytes, seen in the backward direction.                                                                                                                              | Yes |
| bwd_pkts_payload.std         |The standard deviation of the payload size, in bytes, seen in the backward direction.                                                                                                    | Yes |
| flow_pkts_payload.max        |  The largest payload size, in bytes, seen in the flow.                                                                                                                                                       | Yes |
| flow_pkts_payload.min        |  The smallest payload size, in bytes, seen in the flow.                                                                                                                                                     | Yes |
| flow_pkts_payload.tot          | The total payload size, in bytes, seen in the flow.                                                                                                                                                              | No |
| flow_pkts_payload.avg        |  The average payload size, in bytes, seen in the flow.                                                                                                                                                         | Yes |
| flow_pkts_payload.std         | The standard deviation of the payload size, in bytes, seen in the flow                                                                                                                               | Yes |
| payload_bytes_per_second | The average number of payload bytes transmitted per second. If the duration is 0 then this feature is also set to 0.                                                       | Yes |
| flow_FIN_flag_count             | The total number of FIN flags which have been seen in a TCP flow. If the the flow is not a TCP flow this feature is set to 0.                                          | Yes |
| flow_SYN_flag_count            | The total number of SYN flags which have been seen in a TCP flow. If the the flow is not a TCP flow this feature is set to 0.                                         | Yes |
| flow_RST_flag_count            | The total number of RST flags which have been seen in a TCP flow. If the the flow is not a TCP flow this feature is set to 0.                                            | Yes |
| fwd_PSH_flag_count            | The total number of PSH flags which have been seen in the forward direction of a TCP flow. If the the flow is not a TCP flow this feature is set to 0.    | Yes |
| bwd_PSH_flag_count           | The total number of PSH flags which have been seen in the backward direction of a TCP flow. If the the flow is not a TCP flow this feature is set to 0.    | Yes |
| flow_ACK_flag_count           | The total number of ACK flags which have been seen in a TCP flow. If the the flow is not a TCP flow this feature is set to 0.                                            | Yes |
| fwd_URG_flag_count           | The total number of URG flags which have been seen in the forward direction of a TCP flow. If the the flow is not a TCP flow this feature is set to 0.     | Yes |
| bwd_URG_flag_count           | The total number of URG flags which have been seen in the backward direction of a TCP flow. If the the flow is not a TCP flow this feature is set to 0.    | Yes |
| flow_CWR_flag_count           | The total number of CWR flags which have been seen in a TCP flow. If the the flow is not a TCP flow this feature is set to 0.                                              | Yes |
| flow_ECE_flag_count           | The total number of ECE flags which have been seen in a TCP flow. If the the flow is not a TCP flow this feature is set to 0.                                               | Yes |
| fwd_iat.max                           |  The largest inter-arrival time in microseconds bet two consecutive packets in the forward direction.                                                                                    | Yes |
| fwd_iat.min                            |  The smallest inter-arrival time in microseconds bet two consecutive packets in the forward direction.                                                                                  | Yes |
| fwd_iat.tot                              | The inter-arrival time in microseconds bet two consecutive packets in the forward direction.                                                                                                  | Yes |
| fwd_iat.avg                            |  The average inter-arrival time in microseconds bet two consecutive packets in the forward direction.                                                                                   | Yes |
| fwd_iat.std                             | The standard deviation of all inter-arrival times in the forward direction in microseconds.                                                                                                       | Yes |
| bwd_iat.max                          | The largest inter-arrival time in microseconds bet two consecutive packets in the backward direction.                                                                                  | Yes |
| bwd_iat.min                           | The smallest inter-arrival time in microseconds bet two consecutive packets in the backward direction.                                                                                 | Yes |
| bwd_iat.tot                            | The inter-arrival time in microseconds bet two consecutive packets in the backward direction.                                                                                                | Yes |
| bwd_iat.avg                           |The average inter-arrival time in microseconds bet two consecutive packets in the backward direction.                                                                                   | Yes |
| bwd_iat.std                           | The standard deviation of all inter-arrival times in the backward direction in microseconds.                                                                                                       | Yes |
| flow_iat.max                          |  The largest inter-arrival time in microseconds bet two consecutive packets in the flow.                                                                                                              | Yes |
| flow_iat.min                           | The smallest inter-arrival time in microseconds bet two consecutive packets in the flow.                                                                                                           | Yes |
| flow_iat.tot                            | The inter-arrival time in microseconds bet two consecutive packets in the flow.                                                                                                                           | No |
| flow_iat.avg                           | The average inter-arrival time in microseconds bet two consecutive packets in the flow.                                                                                                             | Yes |
| flow_iat.std                           | The standard deviation of all inter-arrival times in the flow, in microseconds.                                                                                                                                | Yes |
| fwd_subflow_pkts               |  The average number of packets in the subflows in the forward direction.                                                                                                                                     | Yes |
| bwd_subflow_pkts              |  The average number of packets in the subflows in the backward direction.                                                                                                                                 | Yes |
| fwd_subflow_bytes             |  The average number of payload bytes in the subflows in the forward direction.                                                                                                                           | Yes |
| bwd_subflow_bytes            |  The average number of payload bytes in the subflows in the backward direction.                                                                                                                       | Yes |
| fwd_bulk_bytes                   |  The average number of payload bytes transmitted in a bulk transmission in forward direction.                                                                                                    | Yes |
| bwd_bulk_bytes                  |  The average number of payload bytes transmitted in a bulk transmission in backward direction.                                                                                                 | Yes |
| fwd_bulk_packets               |   The average number of packets transmitted in a bulk transmission in forward direction.                                                                                                              | Yes |
| bwd_bulk_packets              |   The average number of packets transmitted in a bulk transmission in backward direction.                                                                                                        | Yes |
| fwd_bulk_rate                      |   The average number of payload bytes transmitted per second during a bulk transmission in forward direction.                                                                      | Yes |
| bwd_bulk_rate                     |   The average number of payload bytes transmitted per second during a bulk transmission in backward direction.                                                                    | Yes |
| active.max                            |  The longest duration the flow was active in microseconds.                                                                                                                                                        | Yes |
| active.min                             |  The shortest duration the flow was active in microseconds.                                                                                                                                                        | Yes |
| active.tot                              |   The total duration the flow was active in microseconds.                                                                                                                                                             | Yes |
| active.avg                             |   The average duration the flow was active in microseconds.                                                                                                                                                      | Yes |
| active.std                             |    The standard deviation of all active periods in microseconds.                                                                                                                                                  | No |
| idle.max                               |  The longest duration the flow was idle in microseconds.                                                                                                                                                           | Yes |
| idle.min                                | The shortest duration the flow was idle in microseconds.                                                                                                                                                         | Yes |
| idle.tot                                 |  The total duration the flow was idle in microseconds.                                                                                                                                                                | Yes |
| idle.avg                                |  The average duration the flow was idle in microseconds.                                                                                                                                                         | Yes |
| idle.std                                 | The standard deviation of all idle periods in microseconds.                                                                                                                                                         | No |
| fwd_init_window_size          | The window size in bytes the first packet in the forward direction has. The windows scale parameter is currently ignored, as this is only set in a SYN packet but we currently look at any packet. | Yes |
| bwd_init_window_size         | The window size in bytes the first packet in the backward direction has. The windows scale parameter is currently ignored, as this is only set in a SYN packet but we currently look at any packet.  | Yes |
| fwd_last_window_size          | The window size in bytes the last packet in the forward direction has. The windows scale parameter is currently ignored, as this is only set in a SYN packet but we currently look at any packet.   | Yes |
| bwd_last_window_size         | The window size in bytes the last packet in the backward direction has. The windows scale parameter is currently ignored, as this is only set in a SYN packet but we currently look at any packet.   | Yes |


## License

Zeek FlowMeter is released under the [MIT License](https://opensource.org/licenses/MIT).
