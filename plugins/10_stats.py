#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import jmespath
from mobdoctor import red, green, percent
from datetime import datetime, timedelta

def do_check(yonfig, system_state):
    """Parses configuration file
    Provides contextual information for other modules
    :param global_state: A set of variables reflecting system's configuration, updated by every plugin
    :return: global_state: When the global_state is updated, it is returned for other plugins to consume
    """

    plugin_enabled = True
    if not plugin_enabled:
        return False
    
    plugin_state = {}
    stats = []

    with open('eve-log.json', 'r') as f:
        logs = [
            json.loads(line) for line in f.readlines()
        ]
        stats = [
            entry for entry in logs
            if entry['event_type'] == 'stats'
        ]

    first_stat_ts = stats[0]['timestamp']
    last_stat_ts = stats[-1]['timestamp']
    first_stat = stats[0]['stats']
    last_stat = stats[-1]['stats']
    # 2018-11-07T01:00:06.000152+0000
    first_stat_dt = datetime.strptime(first_stat_ts, "%Y-%m-%dT%H:%M:%S.%f%z")
    last_stat_dt = datetime.strptime(last_stat_ts, "%Y-%m-%dT%H:%M:%S.%f%z")
    stat_delta = (last_stat_dt - first_stat_dt).total_seconds()
    
    # Can we even parse protocols
    local_status = True
    flow_ids = {}
    print('Checking counters for the most common protocols'.format())
    for proto in ['http', 'tls', 'dns_udp']:
        flow_ids[proto] = stats[-1]['stats']['app_layer']['flow'][proto]
        if flow_ids[proto] == 0:
            local_status = False
            print('Problem found - counter for the {0} protocol is zero'.format(proto))
        print('{0} - {1} flows identified'.format(proto, flow_ids[proto]))

    # The built-in protocol detection wasn't able to recognize a protocol
    proto_tcp_failed = 0
    proto_tcp_ok = 0
    proto_tcp_failed = proto_tcp_failed + stats[-1]['stats']['app_layer']['flow']['failed_tcp']
    for proto in ['http', 'ftp', 'smtp', 'tls', 'ssh', 'imap', 'msn', 'smb', 'dcerpc_tcp', 'dns_tcp', 'nfs_tcp']:
        proto_tcp_ok = proto_tcp_ok + stats[-1]['stats']['app_layer']['flow'][proto]
    print('TCP protocols not recognized: {0:.2f}%'.format(100*(proto_tcp_failed / proto_tcp_ok)))

    proto_udp_failed = 0
    proto_udp_ok = 0
    proto_udp_failed = proto_udp_failed + last_stat['app_layer']['flow']['failed_udp']
    for proto in ['ntp', 'dcerpc_udp', 'dns_udp', 'nfs_udp']:
        proto_udp_ok = proto_udp_ok + last_stat['app_layer']['flow'][proto]
    print('UDP protocols not recognized: {0:.2f}%'.format(100*(proto_udp_failed / proto_udp_ok)))

    # decoder.teredo.enabled: false
    # Transactions inside a flow, like DNS TXs and HTTP pipelines
    # details.stats.app_layer.tx.dns_tcp
    # details.stats.app_layer.tx.dns_udp
    # details.stats.app_layer.tx.http
    drop_rate = percent(last_stat['capture']['kernel_drops'], last_stat['capture']['kernel_packets'])
    print('Your drop rate is {0:.2f}'.format(drop_rate))
    # details.stats.capture.kernel_drops
    # details.stats.capture.kernel_packets

    # details.stats.decoder.avg_pkt_size - warn on >1500 and tell avg is 850-950
    avg_pkg_size = last_stat['decoder']['avg_pkt_size']
    print('The average packet size is {0} bytes'.format(avg_pkg_size))
    if avg_pkg_size > 1500:
        print('The average packet size is > 1500 bytes')
        # FIXME - instruct what to do (offloading disable)
    
    # Q: How to best explain this?
    # details.stats.decoder.invalid
    # details.stats.decoder.ipraw.invalid_ip_version
    # details.stats.decoder.ipv4 / details.stats.decoder.ethernet > 80%
    # details.stats.decoder.ltnull.pkt_too_small
    # details.stats.decoder.ltnull.unsupported_type
    
    # FIXME
    # Now, this is problematic. It could be that offloading is enabled or it could be the af_packet defragmentation
    # details.stats.decoder.max_pkt_size
    # details.stats.decoder.null
    # details.stats.decoder.pkts
    # details.stats.decoder.raw
    # details.stats.decoder.sll
    # details.stats.decoder.tcp

    # details.stats.defrag.ipv4.fragments
    # details.stats.defrag.ipv4.reassembled
    # details.stats.defrag.ipv4.timeouts
    # details.stats.defrag.ipv6.fragments
    # details.stats.defrag.ipv6.reassembled
    # details.stats.defrag.ipv6.timeouts
    # details.stats.defrag.max_frag_hits

    alerts_number = last_stat['detect']['alert'] - first_stat['detect']['alert']
    alerts_velocity = (alerts_number) / stat_delta
    print("Suricata generated {0} alerts in {1} seconds".format(alerts_number, stat_delta))
    print("That is {0} alerts per second".format(alerts_velocity))
    print("Or, you have one alert every {0} seconds".format(1/alerts_velocity))
    if alerts_velocity > 1.0:
        print("You might want to tune your alerts, you have more than 1 alert / second")
    
    # These are not MBs, this is the number of times the engine ran out of the memory for the DNS parser
    # Increased on every event
    # details.stats.dns.memcap_global
    # details.stats.dns.memcap_state
    # details.stats.dns.memuse
    print(last_stat['dns'])

    # FIXME when can a flow time out while still in use?
    # details.stats.flow_mgr.flows_timeout_inuse

    # FIXME
    # How many flows per hash row
    # The hash structure must sure be an interesting one
    # Should be < 3 or so
    # Large values mean the flow hash is too small
    # details.stats.flow_mgr.rows_maxlen
    # details.stats.flow_mgr.rows_skipped

    # details.stats.tcp.insert_data_normal_fail
    # details.stats.tcp.insert_data_overlap_fail
    # details.stats.tcp.insert_list_fail
    # details.stats.tcp.no_flow
    # details.stats.tcp.overlap
    # details.stats.tcp.overlap_diff_data
    # details.stats.tcp.pseudo
    # details.stats.tcp.pseudo_failed
    # details.stats.tcp.stream_depth_reached
    
    checks = yonfig['checks']
    # This is an indicator that we're missing TCP data, both due to the packet
    # loss and the 2 tcp.*_drop counters below.
    # details.stats.tcp.reassembly_gap
    for k in checks.keys():
        value = jmespath.search(checks[k]['stat'], last_stat)
        print(checks[k]['explanation'])
        print("{0} - {1}".format(k, value))

    return plugin_state

def reserved(system_state):
    return