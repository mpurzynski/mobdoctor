#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json

def do_check(state):
    """Prints a stupid string
    Has an ultra-cool multi-line comment
    :param state: No idea what that is
    :return: state: Why not
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

    # Can we even parse protocols

    # details.stats.app_layer.flow.dns_tcp - warn is none seen
    # details.stats.app_layer.flow.dns_udp - warn is none seen
    # details.stats.app_layer.flow.http
    # details.stats.app_layer.flow.tls

    local_status = True
    flow_ids = {}
    print('Checking counters for the most common protocols'.format())
    for proto in ['http', 'tls', 'dns_tcp']:
        flow_ids[proto] = stats[-1]['stats']['app_layer']['flow'][proto]
        if flow_ids[proto] == 0:
            local_status = False
            print('Problem found - counter for the {0} protocol is zero'.format(proto))
        print('{0} - {1} flows identified'.format(proto, flow_ids[proto]))

    # The built-in protocol detection wasn't able to recognize a protocol

    proto_tcp_failed = 0
    proto_tcp_ok = 0
    for stat_entry in stats:
        proto_tcp_failed = proto_tcp_failed + stat_entry['stats']['app_layer']['flow']['failed_tcp']
        for proto in ['http', 'ftp', 'smtp', 'tls', 'ssh', 'imap', 'msn', 'smb', 'dcerpc_tcp', 'dns_tcp', 'nfs_tcp']:
            proto_tcp_ok = proto_tcp_ok + stat_entry['stats']['app_layer']['flow'][proto]
    print('TCP protocols not recognized: {0:.2f}%'.format(100*(proto_tcp_failed / proto_tcp_ok)))

    proto_udp_failed = 0
    proto_udp_ok = 0
    for stat_entry in stats:
        proto_udp_failed = proto_udp_failed + stat_entry['stats']['app_layer']['flow']['failed_udp']
        for proto in ['ntp', 'dcerpc_udp', 'dns_udp', 'nfs_udp']:
            proto_udp_ok = proto_udp_ok + stat_entry['stats']['app_layer']['flow'][proto]
    print('UDP protocols not recognized: {0:.2f}%'.format(100*(proto_udp_failed / proto_udp_ok)))

    # decoder.teredo.enabled: false
    # details.stats.app_layer.tx.dns_tcp
    # details.stats.app_layer.tx.dns_udp
    # details.stats.app_layer.tx.http
    # details.stats.capture.kernel_drops
    # details.stats.capture.kernel_packets
    # details.stats.decoder.avg_pkt_size - warn on >1500 and tell avg is 850-950
    # details.stats.decoder.invalid
    # details.stats.decoder.ipraw.invalid_ip_version
    # details.stats.decoder.ipv4 / details.stats.decoder.ethernet > 80%
    # details.stats.decoder.ltnull.pkt_too_small
    # details.stats.decoder.ltnull.unsupported_type
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
    # details.stats.detect.alert - calculate delta
    # details.stats.dns.memcap_global
    # details.stats.dns.memcap_state
    # details.stats.dns.memuse

    # details.stats.flow.emerg_mode_entered
    # details.stats.flow.emerg_mode_over
    # details.stats.flow.memcap
    # details.stats.flow.spare
    # details.stats.flow_mgr.flows_timeout_inuse
    # details.stats.flow_mgr.rows_busy
    # details.stats.flow_mgr.rows_checked
    # details.stats.flow_mgr.rows_empty
    # details.stats.flow_mgr.rows_maxlen
    # details.stats.flow_mgr.rows_skipped

    # details.stats.http.memcap
    # details.stats.http.memuse
    # increase stream.reassemble.memcap
    # details.stats.tcp.insert_data_normal_fail
    # details.stats.tcp.insert_data_overlap_fail
    # details.stats.tcp.insert_list_fail
    # details.stats.tcp.invalid_checksum
    # details.stats.tcp.no_flow
    # details.stats.tcp.overlap
    # details.stats.tcp.overlap_diff_data
    # details.stats.tcp.pseudo
    # details.stats.tcp.pseudo_failed
    # details.stats.tcp.stream_depth_reached
    
    # This is an indicator that we're missing TCP data, both due to the packet
    # loss and the 2 tcp.*_drop counters below.
    # details.stats.tcp.reassembly_gap

    # Check if parameters are at defaults

    # This another serious resource stress indicator: 1.3M TCP segments are
    # not properly processed for stream reassembly because of the
    # stream.reassemble.memcap setting being too low.
    # This traces the performance is Suricata putting TCP segments together into a flow
    segment_memcap_drop = {}
    # This is a serious resource stress indicator: 800k TCP sessions are not
    # tracked at all due to the stream.memcap setting being too low.
    # This counter traces if all previously reassembled TCP sessions are traced correctly
    ssn_memcap_drop = {}
    segment_memcap_drop['global'] = 0
    ssn_memcap_drop['global'] = 0

    for stat_entry in stats:
        segment_memcap_drop['global'] = segment_memcap_drop['global'] + stat_entry['stats']['tcp']['segment_memcap_drop']
        ssn_memcap_drop['global'] = ssn_memcap_drop['global'] + stat_entry['stats']['tcp']['ssn_memcap_drop']
        for thread in stat_entry['stats']['threads']:
            if thread.startswith('W'):
                segment_memcap_drop[thread] = stat_entry['stats']['threads'][thread]['tcp']['segment_memcap_drop']
                ssn_memcap_drop[thread] = stat_entry['stats']['threads'][thread]['tcp']['ssn_memcap_drop']
    ##print(segment_memcap_drop)
    #print(ssn_memcap_drop)

    return plugin_state

def reserved(state):
    return