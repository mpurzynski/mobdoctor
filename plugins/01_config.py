#!/usr/bin/env python
# -*- coding: utf-8 -*-

import yaml

def do_check(yonfig, system_state):
    """Parses configuration file
    Provides contextual information for other modules
    :param global_state: A set of variables reflecting system's configuration, updated by every plugin
    :return: global_state: When the global_state is updated, it is returned for other plugins to consume
    """

    plugin_enabled = True
    if not plugin_enabled:
        return False
    
    myname = __name__[11:]
    system_state[myname] = {}
    state = system_state[myname]

    with open('suricata.yml', 'r') as f:
        map = f.read()
    yap = yaml.load(map)
    
    if 'flow' in yap:
        state['flow'] = yap['flow']

    return system_state

def reserved(system_state):
    return