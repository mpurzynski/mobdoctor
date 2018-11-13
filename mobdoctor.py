#!/usr/bin/env python
# -*- coding: utf-8 -*-

import glob
import os.path
import importlib
import yaml

RED = '\033[91m'
ENDC = '\033[0m'
GREEN = '\033[92m'

# Some functions shamesly stolen from Justin Azoff's excellent bro-doctor
# Actually, the whole idea as well

def red(s):
    return RED + s + ENDC

def green(s):
    return GREEN + s + ENDC

def percent(a, b):
    try :
        return 100.0 * a / b
    except ZeroDivisionError:
        return 0.0

def main():
    with open('config.yml', 'r') as f:
        map = f.read()
    yap = yaml.load(map)

    all_plugins = [
        importlib.import_module('plugins.%s' % os.path.basename(x)[:-3])
        for x in sorted(glob.glob("plugins/*.py"))
        if os.path.isfile(x) and not x.endswith('__init__.py')
    ]
    plugin_list = [
        x for x in all_plugins if hasattr(x, 'do_check')
        and hasattr(x, 'reserved')
    ]

    system_state = {}
    for plugin in plugin_list:
        system_state = plugin.do_check(yap, system_state)
    
if __name__ == '__main__':
    main()