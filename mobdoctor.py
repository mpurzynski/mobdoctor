#!/usr/bin/env python
# -*- coding: utf-8 -*-

import glob
import os.path
import importlib

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
    all_plugins = [
        importlib.import_module('plugins.%s' % os.path.basename(x)[:-3])
        for x in glob.glob("plugins/*.py")
        if os.path.isfile(x) and not x.endswith('__init__.py')
    ]
    plugin_list = [
        x for x in all_plugins if hasattr(x, 'do_check')
        and hasattr(x, 'reserved')
    ]

    system_state = {}
    for plugin in plugin_list:
        plugin_state = {}
        plugin_state = plugin.do_check(plugin_state)
        if plugin_state is not None:
            plugin.reserved(plugin_state)


if __name__ == '__main__':
    main()