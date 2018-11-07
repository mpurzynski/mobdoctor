#!/usr/bin/env python
# -*- coding: utf-8 -*-

import glob
import os.path
import importlib

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