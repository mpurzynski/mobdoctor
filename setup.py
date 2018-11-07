from distutils.core import setup, Extension

module1 = Extension('eth',
                    sources = ['ethmodule.c'])

setup (name = 'eth',
       version = '0.1',
       description = 'This is a demo package',
       ext_modules = [module1])
