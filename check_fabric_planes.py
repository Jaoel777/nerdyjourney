#!/home/rikeda/venv_dir/py3/bin/python
""" This script makes commands for trouble shooting of Fabric Check Plane Alarm.
For details, please refer the document below.
https://confluence.gin.ntt.net/display/OPS/Fabric+Check+Plane+Alarm+Troubleshooting"""
import os
import sys

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument('fpc_slot', nargs='+')
    args = parser.parse_args()
    print("request support info | no-more ","\nshow chassis environment cb | no-more",
          "\nshow chassis alarms | no-more")
    for i in args.fpc_slot:
        print(f'request pfe execute command "show jspec client" target fpc{i} | no-more',
              f'\nrequest pfe execute command "show syslog messages" target fpc{i} | no-more',
              f'\nrequest pfe execute command "show nvram" target fpc{i}  | no-more')
    print("file archive source /var/log/* destination /var/tmp/router_name_logs.tgz compress")
    
