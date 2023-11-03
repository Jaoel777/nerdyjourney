#!/home/rikeda/venv_dir/py3/bin/python
import os
import sys
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),"modules"))
import easy_psql
import datetime
import json
import yaml
from rs import RouterSession
from collections import namedtuple
import difflib
import mold

valid_os = ["iox", "junos", "sros","ios"]
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),"modules/settings.yml")) as f:
    settings = yaml.safe_load(f)

def get_router_info():
    p = easy_psql.FreeSearch()
    p.query_where = f"name ~ '{args.router_name}'"
    p.query_from = "routers"
    p.request()
    p.outputs
    if len(p.outputs) == 0:
        print(f"ERROR: {args.router_name} is not valid router name.")
        exit()
    elif len(p.outputs) > 1:
        print(f"ERROR: {args.router_name} matches more than 2. please specify.")
        exit()
    else:
        pass
    os_name = p.outputs[0]["os_name"]

    if os_name not in valid_os:
        print(f"ERROR: {os_name} is not out of scope this script. please retrieve info manually.")
        exit()    
    return(p.outputs[0])


def get_status():
    status = []
    RS = RouterSession(args.router_name,nologin=args.nologin, debug=args.debug)
    cmd_keys = ["admin_show_platform", "show_arp_all", "show_bgp_summary_all", "show_card_state", "show_ifc_brief",
                "show_install_act_summary", "show_install_repo_all", "show_isis_neigh", "show_l2vpn_all", "show_msdp_summary", 
                "show_nv_sat_status_brief", "show_pim_neigh", "show_port", "show_static_all","show_lsp","show_alarms"]
    RS.create_cmds(cmd_keys,{"no_value": ""})
    
    for response in RS():
        status.append(response)
    return(status)
    
def compare(router,pre_status, post_status):
    if len(pre_status) != len(post_status):
        print("ERROR: Script can not compare as picked status of pre/post are different.") 
        exit()
    for num in range(len(pre_status)):
        if pre_status[num].key != post_status[num].key:
            print(f"ERROR: key does not match:",pre_status[num].key,post_status[num].key)
        print(f"====={pre_status[num].key}=====")
        #res = difflib.context_diff(pre_status[num].response.splitlines(),post_status[num].response.splitlines())
        #print('\n'.join(res))
        res = difflib.ndiff(mold.run(router,pre_status[num].key,pre_status[num].response,args.debug).splitlines(),mold.run(router,post_status[num].key,post_status[num].response,args.debug).splitlines())
        
        for r in res:
            if r[0:1] in ['+', '-', '!'] and 'inet' not in r:
                print(r)
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--debug",action="store_true",help="show more detailed messages")
    parser.add_argument("--nologin",action="store_true",help="this is a debug feature to test something")
    parser.add_argument("router_name", metavar="ROUTERNAME or FILENAME")
    prepost = parser.add_mutually_exclusive_group(required=True)
    prepost.add_argument("--pre",action="store_true",help="with ROUTERNAME")
    prepost.add_argument("--post",action="store_true",help="with ROUTERNAME")
    prepost.add_argument("--history",metavar="DATE",help="with DATE and ROUTERNAME")
    prepost.add_argument("--print",action="store_true",help="with FILENAME")
    args = parser.parse_args()

    # Print content of file
    if args.print:
       snap_dir = os.path.expanduser('~/snaps')
       if snap_dir in args.router_name:
           snap_file = args.router_name
       else:
           snap_file = os.path.join(snap_dir,args.router_name)

       if not os.path.exists(snap_file):
           print(f"ERROR: {args.print} does not exist.")
           exit()
       else:
           with open(snap_file) as f:
               status_list = json.load(f)
           for i in status_list:
               print(f"\n=========\ncommand: {i[1]}\noutput: {i[2]}")
       exit()
    router = get_router_info()

    # Define file names
    snap_dir = os.path.expanduser('~/snaps')
    if args.history is None or args.history == "today":
        snap_date = datetime.datetime.today().strftime("%Y%m%d")
    else:
        snap_date = args.history
    pre_snap_file = os.path.join(snap_dir,f"{router['name']}_{snap_date}_pre.json")
    post_snap_file = os.path.join(snap_dir,f"{router['name']}_{snap_date}_post.json")

    # Confirm overwrite if file exists already.
    answer = None
    if args.pre and os.path.exists(pre_snap_file):
        answer = input(f"Do you want to override {pre_snap_file}?[Y/n] >>")
    elif args.post and os.path.exists(post_snap_file):
        answer = input(f"Do you want to override {post_snap_file}?[Y/n] >>")
    if answer is None or "y" in answer or "Y" in answer:
         pass
    else:
        print("Aborting.")
        exit()

    # Get status of protocols on the router
    if args.history is None:
        status = get_status()
    tuple_key = "router_response"
    # Save the status
    if args.pre:
        if not os.path.exists(snap_dir):
            os.mkdir(snap_dir)
            if args.debug:
                print("DEBUG: ~/snaps has been made")
        with open(pre_snap_file,mode = "w") as f:
            json.dump(status,f)
        if args.debug:
            print(f"DEBUG: Pre-snap has been saved in '{pre_snap_file}'")
    elif args.post:
        post_status = status
        if args.debug:
            print(f"DEBUG: Saving post_file = {post_snap_file}")
        with open(post_snap_file,mode = "w") as f:
            json.dump(post_status,f)
        # Load pre status to compare
        with open(pre_snap_file,mode = "r") as f:
            print(f"DEBUG: Loading pre_file = {pre_snap_file}")
            pre_status_list = json.load(f)
        pre_status = []
        router_response = namedtuple(tuple_key,settings["named_tuples"][tuple_key])
        for i in pre_status_list:
            pre_status.append(router_response(i[0],i[1],i[2]))
        # Compare pre and post status
        compare(router,pre_status,post_status)
    elif args.history:
        pre_status = []
        post_status = []
        router_response = namedtuple(tuple_key,settings["named_tuples"][tuple_key])
        with open(pre_snap_file,mode = "r") as f:
            print(f"DEBUG: Loading pre_file = {pre_snap_file}")
            pre_status_list = json.load(f)
        for i in pre_status_list:
            pre_status.append(router_response(i[0],i[1],i[2]))

        with open(post_snap_file,mode = "r") as f:
            print(f"DEBUG: Loading post_file = {post_snap_file}")
            post_status_list = json.load(f)
        for i in post_status_list:
            post_status.append(router_response(i[0],i[1],i[2]))
        compare(router,pre_status,post_status)
