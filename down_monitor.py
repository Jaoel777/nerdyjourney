#!/opt/gums/bin/python3
# -*- encoding: utf-8 -*-
# -*- coding: utf-8 -*-

import sys
import os
from os.path import expanduser
import re
import argparse
#import queue
#import subprocess
#import shlex
#import threading
import time
import datetime
import netmiko
#import ipaddress
import psycopg2
import gzip
import logging
import socket

########## Remain task ##########
#
####### Note ##########################
#
# In case of 23h range(201910040000:201910042300)
# Following are sample data.
# Downsort
#  > ifc: 7.67sec
#  > BGP: 9.47sec
#  > VC : 3.14sec
#  > Total: 20.28sec
#
# Downmonitor
#  > 21.57sec
# 
# So if removed the time.sleep from Downmonitor, the run time would approve.
#
#######################################

### ------ Set Global-val ------  ###
current_path = os.getcwd()
#q = queue.Queue()
#max_throld = 10
### ------  ------  ###


### For decolate of print
class deco(object):

    def clr(str, color):

        deco_str = ""

        BLACK = '\033[30m'
        RED = '\033[31m'
        GREEN = '\033[32m'
        YELLOW = '\033[33m'
        BLUE = '\033[34m'
        PURPLE = '\033[35m'
        CYAN = '\033[36m'
        WHITE = '\033[37m'
        END = '\033[0m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'
        INVISIBLE = '\033[08m'
        REVERCE = '\033[07m'

        if color == "red": 
            deco_str = RED + str + END
        elif color == "green":
            deco_str = GREEN + str + END
        elif color == "yellow":
            deco_str = YELLOW + str + END
        elif color == "blue":
            deco_str = BLUE + str + END
        elif color == "purple":
            deco_str = PURPLE + str + END
        elif color == "cyan":
            deco_str = CYAN + str + END
        elif color == "white":
            deco_str = WHITE + str + END
        elif color == "bold":
            deco_str = BOLD + str + END
        elif color == "under":
            deco_str = UNDERLINE + str + END
        elif color == "invisible":
            deco_str = INVISIBLE + str + END
        elif color == "reverce":
            deco_str = REVERCE + str + END

        return(deco_str)


class CreateLog():
    #def __init__(self, hour, timespan, count):
    def __init__(self, hour, timespan, count, separate, g_flag, ignore, range, asia, investigate):
        self.msg= "Run script"
        self.path= "/home/witou/logs_script/log_down_monitor.log"

        user= os.environ.get("USER")
        if user != None: self.username= user
        else: self.username= None

        #self.formatter= "%(asctime)s : {} : %(levelname)s : %(message)s : hour={}, timespan={}, count={}".format(self.username, hour, timespan, count)
        #self.formatter= "%(asctime)s : {} : %(levelname)s : %(message)s : hour={}, timespan={}, count={}, sep={}, grep={}, ignore={}, range={}, asia={}"\
        self.formatter= "%(asctime)s : {} : %(levelname)s : hour={}, timespan={}, count={}, sep={}, grep={}, ignore={}, range={}, asia={}, investigate={}"\
.format(self.username, hour, timespan, count, separate, g_flag, ignore, range, asia, investigate)

    def start(self):
        logging.basicConfig(filename= self.path, level= logging.INFO, format= self.formatter)
        logging.info("{}".format(self.msg))


class argprs:

    def run_parse():
        parser = argparse.ArgumentParser(description= "" , formatter_class=argparse.RawTextHelpFormatter)

        parser.add_argument("-hr", "--hour", default= "1", type= int, \
help= "- Designate how long past logs does search.\n\
- If input \"-hr 1\", search logs from 1hr ago thru current time. Default is set 1 hour.\n\
- ex, down_monitor.py -hr 3\n ")

        parser.add_argument("-t", "--timespan", default= "15", type= int, \
help= "- Designate what time script wait between automatically run. Default is set 15 sec.\n\
- If input \"-t 30\", script automatically run every 30 seconds end.\n\
- ex, down_monitor.py -t 30 -c 100\n ")

        parser.add_argument("-c", "--count", default= "1", type= int, \
help= "- Designate what times automatically repeat running script. Default is 1.\n\
- If input \"100\", script automaticaly run until repeatedly run 100 times.\n\
- ex, down_monitor.py -c 100 -t 30\n ")

        parser.add_argument("-s", "--separate", action= "store_true", \
help= "- Separately displayed, such as Backborn, Peer, Customer, and others.\n\
- No further value needed with this.\n\
- ex, down_monitor.py -c 100 -s\n ")

        parser.add_argument("-i", "--investigate", action= "store_true", \
help= "- Investigate via login to each router you selected.\n\
- ex, down_monitor.py -i -hr 2\n ")

        parser.add_argument("-g", "--grep", nargs= 1, type= str, \
help= "- Be able to get extracted result based on input.\n\
- Regular expression and multiple words are available.\n\
- ex, down_monitor.py -g asbnva02\n\
      down_monitor.py -g \"amstnl|frnk\"\n ")

        parser.add_argument("--ignore", action= "store_true", \
help= "- Output without turn-up circuit.\n\
- ex, down_monitor.py --ignore -c 100\n ")

        parser.add_argument("--timerange", nargs=1, type= str, \
help= "- Designate to check time-range(UTC).\n\
- Use \"--timerange YYYYMMDDhhmm:YYYYMMDDhhmm\"\n\
- ex, down_monitor.py --timerange 201910010000:201910020500\n ")

        parser.add_argument("--asia", action= "store_true", \
help= "- To display just whole of Asia region for ANOC.\n\
- ex, down_monitor.py --asia\n ")


        args = parser.parse_args()
        if args.timerange != None: argprs.check_parse(args.timerange[0])

        return(args)


    def check_parse(timerange):
        if re.match(r"^\d{12}:\d{12}$", timerange) == None:
            print("\nInvalid input. \nPlease input like following, 201910012000:201910012300 (YYYYMMDDhhmm:YYYYMMDDhhmm)\n")
            sys.exit()
        else:
            st_date= timerange.split(":")[0]
            ed_date= timerange.split(":")[1]

            ### convert input to time and take error check
            st_date= datetime.datetime.strptime(st_date, "%Y%m%d%H%M")
            ed_date= datetime.datetime.strptime(ed_date, "%Y%m%d%H%M")
            if st_date >= datetime.datetime.today() or ed_date > datetime.datetime.today() or st_date >= ed_date:
                print("Detected invalid value.\nStart time can not over current time, and end time as well.\n")
                sys.exit()


### subprocess run and get result
#cmd= ""
#z = subprocess.Popen((cmd).split(" ") , stdout=subprocess.PIPE , stderr = subprocess.PIPE)
#out , err = z.communicate()
#out.decode("utf-8")    


class Log:
    def __init__(self, input_time):
        ### Regarding LogFiles
        self.juniper_log_today= "/var/log/local5/debug"
        #self.juniper_log_today= "/home/witou/lab/debug" # For speed test
        self.cisco_log_today= "/var/log/local7/debug"
        self.nokia_log_today= "/var/log/local6/debug"
        self.juniper_log_past= ""
        self.cisco_log_past= ""
        self.nokia_log_past= ""
        self.log_list= []


        ### Regarding TimeVariable
        self.current_time= datetime.datetime.today() #            #type: delta, value: current_time
        self.input_time_delta= datetime.timedelta(hours= input_time)  #type: delta, value: input_time
        self.additional_time_delta= datetime.timedelta(seconds= 1)    #type: delta, value: 1second
        self.additional_day_delta= datetime.timedelta(days= 1)        #type: delta, value: 1day
        self.start_time= self.current_time - self.input_time_delta    #type: delta, value: start-time
        self.end_time= self.current_time + self.additional_time_delta #type: delta, value: end-time
        self.start_time_str= ""
        self.end_time_str= self.end_time.strftime("%H:%M:%S") # Store variable at here for rapid process(Not compare STRINGS VS VARIABLE)
        self.origin_start_time= self.start_time.strftime("%b %d %H:%M:%S")
        self.origin_end_time= self.end_time.strftime("%b %d %H:%M:%S")


        ### Regarding SearchWords
        ## Common
        self.search_router= re.compile(r"\D\d{2}\.\D{6}\d{2}\.\D{2}\.\D{2}")
        self.search_remove= re.compile(r"Internal|AS: 65000")
        self.search_timestamp= re.compile(r"^\w{3}\s+\d+\s{1}\d{2}:\d{2}:\d{2}")

        ## Juniper
        #self.juniper_search_all= re.compile(r"SNMP_TRAP_LINK_DOWN|SNMP_TRAP_LINK_UP|RPD_BGP_NEIGHBOR_STATE_CHANGED|RPD_LAYER2_VC_DOWN")
        self.juniper_ifc_down= "SNMP_TRAP_LINK_DOWN"
        self.juniper_ifc_up= "SNMP_TRAP_LINK_UP"
        self.juniper_bgp= "RPD_BGP_NEIGHBOR_STATE_CHANGED"
        self.juniper_vcdown= "RPD_LAYER2_VC_DOWN"
        self.juniper_vcup= "RPD_LAYER2_VC_UP"
        self.juniper_search_all= re.compile(r"{}|{}|{}|{}|{}".format(self.juniper_ifc_down,self.juniper_ifc_up,self.juniper_bgp,self.juniper_vcdown,self.juniper_vcup))
        self.juniper_search_ifcdown= "down(2)"
        self.juniper_search_bgp= re.compile(r"BGP peer (\S+) \(\w{2}ternal AS (\S+)\) changed state from (\S+) to (\S+)")
        self.juniper_search_bgpdown= "Established to Idle"
        self.juniper_search_bgpup= "to Established"
        self.juniper_search_time= re.compile(r"\D{3}\s+\d+ \d{2}:\d{2}:\d{2}")  
        # VC
        self.juniper_vcid= re.compile(r"VC-ID : \d+")


        ## Cisco
        self.cisco_ifc= "PKT_INFRA-LINK-3-UPDOWN"
        self.cisco_bgp= "ROUTING-BGP-5-ADJCHANGE"
        self.cisco_vc= "L2-L2VPN_PW-3-UPDOWN"
        self.cisco_search_all= re.compile(r"{}|{}|{}".format(self.cisco_ifc, self.cisco_bgp, self.cisco_vc))

        self.cisco_ifc_down= re.compile(r"Interface (\S+) changed state to Down")
        self.cisco_ifc_up= re.compile(r"Interface (\S+) changed state to Up")
        self.cisco_bgpdown= re.compile(r"neighbor (\S+) Down")
        self.cisco_bgpup= re.compile(r"neighbor (\S+) Up")
        self.cisco_vcdown= re.compile(r"address (\S+) id  (\S+) state is changed to: Down")
        self.cisco_vcup= re.compile(r"address (\S+) id  (\S+) state is changed to: Up")

        self.cisco_search_time= self.juniper_search_time
    
                ## Nokia
        self.nokia_ifc= "SNMP-WARNING-link"
        self.nokia_bgp= "Base BGP"
        self.nokia_vc= "SVCMGR-MINOR-sdpBindStatusChanged"
        self.nokia_search_all= re.compile(r"{}|{}|{}".format(self.nokia_ifc, self.nokia_bgp, self.nokia_vc))
        
        self.nokia_ifc_down= re.compile(r"Interface (\S+) is not operational")
        self.nokia_ifc_up= re.compile(r"Interface (\S+) is operational")
        self.nokia_bgpdown= re.compile(r"Peer (\S+): moved from higher state ESTABLISHED to lower state")
        self.nokia_bgpup= re.compile(r"Peer (\S+): moved into established state")
        #self.nokia_vcdown= re.compile(r"Status of SDP Bind \d+:(\S+) in service \d+ \(customer \d+\) local PW status bits changed to lacIngressFault")
        #self.nokia_vcup= re.compile(r"Status of SDP Bind \d+:(\S+) in service \d+ \(customer \d+\) local PW status bits changed to none")
        self.nokia_vcdown = re.compile(r"oper=down")
        self.nokia_vcup = re.compile(r"oper=up")
        self.nokia_vcid = re.compile(r"SDP\s+Bind\s+\d+\:(\d+)")

        
        self.nokia_search_time= self.juniper_search_time

        ### Regarding ResultVariable
        self.getval_juniper= ""
        self.getval_cisco= ""
        self.getval_nokia= ""
        self.ifc_count_dict= {}
        self.ifc_state_dict= {}
        self.ebgp_count_dict= {}
        self.ebgp_state_dict= {}
        self.ibgp_count_dict= {}
        self.ibgp_state_dict= {}
        self.vc_count_dict= {}
        self.vc_state_dict= {}


    def get(self, timerange):
        ### Decision either timerange or overnight or not
        ### timerange option is enable
        if timerange != "None":
            ### Update time value
            #print("start: {}".format(datetime.datetime.today()))
            self.start_time= datetime.datetime.strptime(timerange.split(":")[0], "%Y%m%d%H%M")
            self.end_time= datetime.datetime.strptime(timerange.split(":")[1], "%Y%m%d%H%M")
            self.origin_start_time= self.start_time.strftime("%b %d %H:%M:%S")
            self.origin_end_time= self.end_time.strftime("%b %d %H:%M:%S")

            ### Check the range is whether too long or not
            diff= self.end_time - self.start_time
            #print("diff= {} , (type is {})".format(diff, type(diff)))
            if diff > datetime.timedelta(days= 5):
                print("\nThis time-range is too long. Please input the range should be within 5days.\n\
                    If you have to get beyond 5 days, please contact Wataru as I remove limitter.")
                sys.exit()

            ### Make log list in case of time-range option
            self.make_timerange_list() # Create log list needed

            ### Open logs
            self.openlog_timerange_juniper()
            self.openlog_timerange_cisco()
            self.openlog_timerange_nokia()

        ### Only open debug log.
        elif self.start_time.strftime("%d") == self.end_time.strftime("%d"):
            #print("\nCheck logs {} to {}".format(self.start_time.strftime("%b %d %H:%M:%S"), self.end_time.strftime("%b %d %H:%M:%S")))
            self.openlog_today_juniper()
            self.openlog_today_cisco()
            self.openlog_today_nokia()

        ### Open both of .gz and debug.log
        else:
            ### make past log list without debug.log
            self.make_pastlog_list()

            ### Open logs with log.gz and debug.log
            self.openlog_past_juniper()
            self.openlog_past_cisco()
            self.openlog_past_nokia()

        ### Organized dictionary
        self.make_outage_dict_juniper()
        self.make_outage_dict_cisco()
        self.make_outage_dict_nokia()

        return(self.ifc_state_dict, self.ifc_count_dict, self.ebgp_state_dict,\
            self.ebgp_count_dict, self.ibgp_state_dict, self.ibgp_count_dict, self.vc_state_dict, self.vc_count_dict,\
            self.origin_start_time, self.origin_end_time)


    def remove_beyond_time(self, val_list):
        remove_flag= 0
        del_list= []

        for num,val in enumerate(val_list):
            #pick_time= re.match(r"^\w{3}\s+\d+\s{1}\d{2}:\d{2}:\d{2}", val).group()
            pick_time= self.search_timestamp.match(val).group()
            pick_time= datetime.datetime.strptime(pick_time, "%b %d %H:%M:%S")
            if pick_time.strftime("%m%d%H%M%S") > self.end_time.strftime("%m%d%H%M%S"): del val_list[num:]

        #print("strftime: {}".format(type(pick_time.strftime("%m%d%H%M%S"))))
        #print("pick_time: {}".format(type(pick_time)))

        return(val_list)


    def make_timerange_list(self):
        #print("Current: {}".format(self.current_time))
        #print("End: {}".format(self.end_time))

        ### TIMERANGE is within today
        if self.start_time.strftime("%Y%m%d") == self.end_time.strftime("%Y%m%d") and self.start_time.strftime("%Y%m%d") == self.current_time.strftime("%Y%m%d"):
            self.log_list.append("debug")
            return()

        while True:
            #time.sleep(1)
            tmp_time= self.start_time + self.additional_day_delta
            #print(tmp_time)
            #print(self.end_time)

            ### Break decision after add 1day
            if tmp_time > self.end_time and self.end_time.strftime("%Y%m%d") == self.current_time.strftime("%Y%m%d"):
                #print("Added due to tmp_time {} beyond end_time {}. List is {}".format(tmp_time, self.end_time, self.log_list))
                self.log_list.append("debug")
                break
            elif tmp_time > self.end_time:
                #print("Added due to tmp_time {} beyond current_time {}. List is {}".format(tmp_time, self.end_time, self.log_list))
                self.log_list.append("debug-{}.gz".format(tmp_time.strftime("%Y%m%d")))
                break
            elif tmp_time > self.current_time: break

            self.log_list.append("debug-{}.gz".format(tmp_time.strftime("%Y%m%d")))
            self.additional_day_delta+= datetime.timedelta(days= 1)

        #print(self.log_list)
        #sys.exit()

    def make_pastlog_list(self):
        while True:
            time.sleep(1)
            tmp_time= self.start_time + self.additional_day_delta
            self.log_list.append("debug-{}.gz".format(tmp_time.strftime("%Y%m%d")))
            if tmp_time.strftime("%Y%m%d") == self.end_time.strftime("%Y%m%d"): break
            self.additional_day_delta+= datetime.timedelta(days= 1)


    ### Search in Debug (mean Today) JUNIPER
    def openlog_today_juniper(self):
        tmplist= [] # for join as a string at after loop

        try:
            while True:
                with open(self.juniper_log_today, mode= "r", encoding= "utf-8", errors= "replace") as r:
                    ### initialize variable for loop
                    start_flg= 0
                    if re.search(r"0\d", self.start_time.strftime("%d")) != None:
                        self.start_time_str= self.start_time.strftime("%b  %-d %H:%M:%S") # Store variable at here for rapid process
                    else:
                        self.start_time_str= self.start_time.strftime("%b %d %H:%M:%S") # Store variable at here for rapid process
                    #### NOTE: In case of search %H%M%S, mis-pick regarding to STP log

                    for i in r.readlines():
                        if start_flg == 1 and re.search(self.juniper_search_all, i) != None:
                            tmplist.append(i)
                            continue
                        elif start_flg == 1: continue

                        ### start or finish decision by using FIND/VARIABLE search
                        if i.find(self.start_time_str) != -1: 
                            start_flg= 1 # make start_flag

                    ### decision either loop again or finish loop
                    if start_flg == 0:
                        self.start_time= self.start_time + self.additional_time_delta # add 1second
                    elif start_flg == 1:
                        break

            self.getval_juniper= "".join(tmplist) # self.getval have all of log picked.

        except KeyboardInterrupt:
            print("\nInterrupt Forcely")
            sys.exit()


    ### Function of search in past to today log of juniper
    def openlog_past_juniper(self):
        tmplist_past_juniper= []
        past_flag_juniper= 0
        start_flg= 0

        try:
            while True:
                for past_log in self.log_list:

                    if past_flag_juniper == 0:
                        while (past_flag_juniper == 0):
                            past_log_filename_juniper= "/var/log/local5/{}".format(past_log)
                            with gzip.open(past_log_filename_juniper, mode= "rt", encoding= "utf-8", errors= "replace") as r:
                    
                                time.sleep(1)

                                ### Set searching timestamp
                                if re.search(r"0\d", self.start_time.strftime("%d")) != None:
                                    self.start_time_str= self.start_time.strftime("%b  %-d %H:%M:%S")
                                else:
                                    self.start_time_str= self.start_time.strftime("%b %d %H:%M:%S")

                                ### start read lines
                                for i in r.readlines():

                                    ### get and write logs to getval => Most rapid way with join
                                    if start_flg == 1 and re.search(self.juniper_search_all, i) != None:
                                        tmplist_past_juniper.append(i)
                                        continue

                                    if start_flg == 1: continue

                                    ### find first line matching time at first.After that the match line decision whether
                                    if i.find(self.start_time_str) != -1:
                                        start_flg= 1 # make start_flag
                                        if re.search(self.juniper_search_all, i) != None: tmplist_past_juniper.append(i)


                                ### decision either loop again or finish loop
                                if start_flg == 0:
                                    self.start_time= self.start_time + self.additional_time_delta # add 1second
                                    continue
                                else:
                                    past_flag_juniper= 1
                                    break

                    elif past_flag_juniper == 1: ### If opened log file isn't first file, it has to check all lines in logs.
                        past_log_filename_juniper= "/var/log/local5/{}".format(past_log)
                        with gzip.open(past_log_filename_juniper, mode= "rt", encoding= "utf-8", errors= "replace") as r:

                            for i in r.readlines():
                                if re.search(self.juniper_search_all, i) != None: tmplist_past_juniper.append(i)

                ### today log start from here
                with open(self.juniper_log_today, "r") as r:
                    for i in r.readlines():
                        ### start or finish decision by using FIND/VARIABLE search
                        if i.find(self.end_time_str) != -1: break # Decision of end. But if nothing, maybe no issue.

                        ### get and write logs to getval => Most rapid way with join
                        elif re.search(self.juniper_search_all, i) != None: tmplist_past_juniper.append(i)
                    break

            self.getval_juniper= "".join(tmplist_past_juniper) # self.getval have all of log picked.

        except KeyboardInterrupt:
            print("\nInterrupt Forcely")
            sys.exit()


    def openlog_timerange_juniper(self):
        ### Initialize variable
        tmplist_timerange_juniper= []
        start_flg= 0

        ### For debug-print
        #print("\nStart of Juniper time: {}".format(datetime.datetime.today()))
        #print("log_list: {}".format(self.log_list))

        ### Set end time accordingly by day of date due to format deferrence.
        if re.search(r"0\d", self.end_time.strftime("%d")) != None:
            self.end_time_str= self.end_time.strftime("%b  %-d %H:%M:%S")
        else:
            self.end_time_str= self.end_time.strftime("%b %d %H:%M:%S")

        ### Loop start to open/analyze log-file
        try:
            for past_log in self.log_list:
                ### Make completion filename
                past_log_filename_juniper= "/var/log/local5/{}".format(past_log)
                #print(past_log_filename_juniper)

                ### After first file checking completed, as start_flg is remaining as a 1, be able to search all line in log after that.
                while True:
                    #time.sleep(1)
                    ### Set search-word accordingly by day of date
                    if re.search(r"0\d", self.start_time.strftime("%d")) != None:
                        self.start_time_str= self.start_time.strftime("%b  %-d %H:%M:%S")
                    else:
                        self.start_time_str= self.start_time.strftime("%b %d %H:%M:%S")

                    ### Open log file
                    if re.search(r"gz$", past_log_filename_juniper) != None:
                        with gzip.open(past_log_filename_juniper, mode= "rt", encoding= "utf-8", errors= "replace") as r:
                            ### Start loop internal archived log file opened
                            for i in r.readlines():

                                ### MEMO: This algorithm performance is too SLOW. Should use "fidn" method.
                                #pick_time= self.search_timestamp.match(i).group()
                                #pick_time= datetime.datetime.strptime(pick_time, "%b %d %H:%M:%S")
                                #if pick_time.strftime("%m%d%H%M%S") >= self.end_time.strftime("%m%d%H%M%S"):
                                #   print("find beyond time: {}".format(pick_time))
                                #   print("the end time: {}".format(datetime.datetime.today()))
                                #   sys.exit()

                                if i.find(self.end_time_str) != -1: break
                                if start_flg == 1 and re.search(self.juniper_search_all, i) != None:
                                    tmplist_timerange_juniper.append(i)
                                    continue
                                if start_flg == 1: continue
                                if i.find(self.start_time_str) != -1:
                                    start_flg= 1
                                    #print("End of set startflag:{}".format(datetime.datetime.today()))
                                    if re.search(self.juniper_search_all, i) != None: tmplist_timerange_juniper.append(i)
                    else:
                        with open(past_log_filename_juniper, mode= "rt", encoding= "utf-8", errors= "replace") as r:
                            ### Start loop internal log file opened
                            for i in r.readlines():
                                if i.find(self.end_time_str) != -1: break
                                if start_flg == 1 and re.search(self.juniper_search_all, i) != None:
                                    tmplist_timerange_juniper.append(i)
                                    continue
                                if start_flg == 1: continue
                                if i.find(self.start_time_str) != -1:
                                    start_flg= 1
                                    #print("End of set startflag:{}".format(datetime.datetime.today()))
                                    if re.search(self.juniper_search_all, i) != None: tmplist_timerange_juniper.append(i)

                    ### If flag = 0, not added any log-line
                    if start_flg == 0:
                        self.start_time= self.start_time + self.additional_time_delta # add 1second
                        #print("Added time 1sec:{}".format(datetime.datetime.today()))
                        continue
                    else:
                        break

        except KeyboardInterrupt:
            print("\nInterrupt Forcely")
            sys.exit()

        ### Just for timespan option to remove beyond the end_time
        tmplist_timerange_juniper= self.remove_beyond_time(tmplist_timerange_juniper)

        ### Final merge log-lines picked
        self.getval_juniper= "".join(tmplist_timerange_juniper) # self.getval have all of log picked.


    ### Create Dictionary of JUNIPER
    def make_outage_dict_juniper(self):
# MEMO #
# self.ifc_count_dict= {} => [rt ifc] : count
# self.ifc_state_dict= {} => [rt ifc] : [last-down-time, last status]

        tmplist= []

        # Term of juniper
        for i in self.getval_juniper.splitlines():
        ##### START IFC Phase #####

            ### when the down find
            if i.find(self.juniper_ifc_down) != -1:
                ### store time and latest status as a "[rt ifc] = [last-down-time, down]"
                match_rt= self.search_router.search(i)
                ifc= i.split(" ")[-1]
                #rt_ifc= match_rt.group(0) + " " + i.split(" ")[-1]
                rt_ifc= match_rt.group(0) + " " + ifc.split(".")[0]
                t= self.juniper_search_time.match(i)
                tmplist.append(t.group(0))
                tmplist.append("down")
                self.ifc_state_dict[rt_ifc]= tmplist
                tmplist= []

                ### store count info as a "[rt ifc] : count"
                if (rt_ifc in self.ifc_count_dict) == True: self.ifc_count_dict[rt_ifc]+= 1
                else: self.ifc_count_dict[rt_ifc]= 1

            ### when the up find, only perform update status for "[rt ifc] = [last-down-time, up]"
            elif i.find(self.juniper_ifc_up) != -1:
                match_rt= self.search_router.search(i)
                rt_ifc= match_rt.group(0) + " " + i.split(" ")[-1]
                if (rt_ifc in self.ifc_state_dict) == True: ### this needs to make after re_ifc varivable made.
                    self.ifc_state_dict[rt_ifc][1]= "up"
        ##### END IFC Phase #####

        ##### START iBGP Phase #####
            ### When the down find,
            elif i.find(self.juniper_search_bgpdown) != -1 and self.search_remove.search(i) != None:
                match_rt= self.search_router.search(i) ### Get router name
                peer_addr= self.juniper_search_bgp.search(i) ### Get peer address
                rt_peer= match_rt.group(0) + " " + peer_addr.group(0).split(" ")[2] ### merge
                t= self.juniper_search_time.match(i) ### Get time stamp

                tmplist.append(t.group(0))
                tmplist.append("down")
                self.ibgp_state_dict[rt_peer]= tmplist
                tmplist= []

                ### store count info
                if (rt_peer in self.ibgp_count_dict) == True: self.ibgp_count_dict[rt_peer]+= 1
                else: self.ibgp_count_dict[rt_peer]= 1

            ### When the up find,
            elif i.find(self.juniper_bgp) != -1 and i.find(self.juniper_search_bgpup) != -1 and self.search_remove.search(i) != None:
                match_rt= self.search_router.search(i) ### Get router name
                peer_addr= self.juniper_search_bgp.search(i) ### Get peer address
                rt_peer= match_rt.group(0) + " " + peer_addr.group(0).split(" ")[2] ### merge

                if (rt_peer in self.ibgp_state_dict) == True:
                    self.ibgp_state_dict[rt_peer][1]= "up"
        ##### END iBGP Phase #####

        ##### START eBGP Phase #####
            ### When the down find,
            elif i.find(self.juniper_search_bgpdown) != -1:
                match_rt= self.search_router.search(i) ### Get router name
                peer_addr= self.juniper_search_bgp.search(i) ### Get peer address
                rt_peer= match_rt.group(0) + " " + peer_addr.group(0).split(" ")[2] ### merge
                t= self.juniper_search_time.match(i) ### Get time stamp

                tmplist.append(t.group(0))
                tmplist.append("down")
                self.ebgp_state_dict[rt_peer]= tmplist
                tmplist= []

                ### store count info
                if (rt_peer in self.ebgp_count_dict) == True: self.ebgp_count_dict[rt_peer]+= 1
                else: self.ebgp_count_dict[rt_peer]= 1

            ### When the up find,
            elif i.find(self.juniper_bgp) != -1 and i.find(self.juniper_search_bgpup) != -1:
                match_rt= self.search_router.search(i) ### Get router name
                peer_addr= self.juniper_search_bgp.search(i) ### Get peer address
                rt_peer= match_rt.group(0) + " " + peer_addr.group(0).split(" ")[2] ### merge

                if (rt_peer in self.ebgp_state_dict) == True:
                    self.ebgp_state_dict[rt_peer][1]= "up"
        ##### END eBGP Phase #####


        ##### START VC Phase #####
            elif i.find(self.juniper_vcdown) != -1:
                match_rt= self.search_router.search(i) ### Get router name
                vcid= self.juniper_vcid.search(i) ### Get vc-id
                rt_vcid= match_rt.group(0) + " " + vcid.group(0).split(" ")[-1] ### merge
                t= self.juniper_search_time.match(i) ### Get time-stamp

                tmplist.append(t.group(0))
                tmplist.append("down")
                self.vc_state_dict[rt_vcid]= tmplist
                tmplist= []

                ### store count info
                if (rt_vcid in self.vc_count_dict) == True: self.vc_count_dict[rt_vcid] += 1
                self.vc_count_dict[rt_vcid]= 1


            elif i.find(self.juniper_vcup) != -1:
                match_rt= self.search_router.search(i) ### Get router name
                vcid= self.juniper_vcid.search(i) ### Get vc-id
                rt_vcid= match_rt.group(0) + " " + vcid.group(0).split(" ")[-1] ### merge

                if (rt_vcid in self.vc_state_dict) == True:
                    self.vc_state_dict[rt_vcid][1]= "up"


    ### get today log of CISCO
    def openlog_today_cisco(self):
        tmplist= [] # for join as a string at after loop

        try:
            while True:
                with open(self.cisco_log_today, mode= "r", encoding= 'utf-8', errors= 'replace') as r:
                    ### initialize variable for loop
                    start_flg= 0

                    if re.search(r"0\d", self.start_time.strftime("%d")) != None:
                        self.start_time_str= self.start_time.strftime("%b  %-d %H:%M:%S") # Store variable at here for rapid process
                    else:
                        self.start_time_str= self.start_time.strftime("%b %d %H:%M:%S") # Store variable at here for rapid process

                    for i in r.readlines():
                        ### get and write logs to getval => Most rapid way with join
                        if start_flg == 1 and re.search(self.cisco_search_all, i) != None: tmplist.append(i)
                        elif start_flg == 1: continue

                        ### start or finish decision by using FIND/VARIABLE search
                        if i.find(self.start_time_str) != -1: start_flg= 1 # make start_flag

                    ### decision either loop again or finish loop
                    if start_flg == 0:
                        self.start_time= self.start_time + self.additional_time_delta # add 1second
                    elif start_flg == 1: break

            self.getval_cisco= "".join(tmplist) # self.getval have all of log picked.

        except KeyboardInterrupt:
            print("\nInterrupt Forcely")
            sys.exit()


    ### Search in past to today log of CISCO
    def openlog_past_cisco(self):
        tmplist_past_cisco= []
        past_flag_cisco= 0
        start_flg= 0

        try:
            while True:
                for past_log_cisco in self.log_list:
                    if past_flag_cisco == 0:
                        while (past_flag_cisco == 0):
                            past_log_filename_cisco= "/var/log/local7/{}".format(past_log_cisco)
                            with gzip.open(past_log_filename_cisco, mode= "rt", encoding= "utf_8", errors= "replace") as r:
                                time.sleep(1)
                                ### initialize variable for loop
                                if re.search(r"0\d", self.start_time.strftime("%d")) != None:
                                    self.start_time_str= self.start_time.strftime("%b  %-d %H:%M:%S")
                                else:
                                    self.start_time_str= self.start_time.strftime("%b %d %H:%M:%S")

                                for i in r.readlines():
                                    ### get and write logs to getval => Most rapid way with join
                                    if start_flg == 1 and re.search(self.cisco_search_all, i) != None:
                                        tmplist_past_cisco.append(i)

                                    ### Continue for pass below "find" performance
                                    if start_flg == 1: continue

                                    ### start or finish decision by using FIND/VARIABLE search
                                    if i.find(self.start_time_str) != -1:
                                        start_flg= 1 # make start_flag
                                        if re.search(self.cisco_search_all, i) != None: tmplist_past_cisco.append(i)

                                ### decision either loop again or finish loop
                                if start_flg == 0:
                                    self.start_time= self.start_time + self.additional_time_delta # add 1second
                                    continue
                                else:
                                    past_flag_cisco= 1
                                    break

                    elif past_flag_cisco == 1: ### If log file opened is not first file, it has to check all of lines in logs.
                            past_log_filename_cisco= "/var/log/local7/{}".format(past_log_cisco)
                            with gzip.open(past_log_filename_cisco, mode= "rt", encoding= "utf_8", errors= "replace") as r:
                                for i in r.readlines():
                                    if re.search(self.cisco_search_all, i) != None: tmplist_past_cisco.append(i)

                ### today log start from here
                with open(self.cisco_log_today, "r") as r:
                    #print("Open {} : start sleep cisco for 1sec".format(self.cisco_log_today))
                    #time.sleep(1)

                    for i in r.readlines():
                        ### start or finish decision by using FIND/VARIABLE search
                        if i.find(self.end_time_str) != -1: break # Decision of end. But if nothing, maybe no issue.

                        ### get and write logs to getval => Most rapid way with join
                        elif re.search(self.cisco_search_all, i) != None: tmplist_past_cisco.append(i)
                    break

            self.getval_cisco= "".join(tmplist_past_cisco) # self.getval have all of log picked.

        except KeyboardInterrupt:
            print("\nInterrupt Forcely")
            sys.exit()


    ### Search in timerange log CISCO
    def openlog_timerange_cisco(self):
        ### Initialie variable
        tmplist_timerange_cisco= []
        start_flg= 0

        ### Re-set end time accordingly by day of date
        if re.search(r"0\d", self.end_time.strftime("%d")) != None:
            self.end_time_str= self.end_time.strftime("%b  %-d %H:%M:%S")
        else:
            self.end_time_str= self.end_time.strftime("%b %d %H:%M:%S")

        try:
            for past_log in self.log_list:
                past_log_filename_cisco= "/var/log/local7/{}".format(past_log)

                while True:
                    #time.sleep(1)
                    ### Re-set start time acccordingly by day of date
                    if re.search(r"0\d", self.start_time.strftime("%d")) != None:
                        self.start_time_str= self.start_time.strftime("%b  %-d %H:%M:%S")
                    else:
                        self.start_time_str= self.start_time.strftime("%b %d %H:%M:%S")

                    ### Open log
                    if re.search(r"gz$", past_log_filename_cisco) != None:
                        with gzip.open(past_log_filename_cisco, mode= "rt", encoding= "utf-8", errors= "replace") as r:
                            ### Start loop internal archived log file opened
                            for i in r.readlines():
                                if i.find(self.end_time_str) != -1: break
                                elif start_flg == 1 and re.search(self.cisco_search_all, i) != None:
                                    tmplist_timerange_cisco.append(i)
                                    continue
                                elif start_flg == 1: continue
                                elif i.find(self.start_time_str) != -1:
                                    start_flg= 1
                                    if re.search(self.cisco_search_all, i) != None: tmplist_timerange_cisco.append(i)

                    else:
                        with open(past_log_filename_cisco, mode= "rt", encoding= "utf-8", errors= "replace") as r:
                            for i in r.readlines():
                                if i.find(self.end_time_str) != -1: break
                                elif start_flg == 1 and re.search(self.cisco_search_all, i) != None:
                                    tmplist_timerange_cisco.append(i)
                                    continue
                                elif start_flg == 1: continue
                                elif i.find(self.start_time_str) != -1:
                                    start_flg= 1
                                    if re.search(self.cisco_search_all, i) != None: tmplist_timerange_cisco.append(i)

                    if start_flg == 0:
                        self.start_time= self.start_time + self.additional_time_delta # add 1second
                        continue
                    else:
                        break

        except KeyboardInterrupt:
            print("\nInterrupt Forcely")
            sys.exit()

        ### Just for timespan option to remove beyond the end_time
        tmplist_timerange_cisco= self.remove_beyond_time(tmplist_timerange_cisco)

        ### Merge from list to str
        self.getval_cisco= "".join(tmplist_timerange_cisco)


    def make_outage_dict_cisco(self):
        
        tmplist_cisco= []

        # Term of cisco
        for i in self.getval_cisco.splitlines():


        ##### START IFC Phase #####
            ### when the down find
            if re.search(self.cisco_ifc_down, i) != None:
                ### store time and latest status as a "[rt ifc] = [last-down-time, down]"
                match_rt= self.search_router.search(i)
                rt_ifc= match_rt.group(0) + " " + i.split(" ")[-6].strip(",")
                rt_ifc= rt_ifc.lower()
                t= self.cisco_search_time.match(i)
                tmplist_cisco.append(t.group(0))
                tmplist_cisco.append("down")
                self.ifc_state_dict[rt_ifc]= tmplist_cisco
                tmplist_cisco= []

                ### store count info as a "[rt ifc] : count"
                if (rt_ifc in self.ifc_count_dict) == True: self.ifc_count_dict[rt_ifc]+= 1
                else: self.ifc_count_dict[rt_ifc]= 1

            ### when the up find, only perform update status for "[rt ifc] = [last-down-time, up]"
            elif re.search(self.cisco_ifc_up, i) != None:
                match_rt= self.search_router.search(i)
                rt_ifc= match_rt.group(0) + " " + i.split(" ")[-6].strip(",")
                rt_ifc= rt_ifc.lower()
                if (rt_ifc in self.ifc_state_dict) == True: ### this needs to make after re_ifc varivable made.
                    self.ifc_state_dict[rt_ifc][1]= "up"
        ##### END IFC Phase #####

        ##### START iBGP Phase #####
            ### When the down find, and it is iBGP
            elif re.search(self.cisco_bgpdown, i) != None and self.search_remove.search(i) != None:
                match_rt= self.search_router.search(i) ### Get router name
                rt_peer= match_rt.group(0) + " " + self.cisco_bgpdown.search(i).group(0).split(" ")[1] ### merge
                t= self.cisco_search_time.match(i) ### Get time stamp

                tmplist_cisco.append(t.group(0))
                tmplist_cisco.append("down")
                self.ibgp_state_dict[rt_peer]= tmplist_cisco
                tmplist_cisco= []

                ### store count info
                if (rt_peer in self.ibgp_count_dict) == True: self.ibgp_count_dict[rt_peer]+= 1
                else: self.ibgp_count_dict[rt_peer]= 1

            ### When the up find, and it is iBGP
            elif re.search(self.cisco_bgpup, i) != None:
                match_rt= self.search_router.search(i) ### Get router name
                rt_peer= match_rt.group(0) + " " + self.cisco_bgpup.search(i).group(0).split(" ")[1] ### merge

                if (rt_peer in self.ibgp_state_dict) == True:
                    self.ibgp_state_dict[rt_peer][1]= "up"
        ##### END iBGP Phase #####

        ##### START eBGP Phase #####
            ### When the down find, and it is eBGP
            elif re.search(self.cisco_bgpdown, i) != None:
                match_rt= self.search_router.search(i) ### Get router name
                rt_peer= match_rt.group(0) + " " + self.cisco_bgpdown.search(i).group(0).split(" ")[1] ### merge
                t= self.cisco_search_time.match(i) ### Get time stamp

                tmplist_cisco.append(t.group(0))
                tmplist_cisco.append("down")
                self.ebgp_state_dict[rt_peer]= tmplist_cisco
                tmplist_cisco= []

                ### store count info
                if (rt_peer in self.ebgp_count_dict) == True: self.ebgp_count_dict[rt_peer]+= 1
                else: self.ebgp_count_dict[rt_peer]= 1

            ### When the up find, and it is eBGP
            elif re.search(self.cisco_bgpup, i) != None:
                match_rt= self.search_router.search(i) ### Get router name
                rt_peer= match_rt.group(0) + " " + self.cisco_bgpup.search(i).group(0).split(" ")[1] ### merge

                if (rt_peer in self.ebgp_state_dict) == True:
                    self.ebgp_state_dict[rt_peer][1]= "up"
        ##### END eBGP Phase #####


        ##### START VC Phase #####
            #elif i.find(self.cisco_vcdown) != -1:
            elif re.search(self.cisco_vcdown, i) != None:
                match_rt= self.search_router.search(i) ### Get router name
                vcid= self.cisco_vcdown.search(i) ### Get vc-id
                rt_vcid= match_rt.group(0) + " " + vcid.group(0).split(" ")[4].strip(",") ### merge
                t= self.cisco_search_time.match(i) ### Get time-stamp

                tmplist_cisco.append(t.group(0))
                tmplist_cisco.append("down")
                self.vc_state_dict[rt_vcid]= tmplist_cisco
                tmplist_cisco= []

                ### store count info
                if (rt_vcid in self.vc_count_dict) == True: self.vc_count_dict[rt_vcid] += 1
                else: self.vc_count_dict[rt_vcid]= 1


            #elif i.find(self.cisco_vcup) != -1:
            elif re.search(self.cisco_vcup, i) != None:
                match_rt= self.search_router.search(i) ### Get router name
                vcid= self.cisco_vcup.search(i) ### Get vc-id
                rt_vcid= match_rt.group(0) + " " + vcid.group(0).split(" ")[4].strip(",") ### merge

                if (rt_vcid in self.vc_state_dict) == True:
                    self.vc_state_dict[rt_vcid][1]= "up"


    def openlog_today_nokia(self):
        tmplist= [] # for join as a string at after loop

        try:
            while True:
                with open(self.nokia_log_today, mode= "r", encoding= "utf-8", errors= "replace") as r:
                    ### initialize variable for loop
                    start_flg= 0
                    if re.search(r"0\d", self.start_time.strftime("%d")) != None:
                        self.start_time_str= self.start_time.strftime("%b  %-d %H:%M:%S") # Store variable at here for rapid process
                    else:
                        self.start_time_str= self.start_time.strftime("%b %d %H:%M:%S") # Store variable at here for rapid process
                    #### NOTE: In case of search %H%M%S, mis-pick regarding to STP log

                    for i in r.readlines():
                        if start_flg == 1 and re.search(self.nokia_search_all, i) != None:
                            tmplist.append(i)
                            continue
                        elif start_flg == 1: continue

                        ### start or finish decision by using FIND/VARIABLE search
                        if i.find(self.start_time_str) != -1: 
                            start_flg= 1 # make start_flag

                    ### decision either loop again or finish loop
                    if start_flg == 0:
                        self.start_time= self.start_time + self.additional_time_delta # add 1second
                    elif start_flg == 1:
                        break

            self.getval_nokia= "".join(tmplist) # self.getval have all of log picked.

        except KeyboardInterrupt:
            print("\nInterrupt Forcely")
            sys.exit()


    ### Function of search in past to today log of nokia
    def openlog_past_nokia(self):
        tmplist_past_nokia= []
        past_flag_nokia= 0
        start_flg= 0

        try:
            while True:
                for past_log in self.log_list:

                    if past_flag_nokia == 0:
                        while (past_flag_nokia == 0):
                            past_log_filename_nokia= "/var/log/local5/{}".format(past_log)
                            with gzip.open(past_log_filename_nokia, mode= "rt", encoding= "utf-8", errors= "replace") as r:
                    
                                time.sleep(1)

                                ### Set searching timestamp
                                if re.search(r"0\d", self.start_time.strftime("%d")) != None:
                                    self.start_time_str= self.start_time.strftime("%b  %-d %H:%M:%S")
                                else:
                                    self.start_time_str= self.start_time.strftime("%b %d %H:%M:%S")

                                ### start read lines
                                for i in r.readlines():

                                    ### get and write logs to getval => Most rapid way with join
                                    if start_flg == 1 and re.search(self.nokia_search_all, i) != None:
                                        tmplist_past_nokia.append(i)
                                        continue

                                    if start_flg == 1: continue

                                    ### find first line matching time at first.After that the match line decision whether
                                    if i.find(self.start_time_str) != -1:
                                        start_flg= 1 # make start_flag
                                        if re.search(self.nokia_search_all, i) != None: tmplist_past_nokia.append(i)


                                ### decision either loop again or finish loop
                                if start_flg == 0:
                                    self.start_time= self.start_time + self.additional_time_delta # add 1second
                                    continue
                                else:
                                    past_flag_nokia= 1
                                    break

                    elif past_flag_nokia == 1: ### If opened log file isn't first file, it has to check all lines in logs.
                        past_log_filename_nokia= "/var/log/local5/{}".format(past_log)
                        with gzip.open(past_log_filename_nokia, mode= "rt", encoding= "utf-8", errors= "replace") as r:

                            for i in r.readlines():
                                if re.search(self.nokia_search_all, i) != None: tmplist_past_nokia.append(i)

                ### today log start from here
                with open(self.nokia_log_today, "r") as r:
                    for i in r.readlines():
                        ### start or finish decision by using FIND/VARIABLE search
                        if i.find(self.end_time_str) != -1: break # Decision of end. But if nothing, maybe no issue.

                        ### get and write logs to getval => Most rapid way with join
                        elif re.search(self.nokia_search_all, i) != None: tmplist_past_nokia.append(i)
                    break

            self.getval_nokia= "".join(tmplist_past_nokia) # self.getval have all of log picked.

        except KeyboardInterrupt:
            print("\nInterrupt Forcely")
            sys.exit()


    def openlog_timerange_nokia(self):
        ### Initialize variable
        tmplist_timerange_nokia= []
        start_flg= 0

        ### For debug-print
        #print("\nStart of Nokia time: {}".format(datetime.datetime.today()))
        #print("log_list: {}".format(self.log_list))

        ### Set end time accordingly by day of date due to format diferrence.
        if re.search(r"0\d", self.end_time.strftime("%d")) != None:
            self.end_time_str= self.end_time.strftime("%b  %-d %H:%M:%S")
        else:
            self.end_time_str= self.end_time.strftime("%b %d %H:%M:%S")

        ### Loop start to open/analyze log-file
        try:
            for past_log in self.log_list:
                ### Make completion filename
                past_log_filename_nokia= "/var/log/local6/{}".format(past_log)
                #print(past_log_filename_juniper)

                ### After first file checking completed, as start_flg is remaining as a 1, be able to search all line in log after that.
                while True:
                    #time.sleep(1)
                    ### Set search-word accordingly by day of date
                    if re.search(r"0\d", self.start_time.strftime("%d")) != None:
                        self.start_time_str= self.start_time.strftime("%b  %-d %H:%M:%S")
                    else:
                        self.start_time_str= self.start_time.strftime("%b %d %H:%M:%S")

                    ### Open log file
                    if re.search(r"gz$", past_log_filename_nokia) != None:
                        with gzip.open(past_log_filename_nokia, mode= "rt", encoding= "utf-8", errors= "replace") as r:
                            ### Start loop internal archived log file opened
                            for i in r.readlines():

                                ### MEMO: This algorithm performance is too SLOW. Should use "fidn" method.
                                #pick_time= self.search_timestamp.match(i).group()
                                #pick_time= datetime.datetime.strptime(pick_time, "%b %d %H:%M:%S")
                                #if pick_time.strftime("%m%d%H%M%S") >= self.end_time.strftime("%m%d%H%M%S"):
                                #   print("find beyond time: {}".format(pick_time))
                                #   print("the end time: {}".format(datetime.datetime.today()))
                                #   sys.exit()

                                if i.find(self.end_time_str) != -1: break
                                if start_flg == 1 and re.search(self.nokia_search_all, i) != None:
                                    tmplist_timerange_nokia.append(i)
                                    continue
                                if start_flg == 1: continue
                                if i.find(self.start_time_str) != -1:
                                    start_flg= 1
                                    #print("End of set startflag:{}".format(datetime.datetime.today()))
                                    if re.search(self.nokia_search_all, i) != None: tmplist_timerange_nokia.append(i)
                    else:
                        with open(past_log_filename_nokia, mode= "rt", encoding= "utf-8", errors= "replace") as r:
                            ### Start loop internal log file opened
                            for i in r.readlines():
                                if i.find(self.end_time_str) != -1: break
                                if start_flg == 1 and re.search(self.nokia_search_all, i) != None:
                                    tmplist_timerange_nokia.append(i)
                                    continue
                                if start_flg == 1: continue
                                if i.find(self.start_time_str) != -1:
                                    start_flg= 1
                                    #print("End of set startflag:{}".format(datetime.datetime.today()))
                                    if re.search(self.nokia_search_all, i) != None: tmplist_timerange_nokia.append(i)

                    ### If flag = 0, not added any log-line
                    if start_flg == 0:
                        self.start_time= self.start_time + self.additional_time_delta # add 1second
                        #print("Added time 1sec:{}".format(datetime.datetime.today()))
                        continue
                    else:
                        break

        except KeyboardInterrupt:
            print("\nInterrupt Forcely")
            sys.exit()

        ### Just for timespan option to remove beyond the end_time
        tmplist_timerange_nokia= self.remove_beyond_time(tmplist_timerange_nokia)

        ### Final merge log-lines picked
        self.getval_nokia= "".join(tmplist_timerange_nokia) # self.getval have all of log picked.


    ### Create Dictionary of NOKIA
    def make_outage_dict_nokia(self):
# MEMO #
# self.ifc_count_dict= {} => [rt ifc] : count
# self.ifc_state_dict= {} => [rt ifc] : [last-down-time, last status]

        tmplist= []

        # Term of nokia
        for i in self.getval_nokia.splitlines():
            try:#DEBUG rikeda
                rt = re.search('[a-zA-Z]+\s+\d+\s+\S+\s+(\S+)',i).group(1)
                rt = socket.getfqdn(rt).replace(".gin.ntt.net","")
            except Exception as e:
                print(e)

                print(i)
                import code; code.interact(local=locals())
                exit()

                ##### START IFC Phase #####
            ### when the down find
            if re.search(self.nokia_ifc_down,i) != None:
                #match_rt.group(0): a02.sngpsi07.sg.bb,t.group(0): Jan 22 04:35:17
                ### store time and latest status as a "[rt ifc] = [last-down-time, down]"
                
                rt_ifc= rt + " " + i.split()[-4]
                t= self.nokia_search_time.match(i)
                tmplist.append(t.group(0))
                tmplist.append("down")
                self.ifc_state_dict[rt_ifc]= tmplist
                tmplist= []

                ### store count info as a "[rt ifc] : count"
                if (rt_ifc in self.ifc_count_dict) == True: self.ifc_count_dict[rt_ifc]+= 1
                else: self.ifc_count_dict[rt_ifc]= 1

            ### when the up find, only perform update status for "[rt ifc] = [last-down-time, up]"
            elif re.search(self.nokia_ifc_up,i) != None: 
                rt_ifc= rt + " " + i.split()[-3]
                if (rt_ifc in self.ifc_state_dict) == True: ### this needs to make after re_ifc varivable made.
                    self.ifc_state_dict[rt_ifc][1]= "up"
        ##### END IFC Phase #####


        ##### START iBGP Phase #####
            ### When the down find,
            elif re.search(self.nokia_bgpdown,i) != None:
                peer_addr= self.nokia_bgpdown.search(i) ### Get peer address
                rt_peer= rt + " " + peer_addr.group(1) ### merge
                t= self.nokia_search_time.match(i) ### Get time stamp

                tmplist.append(t.group(0))
                tmplist.append("down")
                self.ebgp_state_dict[rt_peer]= tmplist
                tmplist= []

                ### store count info
                if (rt_peer in self.ibgp_count_dict) == True: self.ibgp_count_dict[rt_peer]+= 1
                else: self.ibgp_count_dict[rt_peer]= 1

            ### When the up find,
            elif re.search(self.nokia_bgpup,i) != None:
                peer_addr= self.nokia_bgpup.search(i) ### Get peer address
                rt_peer= rt + " " + peer_addr.group(1) ### merge

                if (rt_peer in self.ibgp_state_dict) == True:
                    self.ibgp_state_dict[rt_peer][1]= "up"
        ##### END iBGP Phase #####
        ##### START eBGP Phase #####
            ### When the down find,
            elif re.search(self.nokia_bgpdown,i) != None:
                peer_addr= self.nokia_bgpdown.search(i) ### Get peer address
                rt_peer= rt + " " + peer_addr.group(1) ### merge
                t= self.nokia_search_time.match(i) ### Get time stamp

                tmplist.append(t.group(0))
                tmplist.append("down")
                self.ebgp_state_dict[rt_peer]= tmplist
                tmplist= []

                ### store count info
                if (rt_peer in self.ebgp_count_dict) == True: self.ebgp_count_dict[rt_peer]+= 1
                else: self.ebgp_count_dict[rt_peer]= 1

            ### When the up find,
            elif re.search(self.nokia_bgpup,i) != None:
                peer_addr= self.nokia_bgpup.search(i) ### Get peer address
                rt_peer= rt + " " + peer_addr.group(1) ### merge

                if (rt_peer in self.ebgp_state_dict) == True:
                    self.ebgp_state_dict[rt_peer][1]= "up"
        ##### END eBGP Phase #####


        ##### START VC Phase #####
            elif re.search(self.nokia_vcdown,i) != None:
                vcid= self.nokia_vcid.search(i) ### Get vc-id
                rt_vcid= rt + " " + vcid.group(1) ### merge
                t= self.nokia_search_time.match(i) ### Get time-stamp

                tmplist.append(t.group(0))
                tmplist.append("down")
                self.vc_state_dict[rt_vcid]= tmplist
                tmplist= []

                ### store count info
                if (rt_vcid in self.vc_count_dict) == True: self.vc_count_dict[rt_vcid] += 1
                self.vc_count_dict[rt_vcid]= 1


            elif re.search(self.nokia_vcup,i) != None:
                match_rt= self.search_router.search(i) ### Get router name
                vcid= self.nokia_vcid.search(i).group(1) ### Get vc-id
                rt_vcid= rt + " " + vcid

                if (rt_vcid in self.vc_state_dict) == True:
                    self.vc_state_dict[rt_vcid][1]= "up"





    ### For test (No use in normal run)
    def write_test(self):
        with open("/home/witou/lab/getlogtest.log", "w") as w:
            for i in self.getval_juniper:
                w.write(i)
            for i in self.getval_cisco:
                w.write(i)
            for i in self.getval_nokia:
                w.write(i)

class DB:
    def __init__(self, ifc_st, ifc_cnt, ebgp_st, ebgp_cnt, ibgp_st, ibgp_cnt, vc_st, vc_cnt):
        ### Regarding GetLoginInformation
        self.current_path= os.getcwd()
        self.home_path= expanduser("~") + "/.cloginrc"

        ### Regarding ConnectDatabase
        self.host= "localhost"
        self.db_name= "cfgtools"
        self.user_name= ""
        self.password= ""

        ### Regarding got information
        self.ifc_state_dict= ifc_st
        self.ifc_count_dict= ifc_cnt
        self.ebgp_state_dict= ebgp_st
        self.ebgp_count_dict= ebgp_cnt
        self.ibgp_state_dict= ibgp_st
        self.ibgp_count_dict= ibgp_cnt
        self.vc_state_dict= vc_st
        self.vc_count_dict= vc_cnt

        ### Regarding SQL command
        ## For Interface 
        self.ifc_cmd= "\
SELECT device_name, ifc_name, ifc_descr_type, ifc_descr, abbr, cid, cust_id, ifc_state, if.noc_field \
FROM ct_ifcs AS if \
JOIN ct_devices AS dev on if.device_id = dev.device_id \
JOIN ct_ifcs_state AS ifst on ifst.ifc_state_id = if.ifc_state_id \
JOIN ct_ifcs_descr_type AS ifdst on ifdst.ifc_descr_type_id = if.ifc_descr_type_id \
JOIN ct_vendor AS vendor on if.telco_id = vendor.vendor_id \
WHERE device_name like '%{}%' and \
ifc_name like '%{}'\
"

        self.ifc_exception_first_cmd= "\
SELECT router, ifc_name, intf_type, name, telco, cid, cust_id, state \
FROM interfaces \
WHERE router like '%{}%' and ifc_name like '%{}'\
"

        self.ifc_exception_second_cmd= "\
SELECT device_name, ifc_name, if.noc_field \
FROM ct_ifcs AS if \
JOIN ct_devices AS dev on if.device_id = dev.device_id \
WHERE device_name like '{}%' \
AND ifc_name like '%{}'\
"

#       self.ifc_nocfield= "\
#SELECT noc_field FROM ct_ifcs \
#JOIN ct_devices as dev on dev.device_id = ct_ifcs.device_id



#       self.ifc_cmd= "\
#SELECT router, ifc_name, intf_type, name, telco, cid, cust_id, state, cie_field \
#FROM interfaces \
#WHERE router like '{}' and ifc_name like '{}'\
#"


#       self.bgp_cmd= "SELECT router, multihop_src, ip_addr, asn, description, state from peers where ip_addr = '{}'"
        self.bgp_cmd= "\
SELECT peers.router, multihop_src, ip_addr, asn, peers.description, cust_id, peers.state \
FROM peers \
JOIN interfaces AS ifcs on ifcs.ifc_name = peers.multihop_src AND peers.router = ifcs.router \
WHERE ip_addr = '{}'\
"

        ## For VC session
        self.vc_cmd= " \
SELECT id, l2.router, l2.ifc_name, name, cust_id, if.state, comment \
from l2vpnu as l2 \
JOIN interfaces as if on l2.router = if.router and l2.ifc_name = if.ifc_name \
where id = '{}'"

        ## For iBGP session
        self.ibgp_cmd = " \
SELECT state \
FROM routers \
WHERE name = '{}'"


        ### Master dict
        self.master_ifc= {}
        self.master_ifc_BB= {}
        self.master_ifc_BC= {}
        self.master_ifc_BP= {}
        self.master_ebgp= {}
        self.master_ibgp= {}
        self.master_vc= {}


        ### Define for research
        self.search_bb= re.compile(r"BB:")
        self.search_bl= re.compile(r"BL:")
        self.search_bc= re.compile(r"BC:|BT:|BL:")
        self.search_bp= re.compile(r"BP:")
        self.search_rt_in_desc= re.compile(r"r(\d{2})\.(\D{6})(\d{2})\.(\D{2})\.(\D{2})") ### i.e. r25.nycmny01.us.bb


    def get_login_info(self):
        with open(self.home_path, 'r') as f:
            for line in f:
                if re.match(r"add user\s+", line):
                    self.user_name = line.split()[-1]
                elif re.match(r"add password\s+\*", line):
                    self.password = line.split()[-2][1:-1]
                    break
        return(self.user_name, self.password)


    def db_login(self):
        ### Initialize DB connection
        self.db_con= psycopg2.connect("dbname={} host={} user={} password={}".format(self.db_name, self.host, self.user_name, self.password))
        self.db_cur= self.db_con.cursor()

    def get_ifc_info(self):

        #print("\nStart get_ifc_info DB: {}".format(datetime.datetime.today()))
        #print("Length: {}".format(len(self.ifc_state_dict)))

        for rt_ifc, state_list in self.ifc_state_dict.items():

            temp_list= [] ### zero clear

            ### store SQL command / execute / fetch result
            cmd= self.ifc_cmd.format(rt_ifc.split(" ")[0], rt_ifc.split(" ")[1])
            self.db_cur.execute(cmd)
            rows= self.db_cur.fetchall()

            #### MEMO #####
            # Even if create error detect phase, existing no registrated info like below
            # a01.amstnl02.nl.bb em0

            ### Error detect
            if len(rows) == 0:
                row_list= []

                ### Get information except noc_field , because can not get in one sql.
                cmd= self.ifc_exception_first_cmd.format(rt_ifc.split(" ")[0], rt_ifc.split(" ")[1])
                self.db_cur.execute(cmd)
                rows= self.db_cur.fetchall()

                if len(rows) == 0: continue

                for i in rows:
                    for j in i:
                        if j == None: j= ""
                        row_list.append(j)

                ### Get information only noc_field
                cmd= self.ifc_exception_second_cmd.format(rt_ifc.split(" ")[0], rt_ifc.split(" ")[1])
                self.db_cur.execute(cmd)
                rows= self.db_cur.fetchall()

                if len(rows) == 0: continue

                for i in rows:
                    if i[2] == None: j= ""
                    row_list.append(i[2])

            else: ### In case of no error detected
                ### transfer taple to list for overwrite
                row_list= []
                for i in rows: ### i => taple
                    for j in i: ### j => counter(begin from 0), val= value of list
                        if j == None: j= "" ### If j is None, overwrite to "" from None.
                        row_list.append(j)

            ### To complete ifc-master-dict
            for rt_ifc_B, count in self.ifc_count_dict.items():
                if rt_ifc == rt_ifc_B:
                    if row_list[3] == "unused": continue

                    ifc_key= "{} {}".format(row_list[0], row_list[1])
                    temp_list.append(state_list[0])

                    if row_list[2] == "BB":
                        ### Desc-type + Description + telco + cid
                        temp_list.append("{}: {} - {} {}".format(row_list[2], row_list[3], row_list[4], row_list[5]))
                    elif row_list[2] == "BL" and row_list[6] != "":
                        ### Desc-type + Description - telco - USID
                        temp_list.append("{}: {} - {} - USID: {}".format(row_list[2], row_list[3], row_list[4], row_list[6]))
                    elif row_list[2] == "BL" and row_list[6] == "":
                        ### Desc-type + Description - telco
                        temp_list.append("{}: {} - {}".format(row_list[2], row_list[3], row_list[4]))
                    elif row_list[4] == "" and row_list[5] == "":
                        temp_list.append("{}: {} - USID: {}".format(row_list[2], row_list[3], row_list[6]))
                    elif row_list[4] == "":
                        temp_list.append("{}: {} - {} - USID: {}".format(row_list[2], row_list[3], row_list[5], row_list[6]))
                    elif row_list[5] == "":
                        temp_list.append("{}: {} - {} - USID: {}".format(row_list[2], row_list[3], row_list[4], row_list[6]))
                    else:
                        ### Desc-type + Description + telco + cid + usid
                        temp_list.append("{}: {} - {} {} - USID: {}".format(row_list[2], row_list[3], row_list[4], row_list[5], row_list[6]))

                    temp_list.append(state_list[1])     ### Current status
                    temp_list.append(row_list[7])       ### Status on DB
                    temp_list.append(count)         ### Count
                    temp_list.append(row_list[8])       ### # NOC-field

                    #### completed list => ['TIME', 'TYPE: DESCRIPTION', 'CURRENT', 'DB', 'COUNT', 'TICKET']

                    ### Branch for seaparate interface type
                    if self.search_bb.match(temp_list[1]) != None: self.master_ifc_BB[ifc_key]= temp_list
                    elif self.search_rt_in_desc.search(temp_list[1]) != None and self.search_bl.match(temp_list[1]) != None:
                        self.master_ifc_BB[ifc_key]= temp_list
                    elif self.search_bc.match(temp_list[1]) != None: self.master_ifc_BC[ifc_key]= temp_list
                    elif self.search_bp.match(temp_list[1]) != None: self.master_ifc_BP[ifc_key]= temp_list
                    else: self.master_ifc[ifc_key]= temp_list

                    ### Zero-clear
                    temp_list= []

    def get_ibgp_info(self):

        for rt_peer, state_list in self.ibgp_state_dict.items():
            temp_list= []

            cmd= self.ibgp_cmd.format(rt_peer.split()[0])
            self.db_cur.execute(cmd)
            rows= self.db_cur.fetchall()
            if len(rows) == 0:
                status = "unknown"
            else:
                status = rows[0][0]

            ### To complete bgp-master-dict
            for rt_peer_B, count in self.ibgp_count_dict.items():
                peer_key= f"{rt_peer}"
                temp_list.append(state_list[0])                     # Last down time
                temp_list.append(f"{rt_peer.split()[0]} loopback 0")      # route-name ifc
                temp_list.append(rt_peer.split()[1])                       # peer address
                temp_list.append("65000")                  # asn
                temp_list.append(f"{socket.getfqdn(rt_peer.split()[1]).replace('.gin.ntt.net','')}")
                temp_list.append(state_list[1])                     # current states
                temp_list.append(status)                       # states on DB
                temp_list.append(count)                         # count

                self.master_ibgp[peer_key]= temp_list
                temp_list= []

    def get_ebgp_info(self):

        for rt_peer, state_list in self.ebgp_state_dict.items():
            temp_list= []
            cmd= self.bgp_cmd.format(rt_peer.split(" ")[1])
            self.db_cur.execute(cmd)
            rows= self.db_cur.fetchall()
            #print("Get query: {} at {}".format(rt_peer, datetime.datetime.today()))

            ### Error detect
            if len(rows) == 0:
                continue

            ### To complete bgp-master-dict
            for rt_peer_B, count in self.ebgp_count_dict.items():
                if rt_peer == rt_peer_B:
                    for row_list in rows:
                        peer_key= "{} {}".format(row_list[0], row_list[2])
                        temp_list.append(state_list[0])                     # Last down time
                        temp_list.append("{} {}".format(row_list[0], row_list[1]))      # route-name ifc
                        temp_list.append(row_list[2])                       # peer address
                        temp_list.append(str(row_list[3]))                  # asn
                        if row_list[5] != None: temp_list.append("{} - USID: {}".format(row_list[4], row_list[5]))  # Description - USID
                        else: temp_list.append("{} - USID: ".format(row_list[4]))
                        temp_list.append(state_list[1])                     # current states
                        temp_list.append(row_list[6])                       # states on DB
                        temp_list.append(count)                         # count

                        self.master_ebgp[peer_key]= temp_list
                        temp_list= []
### NOTE: ###################
### {rt_peer : [time, xxx,xxx,xxx,]}
### {rt_peer : [{time: [xxx,xxx,xxx]}]
###########

        #print("Length: {}".format(len(self.master_ebgp)))


    def get_vc_info(self):

        for rt_vc, state_list in self.vc_state_dict.items():
            temp_list= []
            cmd= self.vc_cmd.format(rt_vc.split(" ")[-1])
            self.db_cur.execute(cmd)
            rows= self.db_cur.fetchall()

            ### Error detect
            if len(rows) == 0:
                continue

            ### To complete vc-master-dict
            for rt_vc_B, count in self.vc_count_dict.items():
                if rt_vc == rt_vc_B:
                    temp_list.append(state_list[0])# Last down time
                    temp_list.append("VC-{}".format(rt_vc.split(" ")[-1]))# VC-id

                    if rt_vc.split(" ")[0] == rows[0][1]:
                        if (len(rows)) != 2: continue ### Avoid to can not catch the 2 columuns
                        else:
                            temp_list.append("{} {}".format(rows[0][1], rows[0][2]))# one of the router interface
                            temp_list.append("{} {}".format(rows[1][1], rows[1][2]))# other side router interface
                            temp_list.append(rows[0][3])# Description
                            temp_list.append(rows[0][4])# USID
                            temp_list.append(state_list[1])# Current states
                            temp_list.append(rows[0][5])# Status on DB
                            temp_list.append(count)# Count
                    else:
                        if (len(rows)) != 2: continue ### Avoid to can not catch the 2 columuns
                        else:
                            temp_list.append("{} {}".format(rows[1][1], rows[1][2]))# one of the router interface
                            temp_list.append("{} {}".format(rows[0][1], rows[0][2]))# other side router interface
                            temp_list.append(rows[1][3])# Description
                            temp_list.append(rows[1][4])# USID
                            temp_list.append(state_list[1])# Current states
                            temp_list.append(rows[1][5])# Status on DB
                            temp_list.append(count)# Count

                    self.master_vc[rt_vc]= temp_list
                    temp_list= []

        self.db_cur.close()
        self.db_con.close()


    def return_dict(self):
        return(self.master_ifc, self.master_ebgp,self.master_ibgp ,self.master_vc, self.master_ifc_BB, self.master_ifc_BC, self.master_ifc_BP)


##################

### This is not relevant to invesatigate switch.
class Monitor:
    def __init__(self, master_ifc, master_ebgp, master_ibgp, master_vc, master_ifc_bb, master_ifc_bc, master_ifc_bp, origin_start_time, origin_end_time, grep_flag, ignore_flag):

        ### take over master dictionary
        self.master_ifc= master_ifc
        self.master_ebgp= master_ebgp
        self.master_ibgp= master_ibgp
        self.master_vc= master_vc
        self.master_ifc_bb= master_ifc_bb
        self.master_ifc_bc= master_ifc_bc
        self.master_ifc_bp= master_ifc_bp


        ### set innitial max length of value + 2 (actual len should -2)
        self.len_date= 8    # date      # need 16 spaces, 16 - len("LastDown")
        self.len_rtifc= 9   # interface
        self.len_ifdesc= 11 # description
        self.len_cur= 3     # cur / DB  # up/down/turn-up
        self.len_db= 2      # cur / DB  # up/down/turn-up
        self.len_count= 5   # count
        self.len_ticket= 9  # ticket
        self.len_peer= 12   # peer address
        self.len_asn= 3     # asn
        self.len_bgpdesc= 11    # description
        self.len_vcid= 5    # VC-ID
        self.len_other= 10  # other-side
        self.len_vcdesc= 11 # description
        self.len_usid= 4    # USID
        self.len_comment= 9 # comment

        self.origin_len= {}
        self.origin_len["line"]= 4
        self.origin_len["date"]= 8
        self.origin_len["rt_ifc"]= 9
        self.origin_len["ifdesc"]= 11
        self.origin_len["cur"]= 3
        self.origin_len["db"]= 2
        self.origin_len["count"]= 5
        self.origin_len["ticket"]= 9
        self.origin_len["peer"]= 12
        self.origin_len["asn"]= 3
        self.origin_len["bgpdesc"]= 11
        self.origin_len["vcid"]= 5
        self.origin_len["other"]= 10
        self.origin_len["vcdesc"]= 11
        self.origin_len["usid"]= 4
        self.origin_len["comment"]= 9
        self.max_len= self.origin_len.copy()


        ### Regarding Time
        self.origin_start_time= origin_start_time
        self.origin_end_time= origin_end_time

        ### flag
        self.grep_flag= grep_flag
        self.ignore_flag= ignore_flag

    def reset_val(self):
        self.len_rtifc= 9       # interface
        self.len_ifdesc= 11 # Description
        self.len_cur= 3         # cur / DB      # up/down/turn-up
        self.len_db= 2          # cur / DB      # up/down/turn-up
        self.len_ticket= 9      # ticket

        self.origin_len= {}
        self.origin_len["line"]= 4
        self.origin_len["date"]= 8
        self.origin_len["rt_ifc"]= 9
        self.origin_len["ifdesc"]= 11
        self.origin_len["cur"]= 3
        self.origin_len["db"]= 2
        self.origin_len["count"]= 5
        self.origin_len["ticket"]= 9
        self.origin_len["peer"]= 12
        self.origin_len["asn"]= 3
        self.origin_len["bgpdesc"]= 11
        self.origin_len["vcid"]= 5
        self.origin_len["other"]= 10
        self.origin_len["vcdesc"]= 11
        self.origin_len["usid"]= 4
        self.origin_len["comment"]= 9
        self.max_len= self.origin_len.copy()


    def start(self, lpcount, maxcount, sp_flag):

        ### Deal with IGNORE option
        if self.ignore_flag == True:
            self.ignore_run()

        ### Loop count and search span showing
        print(deco.clr("\n            *** Loop Count: {} / {} ***".format(lpcount + 1, maxcount), "yellow"))
        print("-" * 50)
        print("| " + deco.clr("Check Span: {} to {}".format(self.origin_start_time, self.origin_end_time), "cyan") + " |")
        print("-" * 50)
        print(" ")

        ### branch for separate option
        if sp_flag == False:
            ### No separate option
            self.master_ifc.update(self.master_ifc_bb) ### merge to master_ifc
            self.master_ifc.update(self.master_ifc_bc) ### merge to master_ifc
            self.master_ifc.update(self.master_ifc_bp) ### merge to master_ifc

            ### Grep parse phase
            if self.grep_flag != "None": self.grep_run()

            ### Create monitor phase
            #print(self.master_ifc)
            self.ifc_phase("Circuits", self.master_ifc)
            self.ebgp_phase()
            self.ibgp_phase()
            self.vc_phase()
        else:
            ### Run with separate option 
            ### Grep parse phase for separate only
            if self.grep_flag != "None": self.grep_run_separate()
            self.ifc_phase("Backborn Circuits", self.master_ifc_bb)
            self.ifc_phase("Customer Circuits", self.master_ifc_bc)
            self.ifc_phase("Peer Circuits", self.master_ifc_bp)

            ### Grep parse phase
            if self.grep_flag != "None": self.grep_run()
            self.ifc_phase("Other Circuits", self.master_ifc)
            self.ebgp_phase()
            self.ibgp_phase()
            self.vc_phase()

        print(" ")


    def ignore_run(self):

        #### IFC be checked
        erase_list_ignore= []
        for key, val_list in self.master_ifc.items():
            if val_list[3] == "turn-up": erase_list_ignore.append(key)
        ## Remove from list
        for key in erase_list_ignore: del self.master_ifc["{}".format(key)]

        #### eBGP be checked
        erase_list_ignore= []
        for key, val_list in self.master_ebgp.items():
            if val_list[6] == "turn-up": erase_list_ignore.append(key)
        ## Remove from list
        for key in erase_list_ignore: del self.master_ebgp["{}".format(key)]

        #### VC be checked
        erase_list_ignore= []
        for key, val_list in self.master_vc.items():
            if val_list[7] == "turn-up": erase_list_ignore.append(key)
        ## Remove from list
        for key in erase_list_ignore: del self.master_vc["{}".format(key)]

        #### IFC_bb be checked
        erase_list_ignore= []
        for key, val_list in self.master_ifc_bb.items():
            if val_list[3] == "turn-up": erase_list_ignore.append(key)
        ## Remove from list
        for key in erase_list_ignore: del self.master_ifc_bb["{}".format(key)]

        #### IFC_bc be checked
        erase_list_ignore= []
        for key, val_list in self.master_ifc_bc.items():
            if val_list[3] == "turn-up": erase_list_ignore.append(key)
        ## Remove from list
        for key in erase_list_ignore: del self.master_ifc_bc["{}".format(key)]

        #### IFC_bp be checked
        erase_list_ignore= []
        for key, val_list in self.master_ifc_bp.items():
            if val_list[3] == "turn-up": erase_list_ignore.append(key)
        ## Remove from list
        for key in erase_list_ignore: del self.master_ifc_bp["{}".format(key)]


    def grep_run(self):
        ########## IFC dictionary ##########
        erase_list= []
        for key, val_list in self.master_ifc.items():
            no_erase_flag= 0
            if re.search(self.grep_flag, key) != None: ### If match the grep-word, skip to next key.
                continue
            else:
                for val in val_list: ### check all column, and if detect the grep-word, enable the no_erase_flag to avoid erasing in list.
                    if val == None or type(val) != str: continue ### Avoid character error
                    if re.search(self.grep_flag, val) != None:
                        no_erase_flag= 1
                        break
                if no_erase_flag != 1: erase_list.append(key) ### If no_erase_flag is not enable, add to erase list

        ### Run erase from master_ifc
        for key in erase_list:
            del self.master_ifc["{}".format(key)]


        ########## BGP dictionary ##########
        erase_list= []
        for key, val_list in self.master_ebgp.items():
            no_erase_flag= 0
            if re.search(self.grep_flag, key) != None: ### If match the grep-word, skip to next key.
                continue
            else:
                for val in val_list: ### check all column, and if detect the grep-word, enable the no_erase_flag to avoid erasing in list.
                    if val == None or type(val) != str: continue ### Avoid character error
                    if re.search(self.grep_flag, val) != None:
                        no_erase_flag= 1
                        break
                if no_erase_flag != 1: erase_list.append(key) ### If no_erase_flag is not enable, add to erase list

        ### Run erase from master_ebgp
        for key in erase_list:
            del self.master_ebgp["{}".format(key)]


        ########## VC dictionary ##########
        erase_list= []
        for key, val_list in self.master_vc.items():
            no_erase_flag= 0
            if re.search(self.grep_flag, key) != None: ### If match the grep-word, skip to next key.
                continue
            else:
                for val in val_list: ### check all column, and if detect the grep-word, enable the no_erase_flag to avoid erasing in list.
                    if val == None or type(val) != str: continue ### Avoid character error
                    if re.search(self.grep_flag, val) != None:
                        no_erase_flag= 1
                        break
                if no_erase_flag != 1: erase_list.append(key) ### If no_erase_flag is not enable, add to erase list

        ### Run erase from master_ebgp
        for key in erase_list:
            del self.master_vc["{}".format(key)]


    ### For only bb, bc, bp dictionary
    def grep_run_separate(self):
        
        ## bb,bc,bp
        ########## IFC bb dictionary ##########
        erase_list= []
        for key, val_list in self.master_ifc_bb.items():
            no_erase_flag= 0
            if re.search(self.grep_flag, key) != None: ### If match the grep-word, skip to next key.
                continue
            else:
                for val in val_list: ### check all column, and if detect the grep-word, enable the no_erase_flag to avoid erasing in list.
                    if val == None or type(val) != str: continue ### Avoid character error
                    if re.search(self.grep_flag, val) != None:
                        no_erase_flag= 1
                        break
                if no_erase_flag != 1: erase_list.append(key) ### If no_erase_flag is not enable, add to erase list

        ### Run erase from master_ifc
        for key in erase_list:
            del self.master_ifc_bb["{}".format(key)]


        ########## IFC bc dictionary ##########
        erase_list= []
        for key, val_list in self.master_ifc_bc.items():
            no_erase_flag= 0
            if re.search(self.grep_flag, key) != None: ### If match the grep-word, skip to next key.
                continue
            else:
                for val in val_list: ### check all column, and if detect the grep-word, enable the no_erase_flag to avoid erasing in list.
                    if val == None or type(val) != str: continue ### Avoid character error
                    if re.search(self.grep_flag, val) != None:
                        no_erase_flag= 1
                        break
                if no_erase_flag != 1: erase_list.append(key) ### If no_erase_flag is not enable, add to erase list

        ### Run erase from master_ifc
        for key in erase_list:
            del self.master_ifc_bc["{}".format(key)]


        ########## IFC bp dictionary ##########
        erase_list= []
        for key, val_list in self.master_ifc_bp.items():
            no_erase_flag= 0
            if re.search(self.grep_flag, key) != None: ### If match the grep-word, skip to next key.
                continue
            else:
                for val in val_list: ### check all column, and if detect the grep-word, enable the no_erase_flag to avoid erasing in list.
                    if val == None or type(val) != str: continue ### Avoid character error
                    if re.search(self.grep_flag, val) != None:
                        no_erase_flag= 1
                        break
                if no_erase_flag != 1: erase_list.append(key) ### If no_erase_flag is not enable, add to erase list

        ### Run erase from master_ifc
        for key in erase_list:
            del self.master_ifc_bp["{}".format(key)]


    def ifc_phase(self, output_title, got_dict):
        print("[ {} ]".format(output_title))
        #sorted_dict_ifc= sorted(self.master_ifc.items(), key= lambda x: datetime.datetime.strptime(x[1][0], "%b %d %H:%M:%S"))
        sorted_dict_ifc= sorted(got_dict.items(), key= lambda x: datetime.datetime.strptime(str(datetime.datetime.now().year) + " " + x[1][0], "%Y %b %d %H:%M:%S"))

        ### For only count max length
        for tap in sorted_dict_ifc:
            ### count value and compare
            if tap[0] == None: pass                             # Router Interface
            elif len(tap[0]) > self.len_rtifc: self.len_rtifc= len(tap[0])
            if tap[1][1] == None: pass                          # InterfaceDescription
            elif len(tap[1][1]) > self.len_ifdesc: self.len_ifdesc= len(tap[1][1])
            if tap[1][2] == None: pass                          # Current status
            elif len(tap[1][2]) > self.len_cur: self.len_cur= len(tap[1][2])
            if tap[1][3] == None: pass                          # DB status
            elif len(tap[1][3]) > self.len_db: self.len_db= len(tap[1][3])
            if tap[1][5] == None: tap[1][5]= ""                     # Ticket Number
            if len(str(tap[1][5])) > self.len_ticket: self.len_ticket= len(str(tap[1][5]))
### Just note, tap[1][5] is in list be included taple. But it can modify the value. Confirmed.


        ### First line as column
            ### Max length - (x as a column length + 1 as a first space) without LastDown column
        print("LastDown" + " " * self.len_date + "| " +\
              "Interface" + " " * (self.len_rtifc - 8) + "| " +\
              "Description" + " " * (self.len_ifdesc - 10) + "| " +\
              "cur" + " " * (self.len_cur - 2) + "| " +\
              "DB" + " " * (self.len_db - 1) + "| " +\
              "count" + " " + "| " +\
              "NOC_field" + " " * (self.len_ticket - 8))

        ### Second line as line(-+)
        print("-" * (self.len_date + 8) + "+" +\
              "-" * (self.len_rtifc + 2) + "+" +\
              "-" * (self.len_ifdesc + 2) + "+" +\
              "-" * (self.len_cur + 2) + "+" +\
              "-" * (self.len_db + 2) + "+" +\
              "-" * (self.len_count + 2) + "+" +\
              "-" * (self.len_ticket + 2))

        ### For output
        for tap in sorted_dict_ifc:
            #print("{} | {} | {} | {} | {} | {} | {}".format(tap[1][0], tap[0], tap[1][1], tap[1][2], tap[1][3],tap[1][4],tap[1][5]))
            if tap[1][2] == "up":
                print("{} |".format(tap[1][0]) +\
                      " {}".format(tap[0]) + " " * (self.len_rtifc - len(tap[0]) + 1) + "|" +\
                      " {}".format(tap[1][1]) + " " * (self.len_ifdesc - len(tap[1][1]) + 1) + "|" +\
                      " {}".format(tap[1][2]) + " " * (self.len_cur - len(tap[1][2]) + 1) + "|" +\
                      " {}".format(tap[1][3]) + " " * (self.len_db - len(tap[1][3]) + 1) + "|" +\
                      " {}".format(tap[1][4]) + " " * (self.len_count - len(str(tap[1][4])) + 1) + "|" +\
                      " {}".format(tap[1][5]))
            else:
                print(deco.clr("{} |".format(tap[1][0]) +\
                      " {}".format(tap[0]) + " " * (self.len_rtifc - len(tap[0]) + 1) + "|" +\
                      " {}".format(tap[1][1]) + " " * (self.len_ifdesc - len(tap[1][1]) + 1) + "|" +\
                      " {}".format(tap[1][2]) + " " * (self.len_cur - len(tap[1][2]) + 1) + "|" +\
                      " {}".format(tap[1][3]) + " " * (self.len_db - len(tap[1][3]) + 1) + "|" +\
                      " {}".format(tap[1][4]) + " " * (self.len_count - len(str(tap[1][4])) + 1) + "|" +\
                      " {}".format(tap[1][5]), "red"))

        print(" ")
        self.reset_val()
    
    def ibgp_phase(self):
        print("")
        print("[ iBGP ]")
        sorted_dict_ibgp= sorted(self.master_ibgp.items(), key= lambda x: datetime.datetime.strptime(str(datetime.datetime.now().year) + " " + x[1][0], "%Y %b %d %H:%M:%S"))
        for tap in sorted_dict_ibgp:
            ### count value and compare
            if len(tap[1][1]) > self.len_rtifc: self.len_rtifc= len(tap[1][1])          # Router Interface (No possibilities that this column is None)
            if len(tap[1][2]) > self.len_peer: self.len_peer= len(tap[1][2])            # Peer Addrres (No possibilities that this column is None)
            if tap[1][3] == None: tap[1][3]= " "                            # ASN
            if len(str(tap[1][3])) > self.len_asn: self.len_asn= len(str(tap[1][3]))
            if tap[1][4] == None: tap[1][4]= " "                            # BGP description status
            if len(tap[1][4]) > self.len_bgpdesc: self.len_bgpdesc= len(tap[1][4])
            if len(tap[1][5]) > self.len_cur: self.len_cur= len(tap[1][5])              # Current status(No possibilities that this column is None)
            if tap[1][6] == None: tap[1][6]= " "
            if len(tap[1][6]) > self.len_db: self.len_db= len(tap[1][6])                # DB status

        ### First line as column
            ### Max length - (x as a column length + 1 as a first space) without LastDown column
        print("LastDown" + " " * self.len_date + "| " +\
              "Interface" + " " * (self.len_rtifc - 8) + "| " +\
              "Peer Address" + " " * (self.len_peer - 11) + "| " +\
              "ASN" + " " * (self.len_asn - 2) + "| " +\
              "Description" + " " * (self.len_bgpdesc - 10) + "| " +\
              "cur" + " " * (self.len_cur - 2) + "| " +\
              "DB" + " " * (self.len_db - 1) + "| " +\
              "count")

        ### Second line as line(-+)
        print("-" * (self.len_date + 8) + "+" +\
              "-" * (self.len_rtifc + 2) + "+" +\
              "-" * (self.len_peer + 2) + "+" +\
              "-" * (self.len_asn + 2) + "+" +\
              "-" * (self.len_bgpdesc + 2) + "+" +\
              "-" * (self.len_cur + 2) + "+" +\
              "-" * (self.len_db + 2) + "+" +\
              "-" * (self.len_count + 2))

        ### For output
        for tap in sorted_dict_ibgp:
            if tap[1][5] == "up":
                print("{} |".format(tap[1][0]) +\
                      " {}".format(tap[1][1]) + " " * (self.len_rtifc - len(tap[1][1]) + 1) + "|" +\
                      " {}".format(tap[1][2]) + " " * (self.len_peer - len(tap[1][2]) + 1) + "|" +\
                      " {}".format(tap[1][3]) + " " * (self.len_asn - len(str(tap[1][3])) + 1) + "|" +\
                      " {}".format(tap[1][4]) + " " * (self.len_bgpdesc - len(tap[1][4]) + 1) + "|" +\
                      " {}".format(tap[1][5]) + " " * (self.len_cur - len(tap[1][5]) + 1) + "|" +\
                      " {}".format(tap[1][6]) + " " * (self.len_db - len(tap[1][6]) + 1) + "|" +\
                      " {}".format(tap[1][7]))
            else:
                print(deco.clr("{} |".format(tap[1][0]) +\
                      " {}".format(tap[1][1]) + " " * (self.len_rtifc - len(tap[1][1]) + 1) + "|" +\
                      " {}".format(tap[1][2]) + " " * (self.len_peer - len(tap[1][2]) + 1) + "|" +\
                      " {}".format(tap[1][3]) + " " * (self.len_asn - len(str(tap[1][3])) + 1) + "|" +\
                      " {}".format(tap[1][4]) + " " * (self.len_bgpdesc - len(tap[1][4]) + 1) + "|" +\
                      " {}".format(tap[1][5]) + " " * (self.len_cur - len(tap[1][5]) + 1) + "|" +\
                      " {}".format(tap[1][6]) + " " * (self.len_db - len(tap[1][6]) + 1) + "|" +\
                      " {}".format(tap[1][7]), "red"))

        self.reset_val()


    def ebgp_phase(self):
        print("[ eBGP ]")
        sorted_dict_ebgp= sorted(self.master_ebgp.items(), key= lambda x: datetime.datetime.strptime(str(datetime.datetime.now().year) + " " + x[1][0], "%Y %b %d %H:%M:%S"))

        ### For only count max length
        for tap in sorted_dict_ebgp:
            ### count value and compare
            if len(tap[1][1]) > self.len_rtifc: self.len_rtifc= len(tap[1][1])          # Router Interface (No possibilities that this column is None)
            if len(tap[1][2]) > self.len_peer: self.len_peer= len(tap[1][2])            # Peer Addrres (No possibilities that this column is None)
            if tap[1][3] == None: tap[1][3]= " "                            # ASN
            if len(str(tap[1][3])) > self.len_asn: self.len_asn= len(str(tap[1][3]))
            if tap[1][4] == None: tap[1][4]= " "                            # BGP description status
            if len(tap[1][4]) > self.len_bgpdesc: self.len_bgpdesc= len(tap[1][4])
            if len(tap[1][5]) > self.len_cur: self.len_cur= len(tap[1][5])              # Current status(No possibilities that this column is None)
            if tap[1][6] == None: tap[1][6]= " "
            if len(tap[1][6]) > self.len_db: self.len_db= len(tap[1][6])                # DB status

        ### First line as column
            ### Max length - (x as a column length + 1 as a first space) without LastDown column
        print("LastDown" + " " * self.len_date + "| " +\
              "Interface" + " " * (self.len_rtifc - 8) + "| " +\
              "Peer Address" + " " * (self.len_peer - 11) + "| " +\
              "ASN" + " " * (self.len_asn - 2) + "| " +\
              "Description" + " " * (self.len_bgpdesc - 10) + "| " +\
              "cur" + " " * (self.len_cur - 2) + "| " +\
              "DB" + " " * (self.len_db - 1) + "| " +\
              "count")

        ### Second line as line(-+)
        print("-" * (self.len_date + 8) + "+" +\
              "-" * (self.len_rtifc + 2) + "+" +\
              "-" * (self.len_peer + 2) + "+" +\
              "-" * (self.len_asn + 2) + "+" +\
              "-" * (self.len_bgpdesc + 2) + "+" +\
              "-" * (self.len_cur + 2) + "+" +\
              "-" * (self.len_db + 2) + "+" +\
              "-" * (self.len_count + 2))

        ### For output
        for tap in sorted_dict_ebgp:
            if tap[1][5] == "up":
                print("{} |".format(tap[1][0]) +\
                      " {}".format(tap[1][1]) + " " * (self.len_rtifc - len(tap[1][1]) + 1) + "|" +\
                      " {}".format(tap[1][2]) + " " * (self.len_peer - len(tap[1][2]) + 1) + "|" +\
                      " {}".format(tap[1][3]) + " " * (self.len_asn - len(str(tap[1][3])) + 1) + "|" +\
                      " {}".format(tap[1][4]) + " " * (self.len_bgpdesc - len(tap[1][4]) + 1) + "|" +\
                      " {}".format(tap[1][5]) + " " * (self.len_cur - len(tap[1][5]) + 1) + "|" +\
                      " {}".format(tap[1][6]) + " " * (self.len_db - len(tap[1][6]) + 1) + "|" +\
                      " {}".format(tap[1][7]))
            else:
                print(deco.clr("{} |".format(tap[1][0]) +\
                      " {}".format(tap[1][1]) + " " * (self.len_rtifc - len(tap[1][1]) + 1) + "|" +\
                      " {}".format(tap[1][2]) + " " * (self.len_peer - len(tap[1][2]) + 1) + "|" +\
                      " {}".format(tap[1][3]) + " " * (self.len_asn - len(str(tap[1][3])) + 1) + "|" +\
                      " {}".format(tap[1][4]) + " " * (self.len_bgpdesc - len(tap[1][4]) + 1) + "|" +\
                      " {}".format(tap[1][5]) + " " * (self.len_cur - len(tap[1][5]) + 1) + "|" +\
                      " {}".format(tap[1][6]) + " " * (self.len_db - len(tap[1][6]) + 1) + "|" +\
                      " {}".format(tap[1][7]), "red"))

        self.reset_val()


    def vc_phase(self):
        print("\n[ VC ]")
        sorted_dict_vc= sorted(self.master_vc.items(), key= lambda x: datetime.datetime.strptime(str(datetime.datetime.now().year) + " " + x[1][0], "%Y %b %d %H:%M:%S"))
        ### For only count max length
        for tap in sorted_dict_vc:
            ### count value and compare
            if len(tap[1][1]) > self.len_vcid: self.len_vcid= len(tap[1][1])            # VC-ID (No possibilities that this column is None)
            if len(tap[1][2]) > self.len_rtifc: self.len_rtifc= len(tap[1][2])          # One of the RouterIfc (No possibilities that this column is None)
            if len(tap[1][3]) > self.len_other: self.len_other= len(tap[1][3])          # Other side RouterIfc (No possibilities that this column is None)
            if tap[1][4] == None: tap[1][4]= " "                            # VC description status
            elif len(tap[1][4]) > self.len_vcdesc: self.len_vcdesc= len(tap[1][4])
            if tap[1][5] == None: tap[1][5]= " "                            # USID
            elif len(tap[1][5]) > self.len_usid: self.len_usid= len(tap[1][5])
            if len(tap[1][6]) > self.len_cur: self.len_cur= len(tap[1][6])              # Current status(No possibilities that this column is None)
            if tap[1][7] == None: pass                              # DB status
            elif len(tap[1][7]) > self.len_db: self.len_db= len(tap[1][7])
            if len(str(tap[1][8])) > self.len_count: self.len_count= len(str(tap[1][8]))        # Count


        ### First line as column
            ### Max length - (x as a column length + 1 as a first space) without LastDown column
        print("LastDown" + " " * self.len_date + "| " +\
              "VC-ID" + " " * (self.len_vcid - 4) + "| " +\
              "Interface" + " " * (self.len_rtifc - 8) + "| " +\
              "Other Side" + " " * (self.len_other - 9) + "| " +\
              "Description" + " " * (self.len_vcdesc - 10) + "| " +\
              "USID" + " " * (self.len_usid - 3) + "| " +\
              "cur" + " " * (self.len_cur - 2) + "| " +\
              "DB" + " " * (self.len_db - 1) + "| " +\
              "count" + " " * (self.len_count - 4))

        ### Second line as line(-+)
        print("-" * (self.len_date + 8) + "+" +\
              "-" * (self.len_vcid + 2) + "+" +\
              "-" * (self.len_rtifc + 2) + "+" +\
              "-" * (self.len_other + 2) + "+" +\
              "-" * (self.len_vcdesc + 2) + "+" +\
              "-" * (self.len_usid + 2) + "+" +\
              "-" * (self.len_cur + 2) + "+" +\
              "-" * (self.len_db + 2) + "+" +\
              "-" * (self.len_count + 2))

        ### For output
        for tap in sorted_dict_vc:
            if tap[1][6] == "up":
                print("{} |".format(tap[1][0]) +\
                      " {}".format(tap[1][1]) + " " * (self.len_vcid - len(tap[1][1]) + 1) + "|" +\
                      " {}".format(tap[1][2]) + " " * (self.len_rtifc - len(tap[1][2]) + 1) + "|" +\
                      " {}".format(tap[1][3]) + " " * (self.len_other - len(tap[1][3]) + 1) + "|" +\
                      " {}".format(tap[1][4]) + " " * (self.len_vcdesc - len(tap[1][4]) + 1) + "|" +\
                      " {}".format(tap[1][5]) + " " * (self.len_usid - len(tap[1][5]) + 1) + "|" +\
                      " {}".format(tap[1][6]) + " " * (self.len_cur - len(tap[1][6]) + 1) + "|" +\
                      " {}".format(tap[1][7]) + " " * (self.len_db - len(tap[1][7]) + 1) + "|" +\
                      " {}".format(tap[1][8]))
            else:
                print(deco.clr("{} |".format(tap[1][0]) +\
                      " {}".format(tap[1][1]) + " " * (self.len_vcid - len(tap[1][1]) + 1) + "|" +\
                      " {}".format(tap[1][2]) + " " * (self.len_rtifc - len(tap[1][2]) + 1) + "|" +\
                      " {}".format(tap[1][3]) + " " * (self.len_other - len(tap[1][3]) + 1) + "|" +\
                      " {}".format(tap[1][4]) + " " * (self.len_vcdesc - len(tap[1][4]) + 1) + "|" +\
                      " {}".format(tap[1][5]) + " " * (self.len_usid - len(tap[1][5]) + 1) + "|" +\
                      " {}".format(tap[1][6]) + " " * (self.len_cur - len(tap[1][6]) + 1) + "|" +\
                      " {}".format(tap[1][7]) + " " * (self.len_db - len(tap[1][7]) + 1) + "|" +\
                      " {}".format(tap[1][8]), "red"))
        self.reset_val()


### Inherited class of Monitor
class Investigate(Monitor):
    def __init__(self, master_ifc, master_ebgp, master_vc, master_ifc_bb, master_ifc_bc, master_ifc_bp, origin_start_time, origin_end_time, grep_flag, ignore_flag\
             ,userid, password):

        ### Inherit
        super().__init__(master_ifc, master_ebgp, master_vc, master_ifc_bb, master_ifc_bc, master_ifc_bp, origin_start_time, origin_end_time, grep_flag, ignore_flag)

        ### netmiko
        self.miko_info= {}
        self.miko_info["username"]= userid
        self.miko_info["password"]= password
        self.miko_info["host"]= ""
        self.miko_info["device_type"]= "" ### juniper or cisco

        ### Netmiko command
        ## Juniper
        #-IFC
        self.j_lacp= "show lacp interfaces {}"
        self.j_desc= "show interfaces {} descriptions"
        self.j_int= "show interfaces {} extensive | match \"errors|last\"" #last-flap,error,rate
        self.j_rate= "show interfaces {} | match rate"
        self.j_light= "show interfaces diagnostics optics {} | match dbm"
        self.j_logs= "show log messages | match \"{}\" | last 5"
        #-BGP
        self.j_bgp= "show bgp summary | match \"{}\""
        #-VC
        self.j_vcsum= "show l2circuit connections interface et-0/0/20:3.0"
        self.j_vclog= "show log messages | match RPD_LAYER2 | match {}"

        ## Cisco
        #-IFC
        self.c_lacp= "show lacp {}"
        self.c_desc= "show interfaces {} description"
        self.c_int= "show interfaces {} | inc \"error|Last\""
        self.c_rate= "show interfaces {} | inc \"rate\""
        self.c_light= "show controllers {} phy | inc dBm"
        self.c_logs= "show logging | inc \"{}\" | utility tail -n 5"
        #BGP
        self.c_v4bgp= "show bgp summary | inc \"{}\""
        self.c_v6bgp= "show bgp ipv6 unicast summary | utility egrep \"{}\" -A 1"
        #-VC
        self.c_vcsum= "show l2vpn xconnect group l2vpn-{}"
        self.c_vcdetail= "show l2vpn xconnect group l2vpn-{} detail | inc \"time|state|packet\""
        self.c_vclogs= "show logging | inc \"id  {}\" | utility tail -n 5"

        ## Nokia
        #-IFC
        self.n_lacp= "show lag {}"
        self.n_desc= "show port {} description detail"
        self.n_int= "show port {} | match 'Errors|Last State'"
        self.n_light= "show port {} optical"
        self.n_logs=  "show log log-id 101 message {} count 4"
        #BGP
        self.n_v4bgp= "show router bgp summary family ipv4"
        self.n_v6bgp= "show router bgp summary family ipv6"
        #-VC
        self.n_vcsum= 'show service sdp-using | match ":{}"'
        self.n_vclogs= 'show log log-id 101 message SVCMGR-MINOR-sdpBindStatusChanged | match ":{}"'


        ### Database
        self.host= "localhost"
        self.db_name= "cfgtools"
        self.user_name= userid
        self.password= password

        ### SQL
        #### To get OS-name from device and ifc
        self.device_type_sql= "\
SELECT os_name \
FROM ct_os_name as ctos \
WHERE ctos.os_name_id = (SELECT os_name_id FROM ct_devices WHERE device_name like '%{}%' limit 1) \
LIMIT 1\
"

        #### To get peer IP address from device and ifc.
        self.check_peer_sql= "\
SELECT ip_addr \
FROM peers \
WHERE router = '{}' AND multihop_src = '{}'"


        ### This class valiable
        self.count_line= 1
        self.input_num_list= []
        self.count_ifc= 0
        self.count_bgp= 0
        self.sorted_ifc= {}
        self.sorted_bgp= {}


    def main(self):
        ### Connect DB
        self.db_connect()

        ### Merge to self.master_ifc. bgp and vc dict can use with no changes.
        self.master_ifc.update(self.master_ifc_bb) ### merge to master_ifc
        self.master_ifc.update(self.master_ifc_bc) ### merge to master_ifc
        self.master_ifc.update(self.master_ifc_bp) ### merge to master_ifc

        ### Create list for display with line number
        self.sorted_ifc= self.create_matrix("ifc")
        self.sorted_bgp= self.create_matrix("bgp")
        self.sorted_vc= self.create_matrix("vc")

        ### Get user input
        self.select_number()

        ### Start investigation
        self.investigation()

        self.db_disco()


    def db_connect(self):
        self.db_con= psycopg2.connect("dbname={} host={} user={} password={}".format(self.db_name, self.host, self.user_name, self.password))
        self.db_cur= self.db_con.cursor()


    def search_os(self, rt):
        self.db_cur.execute(self.device_type_sql.format(rt))
        rows= self.db_cur.fetchall()

        if rows[0][0] == "junos":
            return("juniper")
        elif rows[0][0] == "iox":
            return("cisco_xr")
        elif rows[0][0] == "ios":
            return("cisco_ios")
        elif rows[0][0] == "sros":
            return("nokia_sros")


    def check_peer(self, router, ifc):
        self.db_cur.execute(self.check_peer_sql.format(router, ifc))
        rows= self.db_cur.fetchall()
        return(rows)

    def check_device(self, router):
        self.db_cur.execute(self.check_device_sql.format(router))
        rows= self.db_cur.fetchall()
        return(rows)

    def miko_connect(self, os_type, rt):
        self.miko_info["device_type"]= os_type
        self.miko_info["host"]= rt
        self.miko_con= netmiko.ConnectHandler(**self.miko_info)


    def check_status(self, os_type, ifc):
        try:
            if os_type == "juniper":
                print(deco.clr(self.int_j.format(ifc), "cyan"))
                int_result= self.miko_con.send_command(self.int_j.format(ifc))
                print(int_result)

                print(deco.clr(self.light_j.format(ifc), "cyan"))
                light_result= self.miko_con.send_command(self.light_j.format(ifc))
                print(light_result)

                print(deco.clr(self.log_j.format(ifc), "cyan"))
                logs_result= self.miko_con.send_command(self.log_j.format(ifc))
                print(logs_result)

            else:### == "cisco"
                print(deco.clr(self.int_c.format(ifc), "cyan"))
                int_result= self.miko_con.send_command(self.int_c.format(ifc))
                print(int_result + "\n")

                print(deco.clr(self.light_c.format(ifc), "cyan"))
                light_result= self.miko_con.send_command(self.light_c.format(ifc))
                print(light_result + "\n")

                print(deco.clr(self.log_c.format(ifc), "cyan"))
                logs_result= self.miko_con.send_command(self.log_c.format(ifc))
                print(logs_result + "\n")

        except KeyboardInterrupt:
            print(deco.clr("\nDetected interruption\n", "red"))
            self.miko_disco()
            self.db_disco()
            sys.exit()

        self.miko_disco()


    def create_matrix(self, dict_type):

        self.reset_length()

        if dict_type == "ifc":
            sorted_dict_ifc= sorted(self.master_ifc.items(), key= lambda x: datetime.datetime.strptime(str(datetime.datetime.now().year) + " " + x[1][0], "%Y %b %d %H:%M:%S"))

            ### For only count max length
            for tap in sorted_dict_ifc:
                ### count value and compare
                if tap[0] == None: pass                             # Router Interface
                elif len(tap[0]) > self.max_len["rt_ifc"]: self.max_len["rt_ifc"]= len(tap[0])
                if tap[1][0] == None: tap[1][0]= ""                     # Date
                elif len(tap[1][0]) > self.max_len["date"]: self.max_len["date"]= len(tap[1][0])
                if tap[1][1] == None: tap[1][1]= ""                         # InterfaceDescription
                elif len(tap[1][1]) > self.max_len["ifdesc"]: self.max_len["ifdesc"]= len(tap[1][1])
                if tap[1][2] == None: tap[1][2]= ""                         # Current status
                elif len(tap[1][2]) > self.max_len["cur"]: self.max_len["cur"]= len(tap[1][2])
                if tap[1][3] == None: tap[1][3]= ""                         # DB status
                elif len(tap[1][3]) > self.max_len["db"]: self.max_len["db"]= len(tap[1][3])
                if tap[1][4] == None: tap[1][4]= ""                         # Count
                elif len(str(tap[1][4])) > self.max_len["count"]: self.max_len["count"]= len(str(tap[1][4]))
                if tap[1][5] == None: tap[1][5]= ""                             # Ticket Number
                if len(str(tap[1][5])) > self.max_len["ticket"]: self.max_len["ticket"]= len(str(tap[1][5]))

            ### create dict stored result of subtract origin-len from max-len
            self.sub_len()

            #print(self.diff_len)

            #print("\nsorted_dict")
            #print(len(sorted_dict_ifc))
            #print(sorted_dict_ifc)

            print("\n[ Interface ]")
            #print(self.max_len)
            #print(self.max_len["ticket"])

            ### First line as column
            print("Line" + " " * (self.diff_len["line"] + 1) + "| " +\
                  "LastDown" + " " * (self.diff_len["date"] + 1) + "| " +\
                  "Interface" + " " * (self.diff_len["rt_ifc"] + 1) + "| " +\
                  "Description" + " " * (self.diff_len["ifdesc"] + 1) + "| " +\
                  "cur" + " " * (self.diff_len["cur"] + 1) + "| " +\
                  "DB" + " " * (self.diff_len["db"] + 1) + "| " +\
                  "count" + " " + "| " +\
                  "NOC_field" + " " * (self.diff_len["ticket"] + 1))

            ### Second line as line(-+)
            print("-" * (self.max_len["line"] + 1) + "+" +\
                  "-" * (self.max_len["date"] + 2) + "+" +\
                  "-" * (self.max_len["rt_ifc"] + 2) + "+" +\
                  "-" * (self.max_len["ifdesc"] + 2) + "+" +\
                  "-" * (self.max_len["cur"] + 2) + "+" +\
                  "-" * (self.max_len["db"] + 2) + "+" +\
                  "-" * (self.max_len["count"] + 2) + "+" +\
                  "-" * (self.max_len["ticket"] + 2))

            ### print Values
            for tap in sorted_dict_ifc:
                if tap[1][2] == "down":
                    print(deco.clr(str(self.count_line) + " " * (self.max_len["line"] - len(str(self.count_line))) + " | " +\
                            tap[1][0] + " " * (self.max_len["date"] - len(tap[1][0])) + " | " +\
                            tap[0] + " " * (self.max_len["rt_ifc"] - len(tap[0])) + " | " +\
                            tap[1][1] + " " * (self.max_len["ifdesc"] - len(tap[1][1])) + " | " +\
                            tap[1][2] + " " * (self.max_len["cur"] - len(tap[1][2])) + " | " +\
                            tap[1][3] + " " * (self.max_len["db"] - len(tap[1][3])) + " | " +\
                            str(tap[1][4]) + " " * (self.max_len["count"] - len(str(tap[1][4]))) + " | " +\
                            tap[1][5], "red"))
                else:
                    
                    print(str(self.count_line) + " " * (self.max_len["line"] - len(str(self.count_line))) + " | " +\
                            tap[1][0] + " " * (self.max_len["date"] - len(tap[1][0])) + " | " +\
                            tap[0] + " " * (self.max_len["rt_ifc"] - len(tap[0])) + " | " +\
                            tap[1][1] + " " * (self.max_len["ifdesc"] - len(tap[1][1])) + " | " +\
                            tap[1][2] + " " * (self.max_len["cur"] - len(tap[1][2])) + " | " +\
                            tap[1][3] + " " * (self.max_len["db"] - len(tap[1][3])) + " | " +\
                            str(tap[1][4]) + " " * (self.max_len["count"] - len(str(tap[1][4]))) + " | " +\
                            tap[1][5])
                self.count_line+=1

            self.count_ifc= self.count_line - 1
            print(" ")
            return(sorted_dict_ifc)

        elif dict_type == "bgp":
            sorted_dict_bgp= sorted(self.master_ebgp.items(), key= lambda x: datetime.datetime.strptime(str(datetime.datetime.now().year) + " " + x[1][0], "%Y %b %d %H:%M:%S"))

            #print("\nsorted_dict_bgp")
            #print(len(sorted_dict_bgp))
            #print(sorted_dict_bgp)
            ### for only count max-length phase.
            for tap in sorted_dict_bgp:
                if len(tap[1][0]) > self.max_len["date"]: self.max_len["date"]= len(tap[1][0])      # Date
                if len(tap[1][1]) > self.max_len["rt_ifc"]: self.max_len["rt_ifc"]= len(tap[1][1])  # Router Interface (No possibilities that this column is None)
                if len(tap[1][2]) > self.max_len["peer"]: self.max_len["peer"]= len(tap[1][2])      # Peer Addrres (No possibilities that this column is None)
                if tap[1][3] == None: tap[1][3]= " "                            # ASN
                if len(str(tap[1][3])) > self.max_len["asn"]: self.max_len["asn"]= len(str(tap[1][3]))
                if tap[1][4] == None: tap[1][4]= " "                            # BGP description status
                if len(tap[1][4]) > self.max_len["bgpdesc"]: self.max_len["bgpdesc"]= len(tap[1][4])
                if len(tap[1][5]) > self.max_len["cur"]: self.max_len["cur"]= len(tap[1][5])        # Current status(No possibilities that this column is None)
                if tap[1][6] == None: tap[1][6]= " "
                if len(tap[1][6]) > self.max_len["db"]: self.max_len["db"]= len(tap[1][6])      # DB status


            ### create dict stored result of subtract origin-len from max-len
            self.sub_len()

            #print(self.diff_len)
            #print(self.diff_len)

            print("[ eBGP ]")

            ### First line as column
            print("Line" + " " * (self.diff_len["line"] + 1) + "| " +\
                  "LastDown" + " " * (self.diff_len["date"] + 1) + "| " +\
                  "Interface" + " " * (self.diff_len["rt_ifc"] + 1) + "| " +\
                  "Peer Address" + " " * (self.diff_len["peer"] + 1) + "| " +\
                  "ASN" + " " * (self.diff_len["asn"] + 1) + "| " +\
                  "Description" + " " * (self.diff_len["bgpdesc"] + 1) + "| " +\
                  "cur" + " " * (self.diff_len["cur"] + 1) + "| " +\
                  "DB" + " " * (self.diff_len["db"] + 1) + "| " +\
                  "count" + " " )

            ### Second line as line(-+)
            print("-" * (self.max_len["line"] + 1) + "+" +\
                  "-" * (self.max_len["date"] + 2) + "+" +\
                  "-" * (self.max_len["rt_ifc"] + 2) + "+" +\
                  "-" * (self.max_len["peer"] + 2) + "+" +\
                  "-" * (self.max_len["asn"] + 2) + "+" +\
                  "-" * (self.max_len["bgpdesc"] + 2) + "+" +\
                  "-" * (self.max_len["cur"] + 2) + "+" +\
                  "-" * (self.max_len["db"] + 2) + "+" +\
                  "-" * (self.max_len["count"] + 2))

            ### Print values
            for tap in sorted_dict_bgp:
                if tap[1][5] == "down":
                    print(deco.clr(str(self.count_line) + " " * (self.max_len["line"] - len(str(self.count_line))) + " | " +\
                            tap[1][0] + " " * (self.max_len["date"] - len(tap[1][0])) + " | " +\
                            tap[1][1] + " " * (self.max_len["rt_ifc"] - len(tap[1][1])) + " | " +\
                            tap[1][2] + " " * (self.max_len["peer"] - len(tap[1][2])) + " | " +\
                            tap[1][3] + " " * (self.max_len["asn"] - len(tap[1][3])) + " | " +\
                            tap[1][4] + " " * (self.max_len["bgpdesc"] - len(tap[1][4])) + " | " +\
                            tap[1][5] + " " * (self.max_len["cur"] - len(tap[1][5])) + " | " +\
                            tap[1][6] + " " * (self.max_len["db"] - len(tap[1][6])) + " | " +\
                            str(tap[1][7]) + " " * (self.max_len["count"] - len(str(tap[1][7]))), "red"))
                else:
                    print(str(self.count_line) + " " * (self.max_len["line"] - len(str(self.count_line))) + " | " +\
                            tap[1][0] + " " * (self.max_len["date"] - len(tap[1][0])) + " | " +\
                            tap[1][1] + " " * (self.max_len["rt_ifc"] - len(tap[1][1])) + " | " +\
                            tap[1][2] + " " * (self.max_len["peer"] - len(tap[1][2])) + " | " +\
                            tap[1][3] + " " * (self.max_len["asn"] - len(tap[1][3])) + " | " +\
                            tap[1][4] + " " * (self.max_len["bgpdesc"] - len(tap[1][4])) + " | " +\
                            tap[1][5] + " " * (self.max_len["cur"] - len(tap[1][5])) + " | " +\
                            tap[1][6] + " " * (self.max_len["db"] - len(tap[1][6])) + " | " +\
                            str(tap[1][7]) + " " * (self.max_len["count"] - len(str(tap[1][7]))))

                self.count_line+= 1
            self.count_bgp= self.count_line - self.count_ifc - 1

            print(" ")
            return(sorted_dict_bgp)

        elif dict_type == "vc":
            sorted_dict_vc= sorted(self.master_vc.items(), key= lambda x: datetime.datetime.strptime(str(datetime.datetime.now().year) + " " + x[1][0], "%Y %b %d %H:%M:%S"))
            #print(sorted_dict_vc)
            #print(self.max_len)
            ### Counting maximum length
            for tap in sorted_dict_vc:
                if len(tap[1][0]) > self.max_len["date"]: self.max_len["date"]= len(tap[1][0])
                if len(tap[1][1]) > self.max_len["vcid"]: self.max_len["vcid"]= len(tap[1][1])
                if len(tap[1][2]) > self.max_len["rt_ifc"]: self.max_len["rt_ifc"]= len(tap[1][2])
                if tap[1][3] == None: tap[1][3]= " "
                if len(tap[1][3]) > self.max_len["other"]: self.max_len["other"]= len(tap[1][3])
                if tap[1][4] == None: tap[1][4]= " "
                if len(tap[1][4]) > self.max_len["vcdesc"]: self.max_len["vcdesc"]= len(tap[1][4])
                if tap[1][5] == None: tap[1][5]= " "
                if len(tap[1][5]) > self.max_len["usid"]: self.max_len["usid"]= len(tap[1][5])
                if len(tap[1][6]) > self.max_len["cur"]: self.max_len["cur"]= len(tap[1][6])
                if tap[1][7] == None: tap[1][7]= " "
                if len(tap[1][7]) > self.max_len["db"]: self.max_len["db"]= len(tap[1][7])
                if len(str(tap[1][8])) > self.max_len["count"]: self.max_len["count"]= len(str(tap[1][8]))

            ### create dict stored result of subtract origin-len from max-len
            self.sub_len()

            #print(self.max_len)
            #print(self.diff_len)

            print("\n[ VC ]")

            ### First line of matrix
            print("Line" + " " * (self.diff_len["line"] + 1) + "| " +\
                  "LastDown" + " " * (self.diff_len["date"] + 1) + "| " +\
                  "VC-ID" + " " * (self.diff_len["vcid"] + 1) + "| " +\
                  "Interface" + " " * (self.diff_len["rt_ifc"] + 1) + "| " +\
                  "Other Side" + " " * (self.diff_len["other"] + 1) + "| " +\
                  "Description" + " " * (self.diff_len["vcdesc"] + 1) + "| " +\
                  "USID" + " " * (self.diff_len["usid"] + 1) + "| " +\
                  "cur" + " " * (self.diff_len["cur"] + 1) + "| " +\
                  "db" + " " * (self.diff_len["db"] + 1) + "| " +\
                  "count" + " " * (self.diff_len["count"] + 1))

            ### Second line of matrix
            print("-" * (self.max_len["line"] + 1) + "+" +\
                "-" * (self.max_len["date"] + 2) + "+" +\
                "-" * (self.max_len["vcid"] + 2) + "+" +\
                "-" * (self.max_len["rt_ifc"] + 2) + "+" +\
                "-" * (self.max_len["other"] + 2) + "+" +\
                "-" * (self.max_len["vcdesc"] + 2) + "+" +\
                "-" * (self.max_len["usid"] + 2) + "+" +\
                "-" * (self.max_len["cur"] + 2) + "+" +\
                "-" * (self.max_len["db"] + 2) + "+" +\
                "-" * (self.max_len["count"] + 2))

            ### Value line
            for tap in sorted_dict_vc:
                if tap[1][6] == "down":
                    print(deco.clr(str(self.count_line) + " " * (self.max_len["line"] - len(str(self.count_line))) + " | " +\
                        tap[1][0] + " " * (self.max_len["date"] - len(tap[1][0])) + " | " +\
                        tap[1][1] + " " * (self.max_len["vcid"] - len(tap[1][1])) + " | " +\
                        tap[1][2] + " " * (self.max_len["rt_ifc"] - len(tap[1][2])) + " | " +\
                        tap[1][3] + " " * (self.max_len["other"] - len(tap[1][3])) + " | " +\
                        tap[1][4] + " " * (self.max_len["vcdesc"] - len(tap[1][4])) + " | " +\
                        tap[1][5] + " " * (self.max_len["usid"] - len(tap[1][5])) + " | " +\
                        tap[1][6] + " " * (self.max_len["cur"] - len(tap[1][6])) + " | " +\
                        tap[1][7] + " " * (self.max_len["db"] - len(tap[1][7])) + " | " +\
                        str(tap[1][8]) + " " * (self.max_len["count"] - len(str(tap[1][8]))), "red"))
                else:
                    print(str(self.count_line) + " " * (self.max_len["line"] - len(str(self.count_line))) + " | " +\
                        tap[1][0] + " " * (self.max_len["date"] - len(tap[1][0])) + " | " +\
                        tap[1][1] + " " * (self.max_len["vcid"] - len(tap[1][1])) + " | " +\
                        tap[1][2] + " " * (self.max_len["rt_ifc"] - len(tap[1][2])) + " | " +\
                        tap[1][3] + " " * (self.max_len["other"] - len(tap[1][3])) + " | " +\
                        tap[1][4] + " " * (self.max_len["vcdesc"] - len(tap[1][4])) + " | " +\
                        tap[1][5] + " " * (self.max_len["usid"] - len(tap[1][5])) + " | " +\
                        tap[1][6] + " " * (self.max_len["cur"] - len(tap[1][6])) + " | " +\
                        tap[1][7] + " " * (self.max_len["db"] - len(tap[1][7])) + " | " +\
                        str(tap[1][8]) + " " * (self.max_len["count"] - len(str(tap[1][8]))))

                self.count_line+=1
            self.count_vc= self.count_line - self.count_bgp - self.count_ifc - 1
            print(" ")
            return(sorted_dict_vc)


    def select_number(self):
        print(deco.clr("\nWhat number-line do you want to investigate?", "cyan"))
        print(deco.clr("For example: 1 , 1 3 5 , 1-3 10 13 , all (Total number must be less than 10)", "cyan"))

        ### Necessary to adjust number
        self.count_line-= 1

        #print(self.count_ifc)
        #print(self.count_bgp)
        #print(self.count_vc)
        #print(self.count_line)
        #print(self.input_num_list)

        try:
            while True:
                err_flag= 0
                #time.sleep(1)
                inputted_num= input(">>> ")

                ### Beginning of error check
                ### Here is in case of "all"
                if re.search(r"^all$|^ALL$|^All$", inputted_num) != None:
                    if self.count_line > 10:
                        print(deco.clr("Too lots lines to investigate. Please reduce to be less than 10.\n", "red"))
                        continue
                    for num in range(self.count_line):
                        self.input_num_list.append(int(num) + 1)
                    break

                ### Here is in case of Multiple "number"
                for val in inputted_num.split(" "):

                    ### Checking "-"
                    if re.search(r"^\d+-\d+$", val) != None:
                        for num in range(int(val.split("-")[0]), int(val.split("-")[-1]) + 1):
                            self.input_num_list.append(int(num))
                        continue

                    if re.search(r"\D", val) != None:
                        print(deco.clr("DO NOT input without number. If multiple, separate using \" \" blank-space.\n", "red"))
                        err_flag= 1
                        self.input_num_list= []
                        break
                    elif re.search(r"^\d+$", val) != None:
                        if int(val) > self.count_line or int(val) == 0:
                            print(deco.clr("Inputted number \"{}\" is out of range.".format(val), "red"))
                            err_flag= 1
                            self.input_num_list= []
                            break
                        else:### = No issue in inputted number
                            self.input_num_list.append(int(val))

                if len(inputted_num.split(" ")) > 10 or len(self.input_num_list) > 10:
                    print(deco.clr("Too lots lines to investigate. Please reduce to be less than 10.\n", "red"))
                    err_flag= 1
                    self.input_num_list= []

                if err_flag == 1: continue
                break

        except KeyboardInterrupt:
            print("\nDetected Interrupt\n")
            sys.exit()

        #print(self.count_ifc)
        #print(self.count_bgp)
        #print(self.count_vc)
        #print(inputted_num)
        #print(self.input_num_list)


    def investigation(self):
        peers = []
        for line_num in self.input_num_list:
            cmd_list= []

            ### IFC phase
            if line_num <= self.count_ifc:
                #print(self.sorted_ifc[line_num - 1][0])
                router= self.sorted_ifc[line_num - 1][0].split(" ")[0]
                ifc= self.sorted_ifc[line_num - 1][0].split(" ")[-1]
                os_type= self.search_os(router)
                self.miko_connect(os_type, router)

                print(deco.clr("\n\n*** Checking {} ***".format(router), "cyan"))

                ### CISCO
                if os_type == "cisco_xr" or os_type == "cisco_ios":
                    if re.search(r"^Bundle|^bundle|^be|^ae", ifc) != None and re.search(r"\d+\.\d+", ifc) == None: cmd_list.append(self.c_lacp.format(ifc))
                    elif re.search(r"^Bundle|^bundle|^be|^ae", ifc) != None and re.search(r"\d+\.\d+", ifc) != None: cmd_list(self.c_lacp.format(ifc))

                    cmd_list.append(self.c_desc.format(ifc))

                    if re.search(r"^lo|^Lo", ifc) == None: cmd_list.append(self.c_rate.format(ifc))

                    cmd_list.append(self.c_int.format(ifc))

                    if re.search(r"^Bundle|^bundle|^ae|^be|^lo|^Lo|\d+\.\d+", ifc) == None: cmd_list.append(self.c_light.format(ifc))

                    cmd_list.append(self.c_logs.format(ifc))

                    #### Checking if this ckt has BGP session. if exist, get bgp sum. Based on Charles request.
                    peer_list= self.check_peer(router, ifc)
                    for peer_addr in peer_list:
                        if peer_addr[0] != None:
                            #print(peer_addr[0])
                            if re.search(r":", peer_addr[0]) != None:
                                cmd_list.append(self.c_v6bgp.format(peer_addr[0]))
                            else:
                                cmd_list.append(self.c_v4bgp.format(peer_addr[0]))
                ### JUNIPER
                elif os_type == "junos":
                    if re.search(r"^Bundle|^bundle|^be|^ae", ifc) != None and re.search(r"^ae\d+\.\d+", ifc) == None: #if it is bundle and not logical(e.g. ae1 not ae1.0)
                        cmd_list.append(self.j_lacp.format(ifc))
                    cmd_list.append(self.j_desc.format(ifc))

                    if re.search(r"^ae\d+\.\d+|\d+\.\d+", ifc) != None: # if it is not bundle interface
                        cmd_list.append(self.j_rate.format(ifc.split(".")[0])) 
                    elif re.search(r"^lo|^Lo", ifc) == None: #If it is loopback
                        cmd_list.append(self.j_rate.format(ifc)) 

                    if re.search(r"^ae\d+\.\d+|\d+\.\d+", ifc) == None:  #If it is NOT bundle
                        cmd_list.append(self.j_int.format(ifc))
                    else: cmd_list.append(self.j_int.format(ifc.split(".")[0]))

                    if re.search(r"^Bundle|^bundle|^be|^ae|^lo|^Lo|^ae\d+\.\d+|\d+\.\d+", ifc) == None: #If it is NOT bundle nor loopback.
                         cmd_list.append(self.j_light.format(ifc))

                    cmd_list.append(self.j_logs.format(ifc))

                    #Add command for check BGP peers which related to the interface
                    peer_list= self.check_peer(router, ifc)
                    for peer_addr in peer_list:
                        if peer_addr[0] != None:
                            cmd_list.append(self.j_bgp.format(peer_addr[0]))
                ### NOKIA
                else:
                    peer_ifc = ifc
                    ifc = re.sub("eth-","",ifc)
                    ifc = re.sub(":\d+","",ifc)
                    if re.match(r"(.*c\d+)",ifc) is not None: ### for optical commands "1/1/c27/3" need to be changed to "1/1/c27"
                        ifc = re.match(r"(.*c\d+)",ifc).group(1)

                    if re.search("lag",ifc) != None: #If it is bundle
                         cmd_list.append(self.n_lacp.format(re.sub("lag","",ifc))) #lag1 -> 1
                    cmd_list.append(self.n_desc.format(ifc))             
                    cmd_list.append(self.n_int.format(ifc))
                    if re.search("lag",ifc) == None: #If it is NOT bundle
                        cmd_list.append(self.n_light.format(ifc))

                    #Add command for check BGP peers which related to the interface
                    peer_list= self.check_peer(router, peer_ifc) 
                    for peer_addr in peer_list:
                        if peer_addr[0] != None:
                            if re.search(r":", peer_addr[0]) != None:
                                cmd_list.append(self.n_v6bgp.format(peer_addr[0]))
                            else:
                                cmd_list.append(self.n_v4bgp.format(peer_addr[0]))
                        peers.append(peer_addr[0])

            ### BGP phase
            elif line_num > self.count_ifc and line_num <= (self.count_ifc + self.count_bgp):
                router= self.sorted_bgp[line_num - self.count_ifc - 1][1][1].split(" ")[0]
                ifc= self.sorted_bgp[line_num - self.count_ifc - 1][1][1].split(" ")[-1]
                os_type= self.search_os(router)
                peer= self.sorted_bgp[line_num - self.count_ifc - 1][1][2]
                self.miko_connect(os_type, router)
                
                print(deco.clr("\n\n*** Checking {} ***".format(router), "cyan"))
                ### CISCO
                if os_type == "cisco_xr" or os_type == "cisco_ios":
                    if re.search(r"^bundle|^Bundle|^be|^ae", ifc) != None and re.search(r"\d+\.\d+", ifc) == None: #If it is bundle and not logical
                        cmd_list.append(self.c_lacp.format(ifc))
                    elif re.search(r"^bundle|^Bundle|^be|^ae", ifc) != None and re.search(r"\d+\.\d+", ifc) != None: # if it is bundle and logical.
                        cmd_list.append(self.c_lacp.format(ifc.split(".")[0]))

                    #print(self.c_desc.format(ifc))
                    cmd_list.append(self.c_desc.format(ifc))

                    if re.search(r"^lo|^Lo", ifc) == None:
                        #print(self.c_rate.format(ifc))
                        cmd_list.append(self.c_rate.format(ifc))

                    #print(self.c_int.format(ifc))
                    cmd_list.append(self.c_int.format(ifc))

                    if re.search(r"^bundle|^Bundle|^be|^ae|^lo|^Lo", ifc) == None:
                        #print(self.c_light.format(ifc))
                        cmd_list.append(self.c_light.format(ifc))

                    if peer.find(r":") == -1:
                        #print(self.c_v4bgp.format(peer))
                        cmd_list.append(self.c_v4bgp.format(peer))
                    else:
                        #print(self.c_v6bgp.format(peer))
                        cmd_list.append(self.c_v6bgp.format(peer))

                    #print(self.c_logs.format(peer))
                    cmd_list.append(self.c_logs.format(peer))
                ### JUNIPER
                elif os_type == "junos":
                    if re.search(r"^bundle|^Bundle|^be|^ae", ifc) != None and re.search(r"^ae\d+\.\d+", ifc) == None:
                        cmd_list.append(self.j_lacp.format(ifc))
                    elif re.search(r"^bundle|^Bundle|^be|^ae", ifc) != None and re.search(r"^ae\d+\.\d+", ifc) != None:
                        cmd_list.append(self.j_lacp.format(ifc.split(".")[0]))

                    cmd_list.append(self.j_desc.format(ifc))

                    if re.search(r"^ae\d+\.\d+|\d+\.\d+", ifc) != None:
                        cmd_list.append(self.j_rate.format(ifc.split(".")[0]))
                    elif re.search(r"^lo|^Lo", ifc) == None:
                        cmd_list.append(self.j_rate.format(ifc))

                    if re.search(r"^ae\d+\.\d+|\d+\.\d+", ifc) == None:
                        cmd_list.append(self.j_int.format(ifc))
                    else:
                        cmd_list.append(self.j_int.format(ifc.split(".")[0]))

                    if re.search(r"^bundle|^Bundle|^be|^ae|^lo|^Lo|^ae\d+\.\d+|\d+\.\d+", ifc) == None:
                        cmd_list.append(self.j_light.format(ifc))

                    cmd_list.append(self.j_bgp.format(peer))

                    cmd_list.append(self.j_logs.format(peer))
                ### NOKIA
                else:
                    if re.search(r"^lag", ifc) != None:
                       cmd_list.append(self.n_lacp.format(re.sub("lag","",ifc))) #lag1 -> 1
                    ifc = re.sub("eth-","",ifc)
                    ifc = re.sub(":\d+","",ifc)
                    if re.match(r"(.*c\d+)",ifc) is not None: ### for optical commands "1/1/c27/3" need to be changed to "1/1/c27"
                        ifc = re.match(r"(.*c\d+)",ifc).group(1)
                    cmd_list.append(self.n_desc.format(ifc))
                    cmd_list.append(self.n_int.format(ifc))        
                    cmd_list.append(self.n_light.format(ifc))
                    cmd_list.append(self.n_logs.format(peer))
                    if peer.find(r":") == -1:
                        cmd_list.append(self.n_v4bgp.format(peer))
                    else:
                        cmd_list.append(self.n_v6bgp.format(peer))
                    peers.append(peer)
                        

            else: ### Beginning of VC-phase
                router= self.sorted_vc[line_num - self.count_ifc - self.count_bgp -1][1][2].split(" ")[0]
                ifc= self.sorted_vc[line_num - self.count_ifc - self.count_bgp -1][1][2].split(" ")[-1]
                vc= self.sorted_vc[line_num - self.count_ifc - self.count_bgp -1][1][1].split("-")[-1]
                os_type= self.search_os(router)
                self.miko_connect(os_type, router)

                print(deco.clr("\n\n*** Checking {} ***".format(router), "cyan"))
                ### CISCO
                if os_type == "cisco_xr" or os_type == "cisco_ios":
                    if re.search(r"^bundle|^Bundle|^be|^ae", ifc) != None and re.search(r"\d+\.\d+", ifc) == None: cmd_list.append(self.c_lacp.format(ifc))
                    cmd_list.append(self.c_desc.format(ifc))
                    if re.search(r"\d+\.\d+", ifc) != None: cmd_list.append(self.c_rate.format(ifc.split(".")[0]))
                    elif re.search(r"^lo|^Lo", ifc) == None: cmd_list.append(self.c_rate.format(ifc))
                    cmd_list.append(self.c_int.format(ifc))
                    if re.search(r"^bundle|^Bundle|^be|^ae|^lo|^Lo|\d+\.\d+", ifc) == None: cmd_list.append(self.c_light.format(ifc))
                    cmd_list.append(self.c_vcsum.format(vc))
                    cmd_list.append(self.c_vcdetail.format(vc))
                    cmd_list.append(self.c_vclogs.format(vc))
                ### Juniper
                elif os_type == "junos":
                    if re.search(r"^bundle|^Bundle|^be|^ae", ifc) != None: cmd_list.append(self.j_lacp.format(ifc))
                    cmd_list.append(self.j_desc.format(ifc))
                    if re.search(r"^lo|^Lo", ifc) == None: cmd_list.append(self.j_rate.format(ifc))
                    cmd_list.append(self.j_int.format(ifc))
                    if re.search(r"^bundle|^Bundle|^be|^ae|^lo|^Lo|\d+\.\d+", ifc) == None: cmd_list.append(self.j_light.format(ifc))
                    cmd_list.append(self.j_vcsum.format(ifc+".0"))
                    cmd_list.append(self.j_vclogs.format(vc))
                ### NOKIA
                else:
                    cmd_list.append(self.n_vcsum.format(vc))
                    cmd_list.append(self.n_vclogs.format(vc))


            #for i in cmd_list: print(i)

            ### Sending command here using appended command list in above.
            for commands in cmd_list:
                result= self.miko_con.send_command(commands, strip_prompt=True, strip_command=True, delay_factor= 2)
                print(deco.clr("\n- {}".format(commands), "green"))
                for num,val_line in enumerate(result.splitlines()):
                    #if val_line.find(r"{master}") != -1: continue
                    if re.search(r"\{master\}|---\(more", val_line) != None: continue
                    elif os_type == "nokia_sros" and "show router bgp summary family" in commands:
                        for peer in peers:
                                 if peer in val_line:
                                     print(val_line)
                                     print(result.splitlines()[num+1])
                                     break
                    elif os_type == "nokia_sros" and "optical" in commands:
                        if re.search(r"(.*c\d+)",ifc) is not None and re.search("Lane ID",val_line) is not None: #10G optical
                            i = 0
                            while i < 6: # print next 5lines include 4lanes of power levels
                               print(result.splitlines()[num+i])
                               i += 1
                               time.sleep(1)
                        elif re.search(r"(.*c\d+)",ifc) is None and re.search("Value",val_line) is not None: #1G optical
                            print(result.splitlines()[num]) #INDEX
                            print(result.splitlines()[num+1]) # -----
                            print(result.splitlines()[num+6]) # TX
                            print(result.splitlines()[num+5]) # RX
                         
                        
                    else: print(val_line)
                if os_type != "juniper":
                    print(" ")

    def reset_length(self):
        self.len_rtifc= 9       # interface
        self.len_ifdesc= 11 # Description
        self.len_cur= 3         # cur / DB      # up/down/turn-up
        self.len_db= 2          # cur / DB      # up/down/turn-up
        self.len_ticket= 9      # ticket

        self.origin_len= {}
        self.origin_len["line"]= 4
        self.origin_len["date"]= 8
        self.origin_len["rt_ifc"]= 9
        self.origin_len["ifdesc"]= 11
        self.origin_len["cur"]= 3
        self.origin_len["db"]= 2
        self.origin_len["count"]= 5
        self.origin_len["ticket"]= 9
        self.origin_len["peer"]= 12
        self.origin_len["asn"]= 3
        self.origin_len["bgpdesc"]= 11
        self.origin_len["vcid"]= 5
        self.origin_len["other"]= 10
        self.origin_len["vcdesc"]= 11
        self.origin_len["usid"]= 4
        self.origin_len["comment"]= 9
        self.max_len= self.origin_len.copy()


    def sub_len(self):
        ### Create subtract length dict
        self.diff_len= self.max_len.copy()
        self.diff_len["line"]= self.max_len["line"] - self.origin_len["line"]
        self.diff_len["date"]= self.max_len["date"] - self.origin_len["date"]
        self.diff_len["rt_ifc"]= self.max_len["rt_ifc"] - self.origin_len["rt_ifc"]
        self.diff_len["ifdesc"]= self.max_len["ifdesc"] - self.origin_len["ifdesc"]
        self.diff_len["cur"]= self.max_len["cur"] - self.origin_len["cur"]
        self.diff_len["db"]= self.max_len["db"] - self.origin_len["db"]
        self.diff_len["ticket"]= self.max_len["ticket"] - self.origin_len["ticket"]

        self.diff_len["bgpdesc"]= self.max_len["bgpdesc"] - self.origin_len["bgpdesc"]
        self.diff_len["asn"]= self.max_len["asn"] - self.origin_len["asn"]
        self.diff_len["peer"]= self.max_len["peer"] - self.origin_len["peer"]

        self.diff_len["vcid"]= self.max_len["vcid"] - self.origin_len["vcid"]
        self.diff_len["other"]= self.max_len["other"] - self.origin_len["other"]
        self.diff_len["vcdesc"]= self.max_len["vcdesc"] - self.origin_len["vcdesc"]
        self.diff_len["usid"]= self.max_len["usid"] - self.origin_len["usid"]

    def miko_disco(self):
        self.miko_con.clear_buffer()
        self.miko_con.disconnect()

    def db_disco(self):
        self.db_cur.close()
        self.db_con.close()


###### main ######
def main():

    ### MEMO ######
    ### ag.hour= -hr option
    ### ag.timespan= -t option
    ### ag.count= -c option
    ### ag.separate= -s option
    ### ag.grep= -g option
    ### ag.ignore= --ignore option
    ### ag.timerange= --timerange option
    ### ag.asia= --asia option
    ### ag.investigate= -i switch

    ag = argprs.run_parse()

    ### Organize variable which option type is store_true
    if ag.grep != None and ag.asia != False:
        print("\nCan not use grep and asia option concurrently.\n")
        sys.exit()

    if ag.grep == None: g_flag= "None"
    else: g_flag= ag.grep[0]

    if ag.timerange == None: t_range= "None"
    else: t_range= ag.timerange[0]

    if ag.asia != False: g_flag= r"\.jp|\.au|\.hk|\.tw|\.kr|\.sg|\.my|\.id|\.bn|\.th"
    ######

    ### Make log about usage
    #logs= CreateLog(ag.hour, ag.timespan, ag.count, ag.separate, g_flag, ag.ignore, t_range, ag.asia, ag.investigate)
    #logs.start()

    ### Create initial message
    if ag.investigate == True:
        print("\n *** Preparing investigate mode ***")
    elif t_range == "None":
        print("\n *** Start {} times repeatedly, output every {} seconds, search logs from {} hour ago thru now. ***".format(ag.count, ag.timespan, ag.hour))
    else:
        print("\n *** Running with time-range flag ***\n (Note: The more input time-range is long, it takes a long time until show output.\n\
        In case of 24h range, it may takes around 20sec.)\n")

    try:
        for lpcount in range(ag.count): ### SET LOOP COUNT

            input_time= ag.hour ### SET GO BACK TIME
            log= Log(input_time)
            ifc_st, ifc_cnt, ebgp_st, ebgp_cnt,ibgp_st,ibgp_cnt, vc_st, vc_cnt, origin_start_time, origin_end_time= log.get(t_range)

            ### For debug print ####
            #print(ifc_st)
            #print(ifc_cnt)
            #print(vc_st)
            #print(vc_cnt)
            #######################

            db= DB(ifc_st, ifc_cnt, ebgp_st, ebgp_cnt,ibgp_st, ibgp_cnt, vc_st, vc_cnt)
            userid, password= db.get_login_info()
            db.db_login()
            db.get_ifc_info()
            db.get_ebgp_info()
            db.get_ibgp_info()
            db.get_vc_info()
            master_ifc, master_ebgp, master_ibgp, master_vc, master_ifc_bb, master_ifc_bc, master_ifc_bp= db.return_dict()

            ### For debug print ####
            #print(master_ifc_bb)
            #print(master_ifc_bc)
            #print(master_ifc_bp)
            #print(master_ifc)
            ########################

            ##### Insert new branch for investigate mode to here. ####
            ##### Not sure but possibility that it happens the inherit error due to putting this before start monitor class.

            ### Start inherited investigate class branch
            if ag.investigate == True:
                inv= Investigate(master_ifc, master_ebgp, master_vc, master_ifc_bb, master_ifc_bc, master_ifc_bp,\
                        origin_start_time, origin_end_time, g_flag, ag.ignore, userid, password)

                inv.main()
                break

            ### Monitor phase
            monitor= Monitor(master_ifc, master_ebgp, master_ibgp, master_vc, master_ifc_bb, master_ifc_bc, master_ifc_bp,\
                     origin_start_time, origin_end_time, g_flag, ag.ignore)
            monitor.start(lpcount, ag.count, ag.separate)
            if t_range != "None": break
            elif lpcount == (ag.count - 1): break ### END decision for quick finish when the end of loop.
            print("\nNext update is {}sec later\n".format(ag.timespan))
            time.sleep(ag.timespan) ### SET TIME SPAN


    except KeyboardInterrupt:
        print("\nInterrupt Forcely")
        sys.exit()


    print("\n")

if __name__ == '__main__':
    main()
