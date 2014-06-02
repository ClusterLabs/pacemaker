#!/usr/bin/python

'''OCF IPaddr/IPaddr2 Resource Agent Test'''

__copyright__ = '''
Author: Huang Zhen <zhenhltc@cn.ibm.com>
Copyright (C) 2004 International Business Machines
Licensed under the GNU GPL.
'''

#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA.

import string,sys,struct,os,random,time,syslog
from cts.CTSvars import *
from __future__ import print_function


def usage():
    print("usage: %s [-2] [--ipbase|-i first-test-ip] [--ipnum|-n test-ip-num]"
          " [--help|-h] [--perform|-p op] [number-of-iterations]"
          % sys.argv[0])
    sys.exit(1)


def perform_op(ra, ip, op):
    os.environ["OCF_RA_VERSION_MAJOR"]    = "1"
    os.environ["OCF_RA_VERSION_MINOR"]    = "0"
    os.environ["OCF_ROOT"]                = CTSvars.OCF_ROOT_DIR
    os.environ["OCF_RESOURCE_INSTANCE"]   = ip
    os.environ["OCF_RESOURCE_TYPE"]       = ra
    os.environ["OCF_RESKEY_ip"]           = ip
    os.environ["HA_LOGFILE"]              = "/dev/null"
    os.environ["HA_LOGFACILITY"]          = "local7"
    path = CTSvars.OCF_ROOT_DIR + "/resource.d/heartbeat/" + ra
    return os.spawnvpe(os.P_WAIT, path, [ra, op], os.environ)


def audit(ra, iplist, ipstatus, summary):
    passed = 1
    for ip in iplist:
        ret = perform_op(ra, ip, "monitor")
        if ret != ipstatus[ip]:
            passed = 0
            log("audit: status of %s should be %d but it is %d\t [failure]" %
                (ip,ipstatus[ip],ret))
            ipstatus[ip] = ret    
    summary["audit"]["called"] += 1;
    if passed :
        summary["audit"]["success"] += 1
    else :
        summary["audit"]["failure"] += 1
        

def log(towrite):
    t = time.strftime("%Y/%m/%d_%H:%M:%S\t", time.localtime(time.time()))  
    logstr = t + " "+str(towrite)
    syslog.syslog(logstr)
    print(logstr)

if __name__ == '__main__': 
    ra = "IPaddr"
    ipbase = "127.0.0.10"
    ipnum = 1
    itnum = 50
    perform = None
    summary = {
        "start":{"called":0,"success":0,"failure":0},
        "stop" :{"called":0,"success":0,"failure":0},
        "audit":{"called":0,"success":0,"failure":0}
    }
    syslog.openlog(sys.argv[0], 0, syslog.LOG_LOCAL7)
    
    # Process arguments...
    skipthis = None
    args = sys.argv[1:]
    for i in range(0, len(args)) :
       if skipthis :
           skipthis = None
           continue
       elif args[i] == "-2" :
           ra = "IPaddr2"
       elif args[i] == "--ip" or args[i] == "-i" :
           skipthis = 1
           ipbase = args[i+1]
       elif args[i] == "--ipnum" or args[i] == "-n" :
           skipthis = 1
           ipnum = int(args[i+1])
       elif args[i] == "--perform" or args[i] == "-p" :
           skipthis = 1
           perform = args[i+1]
       elif args[i] == "--help" or args[i] == "-h" :
           usage()
       else:
           itnum = int(args[i])

    log("Begin OCF IPaddr/IPaddr2 Test")
    
    # Generate the test ips
    iplist = []
    ipstatus = {}
    fields = string.split(ipbase, '.')
    for i in range(0, ipnum) :
        ip = string.join(fields, '.')
        iplist.append(ip)
        ipstatus[ip] = perform_op(ra,ip,"monitor")
        fields[3] = str(int(fields[3])+1)
    log("Test ip:" + str(iplist))
    
    # If use ask perform an operation
    if perform != None:
        log("Perform opeartion %s"%perform)
        for ip in iplist:
            perform_op(ra, ip, perform)
        log("Done")
        sys.exit()    
    
    log("RA Type:" + ra)
    log("Test Count:" + str(itnum))
        
    # Prepare Random
    f = open("/dev/urandom", "r")
    seed = struct.unpack("BBB", f.read(3))
    f.close()
    #seed=(123,321,231)
    rand = random.Random()
    rand.seed(seed[0]) 
    log("Test Random Seed:" + str(seed))
    
    #
    # Begin Tests
    
    log(">>>>>>>>>>>>>>>>>>>>>>>>")
    for i in range(0, itnum):
        ip = rand.choice(iplist)
        if ipstatus[ip] == 0:
            op = "stop"
        elif ipstatus[ip] == 7:
            op = "start"
        else :
            op = rand.choice(["start","stop"])
            
        ret = perform_op(ra, ip, op)
        # update status
        if op == "start" and ret == 0:
            ipstatus[ip] = 0
        elif op == "stop" and ret == 0:
            ipstatus[ip] = 7
        else :
            ipstatus[ip] = 1
        result = ""
        if ret == 0:
            result = "success"
        else :
            result = "failure"
        summary[op]["called"] += 1
        summary[op][result] += 1
        log( "%d:%s %s \t[%s]"%(i, op, ip, result))
        audit(ra, iplist, ipstatus, summary)
        
    log("<<<<<<<<<<<<<<<<<<<<<<<<")
    log("start:\t" + str(summary["start"]))
    log("stop: \t" + str(summary["stop"]))
    log("audit:\t" + str(summary["audit"]))
    
