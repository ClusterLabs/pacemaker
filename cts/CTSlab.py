#!/usr/bin/python

'''CTS: Cluster Testing System: Lab environment module
 '''

__copyright__='''
Copyright (C) 2001,2005 Alan Robertson <alanr@unix.sh>
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

from UserDict import UserDict
import sys, time, types, string, syslog, random, os, string, signal, traceback

from CTS          import *
from CTSvars      import *
from CTSscenarios import *
from CTSaudits    import AuditList
from CTStests     import BSC_AddResource,TestList

from CM_ais import *
from CM_lha import crm_lha

cm = None
Tests = []
Chosen = []
scenario = None

# Not really used, the handler in 
def sig_handler(signum, frame) :
    if cm: cm.log("Interrupted by signal %d"%signum)
    if scenario: scenario.summarize()
    if signum == 15 :
        if scenario: scenario.TearDown()
        sys.exit(1)
        
class LabEnvironment(CtsLab):

    def __init__(self):
        CtsLab.__init__(self)

        #  Get a random seed for the random number generator.
        self["DoStonith"] = 1
        self["DoStandby"] = 1
        self["DoFencing"] = 1
        self["XmitLoss"] = "0.0"
        self["RecvLoss"] = "0.0"
        self["IPBase"] = "127.0.0.10"
        self["ClobberCIB"] = 0
        self["CIBfilename"] = None
        self["CIBResource"] = 0
        self["DoBSC"]    = 0
        self["use_logd"] = 0
        self["oprofile"] = []
        self["warn-inactive"] = 0
        self["ListTests"] = 0
        self["benchmark"] = 0
        self["logrestartcmd"] = "/etc/init.d/syslog-ng restart 2>&1 > /dev/null"
        self["Schema"] = "pacemaker-1.0"
        self["Stack"] = "openais"
        self["stonith-type"] = "external/ssh"
        self["stonith-params"] = "hostlist=all"
        self["at-boot"] = 1  # Does the cluster software start automatically when the node boot 
        self["logger"] = ([StdErrLog(self)])
        self["loop-minutes"] = 60
        self["valgrind-prefix"] = None
        self["valgrind-procs"] = "cib crmd attrd pengine"
        self["valgrind-opts"] = """--leak-check=full --show-reachable=yes --trace-children=no --num-callers=25 --gen-suppressions=all --suppressions="""+CTSvars.CTS_home+"""/cts.supp"""

        self["experimental-tests"] = 0
        self["valgrind-tests"] = 0
        self["unsafe-tests"] = 1
        self["loop-tests"] = 1
        self["scenario"] = "random"

def usage(arg, status=1):
    print "Illegal argument " + arg
    print "usage: " + sys.argv[0] +" [options] number-of-iterations" 
    print "\nCommon options: "  
    print "\t [--at-boot (1|0)],         does the cluster software start at boot time" 
    print "\t [--nodes 'node list'],     list of cluster nodes separated by whitespace" 
    print "\t [--limit-nodes max],       only use the first 'max' cluster nodes supplied with --nodes" 
    print "\t [--stack (heartbeat|ais)], which cluster stack is installed"
    print "\t [--logfile path],          where should the test software look for logs from cluster nodes" 
    print "\t [--outputfile path],       optional location for the test software to write logs to" 
    print "\t [--syslog-facility name],  which syslog facility should the test software log to" 
    print "\t [--choose testcase-name],  run only the named test" 
    print "\t [--list-tests],            list the valid tests" 
    print "\t [--benchmark],             add the timing information" 
    print "\t "
    print "Options for release testing: "  
    print "\t [--populate-resources | -r]" 
    print "\t [--schema (pacemaker-0.6|pacemaker-1.0|hae)] "
    print "\t [--test-ip-base ip]" 
    print "\t "
    print "Additional (less common) options: "  
    print "\t [--trunc (truncate logfile before starting)]" 
    print "\t [--xmit-loss lost-rate(0.0-1.0)]" 
    print "\t [--recv-loss lost-rate(0.0-1.0)]" 
    print "\t [--standby (1 | 0 | yes | no)]" 
    print "\t [--fencing (1 | 0 | yes | no)]" 
    print "\t [--stonith (1 | 0 | yes | no)]" 
    print "\t [--stonith-type type]" 
    print "\t [--stonith-args name=value]" 
    print "\t [--bsc]" 
    print "\t [--once],                 run all valid tests once" 
    print "\t [--no-loop-tests],        dont run looping/time-based tests" 
    print "\t [--no-unsafe-tests],      dont run tests that are unsafe for use with ocfs2/drbd" 
    print "\t [--valgrind-tests],       include tests using valgrind" 
    print "\t [--experimental-tests],   include experimental tests" 
    print "\t [--oprofile 'node list'], list of cluster nodes to run oprofile on]" 
    print "\t [--qarsh]                 Use the QARSH backdoor to access nodes instead of SSH"
    print "\t [--seed random_seed]"
    print "\t [--set option=value]"
    sys.exit(status)

    
#
#   A little test code...
#
if __name__ == '__main__': 

    Environment = LabEnvironment()

    NumIter = 0
    Version = 1
    LimitNodes = 0
    TruncateLog = 0
    ListTests = 0
    HaveSeed = 0
    node_list = ''

    # Set the signal handler
    signal.signal(15, sig_handler)
    signal.signal(10, sig_handler)
    
    # Process arguments...

    skipthis=None
    args=sys.argv[1:]
    for i in range(0, len(args)):
       if skipthis:
           skipthis=None
           continue

       elif args[i] == "-l" or args[i] == "--limit-nodes":
           skipthis=1
           LimitNodes = int(args[i+1])

       elif args[i] == "-r" or args[i] == "--populate-resources":
           Environment["CIBResource"] = 1

       elif args[i] == "-L" or args[i] == "--logfile":
           skipthis=1
           Environment["LogFileName"] = args[i+1]

       elif args[i] == "--outputfile":
           skipthis=1
           Environment["OutputFile"] = args[i+1]

       elif args[i] == "--test-ip-base":
           skipthis=1
           Environment["IPBase"] = args[i+1]

       elif args[i] == "--oprofile":
           skipthis=1
           Environment["oprofile"] = args[i+1].split(' ')

       elif args[i] == "--trunc":
           Environment["TruncateLog"]=1

       elif args[i] == "--list-tests" or args[i] == "--list" :
           Environment["ListTests"]=1

       elif args[i] == "--benchmark":
           Environment["benchmark"]=1

       elif args[i] == "--bsc":
           Environment["DoBSC"] = 1
           Environment["scenario"] = "basic-sanity"

       elif args[i] == "--qarsh":
           Environment.rsh.enable_qarsh()

       elif args[i] == "--fencing":
           skipthis=1
           if args[i+1] == "1" or args[i+1] == "yes":
               Environment["DoFencing"] = 1
           elif args[i+1] == "0" or args[i+1] == "no":
               Environment["DoFencing"] = 0
           else:
               usage(args[i+1])

       elif args[i] == "--stonith":
           skipthis=1
           if args[i+1] == "1" or args[i+1] == "yes":
               Environment["DoStonith"]=1
           elif args[i+1] == "0" or args[i+1] == "no":
               Environment["DoStonith"]=0
           else:
               usage(args[i+1])

       elif args[i] == "--stonith-type":
           Environment["stonith-type"] = args[i+1]
           skipthis=1

       elif args[i] == "--stonith-args":
           Environment["stonith-params"] = args[i+1]
           skipthis=1

       elif args[i] == "--standby":
           skipthis=1
           if args[i+1] == "1" or args[i+1] == "yes":
               Environment["DoStandby"] = 1
           elif args[i+1] == "0" or args[i+1] == "no":
               Environment["DoStandby"] = 0
           else:
               usage(args[i+1])

       elif args[i] == "--clobber-cib" or args[i] == "-c":
           Environment["ClobberCIB"] = 1

       elif args[i] == "--cib-filename":
           skipthis=1
           Environment["CIBfilename"] = args[i+1]

       elif args[i] == "--xmit-loss":
           try:
               float(args[i+1])
           except ValueError:
               print ("--xmit-loss parameter should be float")
               usage(args[i+1])
           skipthis=1
           Environment["XmitLoss"] = args[i+1]

       elif args[i] == "--recv-loss":
           try:
               float(args[i+1])
           except ValueError:
               print ("--recv-loss parameter should be float")
               usage(args[i+1])
           skipthis=1
           Environment["RecvLoss"] = args[i+1]

       elif args[i] == "--choose":
           skipthis=1
           Chosen.append(args[i+1])
           Environment["scenario"] = "sequence"

       elif args[i] == "--nodes":
           skipthis=1
           node_list = args[i+1].split(' ')

       elif args[i] == "--syslog-facility" or args[i] == "--facility":
           skipthis=1
           Environment["SyslogFacility"] = args[i+1]

       elif args[i] == "--seed":
           skipthis=1
           Environment.SeedRandom(args[i+1])

       elif args[i] == "--warn-inactive":
           Environment["warn-inactive"] = 1

       elif args[i] == "--schema":
           skipthis=1
           Environment["Schema"] = args[i+1]

       elif args[i] == "--ais":
           Environment["Stack"] = "openais"

       elif args[i] == "--at-boot" or args[i] == "--cluster-starts-at-boot":
           skipthis=1
           if args[i+1] == "1" or args[i+1] == "yes":
               Environment["at-boot"] = 1
           elif args[i+1] == "0" or args[i+1] == "no":
               Environment["at-boot"] = 0
           else:
               usage(args[i+1])

       elif args[i] == "--heartbeat" or args[i] == "--lha":
           Environment["Stack"] = "heartbeat"

       elif args[i] == "--hae":
           Environment["Stack"] = "openais"
           Environment["Schema"] = "hae"

       elif args[i] == "--stack":
           Environment["Stack"] = args[i+1]
           skipthis=1

       elif args[i] == "--once":
           Environment["scenario"] = "all-once"

       elif args[i] == "--valgrind-tests":
           Environment["valgrind-tests"] = 1

       elif args[i] == "--no-loop-tests":
           Environment["loop-tests"] = 0

       elif args[i] == "--no-unsafe-tests":
           Environment["unsafe-tests"] = 0

       elif args[i] == "--experimental-tests":
           Environment["experimental-tests"] = 1

       elif args[i] == "--set":
           skipthis=1
           (name, value) = args[i+1].split('=')
           Environment[name] = value

       else:
           try:
               NumIter=int(args[i])
           except ValueError:
               usage(args[i])

    Environment["loop-minutes"] = int(Environment["loop-minutes"])
    if Environment["DoBSC"]:
        NumIter = 2
        LimitNodes = 1
        Chosen.append("AddResource")
        Environment["ClobberCIB"]  = 1
        Environment["CIBResource"] = 0 
        Environment["logger"].append(FileLog(Environment, Environment["LogFileName"]))

    else:
        if Environment["OutputFile"]:
            Environment["logger"].append(FileLog(Environment, Environment["OutputFile"]))

        if Environment["SyslogFacility"]:
            Environment["logger"].append(SysLog(Environment))

    if Environment["Stack"] == "heartbeat" or Environment["Stack"] == "lha":
        Environment["Stack"]    = "heartbeat"
        Environment['CMclass']  = crm_lha

    elif Environment["Stack"] == "openais" or Environment["Stack"] == "ais"  or Environment["Stack"] == "whitetank":
        Environment["Stack"]    = "openais (whitetank)"
        Environment['CMclass']  = crm_whitetank
        Environment["use_logd"] = 0

    elif Environment["Stack"] == "corosync" or Environment["Stack"] == "cs" or Environment["Stack"] == "flatiron":
        Environment["Stack"]    = "corosync (flatiron)"
        Environment['CMclass']  = crm_flatiron
        Environment["use_logd"] = 0

    else:
        print "Unknown stack: "+Environment["Stack"]
        sys.exit(1)

    if len(node_list) < 1:
        print "No nodes specified!"
        sys.exit(1)

    if LimitNodes > 0:
        if len(node_list) > LimitNodes:
            print("Limiting the number of nodes configured=%d (max=%d)"
                  %(len(node_list), LimitNodes))
            while len(node_list) > LimitNodes:
                node_list.pop(len(node_list)-1)

    Environment["nodes"] = node_list

    # Create the Cluster Manager object
    cm = Environment['CMclass'](Environment)
    if TruncateLog:
        Environment.log("Truncating %s" % LogFile)
        lf = open(LogFile, "w");
        if lf != None:
            lf.truncate(0)
            lf.close()

    Audits = AuditList(cm)
        
    if Environment["ListTests"] == 1 :
        Tests = TestList(cm, Audits)
        Environment.log("Total %d tests"%len(Tests))
        for test in Tests :
            Environment.log(str(test.name));
        sys.exit(0)

    if len(Chosen) == 0:
        Tests = TestList(cm, Audits)

    else:
        for TestCase in Chosen:
           match = None

           for test in TestList(cm, Audits):
               if test.name == TestCase:
                   match = test

           if not match:
               usage("--choose: No applicable/valid tests chosen")        
           else:
               Tests.append(match)
    
    # Scenario selection
    if Environment["scenario"] == "basic-sanity": 
        scenario = RandomTests(cm, [ BasicSanityCheck(Environment) ], Audits, Tests)

    elif Environment["scenario"] == "all-once": 
        NumIter = len(Tests)
        scenario = AllOnce(
            cm, [ InitClusterManager(Environment), PacketLoss(Environment) ], Audits, Tests)
    elif Environment["scenario"] == "sequence": 
        scenario = Sequence(
            cm, [ InitClusterManager(Environment), PacketLoss(Environment) ], Audits, Tests)
    else:
        scenario = RandomTests(
            cm, [ InitClusterManager(Environment), PacketLoss(Environment) ], Audits, Tests)

    Environment.log(">>>>>>>>>>>>>>>> BEGINNING " + repr(NumIter) + " TESTS ")
    Environment.log("Stack:            %s" % Environment["Stack"])
    Environment.log("Schema:           %s" % Environment["Schema"])
    Environment.log("Scenario:         %s" % scenario.__doc__)
    Environment.log("Random Seed:      %s" % Environment["RandSeed"])
    Environment.log("System log files: %s" % Environment["LogFileName"])

    Environment.dump()
    rc = Environment.run(scenario, NumIter)
    sys.exit(rc)
