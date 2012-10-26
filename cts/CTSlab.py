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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA.

from UserDict import UserDict
import sys, types, string, string, signal, os, socket

pdir=os.path.dirname(sys.path[0])
sys.path.insert(0, pdir) # So that things work from the source directory

try:
    from cts.CTSvars    import *
    from cts.CM_ais     import *
    from cts.CM_lha     import crm_lha
    from cts.CTSaudits  import AuditList
    from cts.CTStests   import TestList
    from cts.CTSscenarios import *

except ImportError:
    sys.stderr.write("abort: couldn't find cts libraries in [%s]\n" %
                     ' '.join(sys.path))
    sys.stderr.write("(check your install and PYTHONPATH)\n")

    # Now do it again to get more details 
    from cts.CTSvars    import *
    from cts.CM_ais     import *
    from cts.CM_lha     import crm_lha
    from cts.CTSaudits  import AuditList
    from cts.CTStests   import TestList
    from cts.CTSscenarios import *
    sys.exit(-1)

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
        self["DoStandby"] = 1
        self["DoFencing"] = 1
        self["XmitLoss"] = "0.0"
        self["RecvLoss"] = "0.0"
        self["ClobberCIB"] = 0
        self["CIBfilename"] = None
        self["CIBResource"] = 0
        self["DoBSC"]    = 0
        self["use_logd"] = 0
        self["oprofile"] = []
        self["warn-inactive"] = 0
        self["ListTests"] = 0
        self["benchmark"] = 0
        self["Schema"] = "pacemaker-1.0"
        self["Stack"] = "openais"
        self["stonith-type"] = "external/ssh"
        self["stonith-params"] = "hostlist=all,livedangerously=yes"
        self["logger"] = ([StdErrLog(self)])
        self["loop-minutes"] = 60
        self["valgrind-prefix"] = None
        self["valgrind-procs"] = "cib crmd attrd pengine stonith-ng"
        self["valgrind-opts"] = """--leak-check=full --show-reachable=yes --trace-children=no --num-callers=25 --gen-suppressions=all --suppressions="""+CTSvars.CTS_home+"""/cts.supp"""
        #self["valgrind-opts"] = """--trace-children=no --num-callers=25 --gen-suppressions=all --suppressions="""+CTSvars.CTS_home+"""/cts.supp"""

        self["experimental-tests"] = 0
        self["valgrind-tests"] = 0
        self["unsafe-tests"] = 1
        self["loop-tests"] = 1
        self["scenario"] = "random"

        master = socket.gethostname()

        # Use the IP where possible to avoid name lookup failures  
        for ip in socket.gethostbyname_ex(master)[2]:
            if ip != "127.0.0.1":
                master = ip
                break;
        self["cts-master"] = master

def usage(arg, status=1):
    print "Illegal argument " + arg
    print "usage: " + sys.argv[0] +" [options] number-of-iterations" 
    print "\nCommon options: "  
    print "\t [--nodes 'node list']        list of cluster nodes separated by whitespace" 
    print "\t [--group | -g 'name']        use the nodes listed in the named DSH group (~/.dsh/groups/$name)" 
    print "\t [--limit-nodes max]          only use the first 'max' cluster nodes supplied with --nodes" 
    print "\t [--stack (v0|v1|cman|corosync|heartbeat|openais)]    which cluster stack is installed"
    print "\t [--list-tests]               list the valid tests" 
    print "\t [--benchmark]                add the timing information" 
    print "\t "
    print "Options that CTS will usually auto-detect correctly: "  
    print "\t [--logfile path]             where should the test software look for logs from cluster nodes" 
    print "\t [--syslog-facility name]     which syslog facility should the test software log to" 
    print "\t [--at-boot (1|0)]            does the cluster software start at boot time" 
    print "\t [--test-ip-base ip]          offset for generated IP address resources"
    print "\t "
    print "Options for release testing: "  
    print "\t [--populate-resources | -r]  generate a sample configuration"
    print "\t [--choose name]              run only the named test" 
    print "\t [--stonith (1 | 0 | yes | no | rhcs | ssh)]" 
    print "\t [--once]                     run all valid tests once" 
    print "\t "
    print "Additional (less common) options: "  
    print "\t [--clobber-cib | -c ]        erase any existing configuration"
    print "\t [--outputfile path]          optional location for the test software to write logs to" 
    print "\t [--trunc]                    truncate logfile before starting" 
    print "\t [--xmit-loss lost-rate(0.0-1.0)]" 
    print "\t [--recv-loss lost-rate(0.0-1.0)]" 
    print "\t [--standby (1 | 0 | yes | no)]" 
    print "\t [--fencing (1 | 0 | yes | no)]" 
    print "\t [--stonith-type type]" 
    print "\t [--stonith-args name=value]" 
    print "\t [--bsc]" 
    print "\t [--no-loop-tests]            dont run looping/time-based tests" 
    print "\t [--no-unsafe-tests]          dont run tests that are unsafe for use with ocfs2/drbd" 
    print "\t [--valgrind-tests]           include tests using valgrind" 
    print "\t [--experimental-tests]       include experimental tests" 
    print "\t [--oprofile 'node list']     list of cluster nodes to run oprofile on]" 
    print "\t [--qarsh]                    use the QARSH backdoor to access nodes instead of SSH"
    print "\t [--seed random_seed]"
    print "\t [--set option=value]"
    print "\t "
    print "\t Example: "
    print "\t    python ./CTSlab.py -g virt1 --stack cs -r --stonith ssh --schema pacemaker-1.0 500"

    sys.exit(status)

    
#
#   A little test code...
#
if __name__ == '__main__': 

    Environment = LabEnvironment()
    rsh = RemoteExec(None, silent=True)

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
           Environment["ClobberCIB"] = 1

       elif args[i] == "-L" or args[i] == "--logfile":
           skipthis=1
           Environment["LogFileName"] = args[i+1]

       elif args[i] == "--outputfile":
           skipthis=1
           Environment["OutputFile"] = args[i+1]

       elif args[i] == "--test-ip-base":
           skipthis=1
           Environment["IPBase"] = args[i+1]
           Environment["CIBResource"] = 1
           Environment["ClobberCIB"] = 1

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
           rsh.enable_qarsh()

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
               Environment["DoFencing"]=1
           elif args[i+1] == "0" or args[i+1] == "no":
               Environment["DoFencing"]=0
           elif args[i+1] == "rhcs":
               Environment["DoStonith"]=1
               Environment["stonith-type"] = "fence_xvm"
               Environment["stonith-params"] = "pcmk_arg_map=domain:uname,delay=0"
           elif args[i+1] == "ssh" or args[i+1] == "lha":
               Environment["DoStonith"]=1
               Environment["stonith-type"] = "external/ssh"
               Environment["stonith-params"] = "hostlist=all,livedangerously=yes"
           elif args[i+1] == "north":
               Environment["DoStonith"]=1
               Environment["stonith-type"] = "fence_apc"
               Environment["stonith-params"] = "ipaddr=north-apc,login=apc,passwd=apc,pcmk_host_map=north-01:2;north-02:3;north-03:4;north-04:5;north-05:6;north-06:7;north-07:9;north-08:10;north-09:11;north-10:12;north-11:13;north-12:14;north-13:15;north-14:18;north-15:17;north-16:19;"
           elif args[i+1] == "south":
               Environment["DoStonith"]=1
               Environment["stonith-type"] = "fence_apc"
               Environment["stonith-params"] = "ipaddr=south-apc,login=apc,passwd=apc,pcmk_host_map=south-01:2;south-02:3;south-03:4;south-04:5;south-05:6;south-06:7;south-07:9;south-08:10;south-09:11;south-10:12;south-11:13;south-12:14;south-13:15;south-14:18;south-15:17;south-16:19;"
           elif args[i+1] == "east":
               Environment["DoStonith"]=1
               Environment["stonith-type"] = "fence_apc"
               Environment["stonith-params"] = "ipaddr=east-apc,login=apc,passwd=apc,pcmk_host_map=east-01:2;east-02:3;east-03:4;east-04:5;east-05:6;east-06:7;east-07:9;east-08:10;east-09:11;east-10:12;east-11:13;east-12:14;east-13:15;east-14:18;east-15:17;east-16:19;"
           elif args[i+1] == "west":
               Environment["DoStonith"]=1
               Environment["stonith-type"] = "fence_apc"
               Environment["stonith-params"] = "ipaddr=west-apc,login=apc,passwd=apc,pcmk_host_map=west-01:2;west-02:3;west-03:4;west-04:5;west-05:6;west-06:7;west-07:9;west-08:10;west-09:11;west-10:12;west-11:13;west-12:14;west-13:15;west-14:18;west-15:17;west-16:19;"
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

       elif args[i] == "-g" or args[i] == "--group" or args[i] == "--dsh-group":
           skipthis=1
           if os.environ['USER'] == 'root':
               Environment["OutputFile"] = "/var/log/cluster-%s.log" % args[i+1]
           else:
               Environment["OutputFile"] = "%s/cluster-%s.log" % (os.environ['HOME'], args[i+1])

           dsh_file = "%s/.dsh/group/%s" % (os.environ['HOME'], args[i+1])
           if os.path.isfile(dsh_file):
               node_list = []
               f = open(dsh_file, 'r')
               for line in f:
                   l = line.strip().rstrip()
                   if not l.startswith('#'):
                       node_list.append(l)
               f.close()

           else:
               print("Unknown DSH group: %s" % args[i+1])

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

       elif args[i] == "--loop-minutes":
           skipthis=1
           try:
               Environment["loop-minutes"]=int(args[i+1])
           except ValueError:
               usage(args[i])

       elif args[i] == "--no-unsafe-tests":
           Environment["unsafe-tests"] = 0

       elif args[i] == "--experimental-tests":
           Environment["experimental-tests"] = 1

       elif args[i] == "--set":
           skipthis=1
           (name, value) = args[i+1].split('=')
           Environment[name] = value

       elif args[i] == "--":
           break

       else:
           try:
               NumIter=int(args[i])
           except ValueError:
               usage(args[i])

    if Environment["DoBSC"]:
        NumIter = 2
        LimitNodes = 1
        Chosen.append("AddResource")
        Environment["ClobberCIB"]  = 1
        Environment["CIBResource"] = 0 
        Environment["logger"].append(FileLog(Environment, Environment["LogFileName"]))

    elif Environment["OutputFile"]:
        Environment["logger"].append(FileLog(Environment, Environment["OutputFile"]))

    elif Environment["SyslogFacility"]:
        Environment["logger"].append(SysLog(Environment))

    if Environment["Stack"] == "heartbeat" or Environment["Stack"] == "lha":
        Environment["Stack"]    = "heartbeat"
        Environment['CMclass']  = crm_lha

    elif Environment["Stack"] == "openais" or Environment["Stack"] == "ais"  or Environment["Stack"] == "whitetank":
        Environment["Stack"]    = "openais (whitetank)"
        Environment['CMclass']  = crm_whitetank
        Environment["use_logd"] = 0

    elif Environment["Stack"] == "corosync" or Environment["Stack"] == "cs" or Environment["Stack"] == "mcp":
        Environment["Stack"]    = "corosync"
        Environment['CMclass']  = crm_mcp
        Environment["use_logd"] = 0

    elif Environment["Stack"] == "cman":
        Environment["Stack"]    = "corosync (cman)"
        Environment['CMclass']  = crm_cman
        Environment["use_logd"] = 0

    elif Environment["Stack"] == "v1":
        Environment["Stack"]    = "corosync (plugin v1)"
        Environment['CMclass']  = crm_cs_v1
        Environment["use_logd"] = 0

    elif Environment["Stack"] == "v0":
        Environment["Stack"]    = "corosync (plugin v0)"
        Environment['CMclass']  = crm_cs_v0
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

    Environment["nodes"] = []
    for n in node_list:
       if len(n.strip()):
           Environment["nodes"].append(n.strip())

    discover = random.Random().choice(Environment["nodes"])
    Environment["have_systemd"] = not rsh(discover, "systemctl list-units")

    # Detect syslog variant
    if not Environment.has_key("syslogd") or not Environment["syslogd"]:
        if Environment["have_systemd"]:
            # Systemd
            Environment["syslogd"] = rsh(discover, "systemctl list-units | grep syslog.*\.service.*active.*running | sed 's:.service.*::'", stdout=1)
        else:
            # SYS-V
            Environment["syslogd"] = rsh(discover, "chkconfig | grep syslog.*on | awk '{print $1}' | head -n 1", stdout=1)

        if not Environment.has_key("syslogd") or not Environment["syslogd"]:
            # default
            Environment["syslogd"] = "rsyslog"

    # Detect if the cluster starts at boot
    if not Environment.has_key("at-boot"):
        atboot = 0

        if Environment["have_systemd"]:
            # Systemd
            atboot = atboot or not rsh(discover, "systemctl is-enabled heartbeat.service")
            atboot = atboot or not rsh(discover, "systemctl is-enabled corosync.service")
            atboot = atboot or not rsh(discover, "systemctl is-enabled pacemaker.service")
        else:
            # SYS-V
            atboot = atboot or not rsh(discover, "chkconfig | grep -e corosync.*on -e heartbeat.*on -e pacemaker.*on")

        Environment["at-boot"] = atboot

    # Try to determinw an offset for IPaddr resources
    if Environment["CIBResource"] and not Environment.has_key("IPBase"):
        network=rsh(discover, "ip addr | grep inet | grep -v -e link -e inet6 -e '/32' -e ' lo' | awk '{print $2}'", stdout=1).strip()
        Environment["IPBase"] = rsh(discover, "nmap -sn -n %s | grep 'scan report' | tail -n 1 | awk '{print $NF}' | sed 's:(::' | sed 's:)::'" % network, stdout=1).strip()
        if not Environment["IPBase"]:
            Environment["IPBase"] = "127.0.0.10"
            Environment.log("Could not determine an offset for IPaddr resources.  Perhaps nmap is not installed on the nodes.")
            Environment.log("Defaulting to '%s', use --test-ip-base to override" % Environment["IPBase"])

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
    Environment.log("Stack:                  %s" % Environment["Stack"])
    Environment.log("Schema:                 %s" % Environment["Schema"])
    Environment.log("Scenario:               %s" % scenario.__doc__)
    Environment.log("CTS Master:             %s" % Environment["cts-master"])
    Environment.log("CTS Logfile:            %s" % Environment["OutputFile"])
    Environment.log("Random Seed:            %s" % Environment["RandSeed"])
    Environment.log("Syslog variant:         %s" % Environment["syslogd"].strip())
    Environment.log("System log files:       %s" % Environment["LogFileName"])
#    Environment.log(" ")
    if Environment.has_key("IPBase"):
        Environment.log("Base IP for resources:  %s" % Environment["IPBase"])
    Environment.log("Cluster starts at boot: %d" % Environment["at-boot"])
        

    Environment.dump()
    rc = Environment.run(scenario, NumIter)
    sys.exit(rc)
