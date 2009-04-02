#!env python

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
from CTSvars import *
from CTS  import ClusterManager, RemoteExec
from CTStests import BSC_AddResource
from socket import gethostbyname_ex
from CM_ais import crm_ais
from CM_lha import crm_lha

tests = None
cm = None
old_handler = None
DefaultFacility = "daemon"

def sig_handler(signum, frame) :
    if cm != None:
        cm.log("Interrupted by signal %d"%signum)
    if signum == 10 and tests != None :
        tests.summarize()
    if signum == 15 :
        sys.exit(1)
        
class Logger:
    TimeFormat = "%b %d %H:%M:%S\t"

    def __call__(self, lines):
        raise ValueError("Abstract class member (__call__)")
    def write(self, line):
        return self(line.rstrip())
    def writelines(self, lines):
        for s in lines:
            self.write(s)
        return 1
    def flush(self):
        return 1
    def isatty(self):
        return None

class SysLog(Logger):
    # http://docs.python.org/lib/module-syslog.html
    defaultsource="CTS"
    map = {
            "kernel":   syslog.LOG_KERN,
            "user":     syslog.LOG_USER,
            "mail":     syslog.LOG_MAIL,
            "daemon":   syslog.LOG_DAEMON,
            "auth":     syslog.LOG_AUTH,
            "lpr":      syslog.LOG_LPR,
            "news":     syslog.LOG_NEWS,
            "uucp":     syslog.LOG_UUCP,
            "cron":     syslog.LOG_CRON,
            "local0":   syslog.LOG_LOCAL0,
            "local1":   syslog.LOG_LOCAL1,
            "local2":   syslog.LOG_LOCAL2,
            "local3":   syslog.LOG_LOCAL3,
            "local4":   syslog.LOG_LOCAL4,
            "local5":   syslog.LOG_LOCAL5,
            "local6":   syslog.LOG_LOCAL6,
            "local7":   syslog.LOG_LOCAL7,
    }
    def __init__(self, labinfo):

        if labinfo.has_key("syslogsource"):
            self.source=labinfo["syslogsource"]
        else:
            self.source=SysLog.defaultsource

	self.facility=DefaultFacility
        if labinfo.has_key("SyslogFacility") \
		and labinfo["SyslogFacility"]:
	    if SysLog.map.has_key(labinfo["SyslogFacility"]):
		self.facility=labinfo["SyslogFacility"]
	    else:
                raise ValueError("%s: bad syslog facility"%labinfo["SyslogFacility"])

	self.facility=SysLog.map[self.facility]
        syslog.openlog(self.source, 0, self.facility)

    def setfacility(self, facility):
        self.facility = facility
        if SysLog.map.has_key(self.facility):
          self.facility=SysLog.map[self.facility]
        syslog.closelog()
        syslog.openlog(self.source, 0, self.facility)
        

    def __call__(self, lines):
        if isinstance(lines, types.StringType):
            syslog.syslog(lines)
        else:
            for line in lines:
                syslog.syslog(line)

    def name(self):
        return "Syslog"

class StdErrLog(Logger):

    def __init__(self, labinfo):
        pass

    def __call__(self, lines):
        t = time.strftime(Logger.TimeFormat, time.localtime(time.time()))  
        if isinstance(lines, types.StringType):
            sys.__stderr__.writelines([t, lines, "\n"])
        else:
            for line in lines:
                sys.__stderr__.writelines([t, line, "\n"])
        sys.__stderr__.flush()

    def name(self):
        return "StdErrLog"

class FileLog(Logger):
    def __init__(self, labinfo, filename=None):

        if filename == None:
            filename=labinfo["LogFileName"]
        
        self.logfile=filename
        import os
        self.hostname = os.uname()[1]+" "
        self.source = "CTS: "
    def __call__(self, lines):

        fd = open(self.logfile, "a")
        t = time.strftime(Logger.TimeFormat, time.localtime(time.time()))  

        if isinstance(lines, types.StringType):
            fd.writelines([t, self.hostname, self.source, lines, "\n"])
        else:
            for line in lines:
                fd.writelines([t, self.hostname, self.source, line, "\n"])
        fd.close()

    def name(self):
        return "FileLog"

class CtsLab(UserDict):
    '''This class defines the Lab Environment for the Cluster Test System.
    It defines those things which are expected to change from test
    environment to test environment for the same cluster manager.

    It is where you define the set of nodes that are in your test lab
    what kind of reset mechanism you use, etc.

    This class is derived from a UserDict because we hold many
    different parameters of different kinds, and this provides
    provide a uniform and extensible interface useful for any kind of
    communication between the user/administrator/tester and CTS.

    At this point in time, it is the intent of this class to model static
    configuration and/or environmental data about the environment which
    doesn't change as the tests proceed.

    Well-known names (keys) are an important concept in this class.
    The HasMinimalKeys member function knows the minimal set of
    well-known names for the class.

    The following names are standard (well-known) at this time:

        nodes           An array of the nodes in the cluster
        reset           A ResetMechanism object
        logger          An array of objects that log strings...
        CMclass         The type of ClusterManager we are running
                        (This is a class object, not a class instance)
        RandSeed        Random seed.  It is a triple of bytes. (optional)

    The CTS code ignores names it doesn't know about/need.
    The individual tests have access to this information, and it is
    perfectly acceptable to provide hints, tweaks, fine-tuning
    directions or other information to the tests through this mechanism.
    '''

    def __init__(self):
        self.data = {}
        self.rsh = RemoteExec(self)
        self.RandomGen = random.Random()

        #  Get a random seed for the random number generator.
        self["LogFileName"] = "/var/log/messages"
        self["SyslogFacility"] = None
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
        self["CMclass"] = crm_ais
        self["logrestartcmd"] = "rcsyslog restart 2>&1 > /dev/null"
        self["Schema"] = "pacemaker-0.6"
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
        self["all-once"] = 0

        self.SeedRandom()

    def SeedRandom(self, seed=None):
        if not seed:
            seed = int(time.time())

        if self.has_key("RandSeed"):
            self.log("New random seed is: " + str(seed))
        else:
            self.log("Random seed is: " + str(seed))

        self["RandSeed"] = seed
        self.RandomGen.seed(str(seed)) 

    def HasMinimalKeys(self):
        'Return TRUE if our object has the minimal set of keys/values in it'
        result = 1
        for key in self.MinimalKeys:
            if not self.has_key(key):
                result = None
        return result

    def log(self, args):
        "Log using each of the supplied logging methods"
        for logfcn in self._logfunctions:
            logfcn(string.strip(args))

    def debug(self, args):
        "Log using each of the supplied logging methods"
        for logfcn in self._logfunctions:
            if logfcn.name() != "StdErrLog":
                logfcn("debug: %s" % string.strip(args))

    def __setitem__(self, key, value):
        '''Since this function gets called whenever we modify the
        dictionary (object), we can (and do) validate those keys that we
        know how to validate.  For the most part, we know how to validate
        the "MinimalKeys" elements.
        '''

        #
        #        List of nodes in the system
        #
        if key == "nodes":
            self.Nodes = {}
            for node in value:
                # I don't think I need the IP address, etc. but this validates
                # the node name against /etc/hosts and/or DNS, so it's a
                # GoodThing(tm).
                try:
                    self.Nodes[node] = gethostbyname_ex(node)
                except:
                    print node+" not found in DNS... aborting"
                    raise
        #
        #        List of Logging Mechanism(s)
        #
        elif key == "logger":
            if len(value) < 1:
                raise ValueError("Must have at least one logging mechanism")
            for logger in value:
                if not callable(logger):
                    raise ValueError("'logger' elements must be callable")
            self._logfunctions = value
        #
        #        Cluster Manager Class
        #
        elif key == "CMclass":
            if not issubclass(value, ClusterManager):
                raise ValueError("'CMclass' must be a subclass of"
                " ClusterManager")
        #
        #        Initial Random seed...
        #
        #elif key == "RandSeed":
        #    if len(value) != 3:
        #        raise ValueError("'Randseed' must be a 3-element list/tuple")
        #    for elem in value:
        #        if not isinstance(elem, types.IntType):
        #            raise ValueError("'Randseed' list must all be ints")
              
        self.data[key] = value

    def IsValidNode(self, node):
        'Return TRUE if the given node is valid'
        return self.Nodes.has_key(node)

    def __CheckNode(self, node):
        "Raise a ValueError if the given node isn't valid"

        if not self.IsValidNode(node):
            raise ValueError("Invalid node [%s] in CheckNode" % node)

    def RandomNode(self):
        '''Choose a random node from the cluster'''
        return self.RandomGen.choice(self["nodes"])

def usage(arg):
    print "Illegal argument " + arg
    print "usage: " + sys.argv[0] +" [options] number-of-iterations" 
    print "\nCommon options: "  
    print "\t [--at-boot (1|0)],         does the cluster software start at boot time" 
    print "\t [--nodes 'node list'],     list of cluster nodes separated by whitespace" 
    print "\t [--limit-nodes max],       only use the first 'max' cluster nodes supplied with --nodes" 
    print "\t [--stack (heartbeat|ais)], which cluster stack is installed"
    print "\t [--logfile path],          where should the test software look for logs from cluster nodes" 
    print "\t [--syslog-facility name],  which syslog facility should the test software log to" 
    print "\t [--choose testcase-name],  run only the named test" 
    print "\t [--list-tests],            list the valid tests" 
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
    print "\t [--seed random_seed]"
    print "\t [--set option=value]"
    sys.exit(1)

    
#
#   A little test code...
#
if __name__ == '__main__': 

    from CTSaudits import AuditList
    from CTStests import TestList,RandomTests,AllTests
    from CTS import Scenario, InitClusterManager, PingFest, PacketLoss, BasicSanityCheck

    Environment = CtsLab()

    NumIter = 0
    Version = 1
    LimitNodes = 0
    TestCase = None
    TruncateLog = 0
    ListTests = 0
    HaveSeed = 0
    StonithType = "external/ssh"
    StonithParams = None
    StonithParams = "hostlist=dynamic".split('=')
    node_list = ''

    #
    # The values of the rest of the parameters are now properly derived from
    # the configuration files.
    #
    # Stonith is configurable because it's slow, I have a few machines which
    # don't reboot very reliably, and it can mild damage to your machine if
    # you're using a real power switch.
    # 
    # Standby is configurable because the test is very heartbeat specific
    # and I haven't written the code to set it properly yet.  Patches are
    # being accepted...

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

       elif args[i] == "--test-ip-base":
           skipthis=1
           Environment["IPBase"] = args[i+1]

       elif args[i] == "--oprofile":
           skipthis=1
           Environment["oprofile"] = args[i+1].split(' ')

       elif args[i] == "--trunc":
           Environment["TruncateLog"]=1

       elif args[i] == "--list-tests":
           Environment["ListTests"]=1

       elif args[i] == "--bsc":
           Environment["DoBSC"] = 1

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
           StonithType = args[i+1]
           skipthis=1

       elif args[i] == "--stonith-args":
           StonithParams = args[i+1].split('=')
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
           TestCase = args[i+1]

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
           Environment["all-once"] = 1

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
        Environment["ClobberCIB"]  = 1
        Environment["CIBResource"] = 0 
        Environment["logger"].append(FileLog(Environment))
    else:
        Environment["logger"].append(SysLog(Environment))

    if Environment["Stack"] == "heartbeat" or Environment["Stack"] == "lha":
        Environment['CMclass'] = crm_lha

    elif Environment["Stack"] == "openais" or Environment["Stack"] == "ais":
        Environment['CMclass']   = crm_ais
        Environment["use_logd"]  = 0
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

    Audits = AuditList(cm)
    Tests = []
        
    # Your basic start up the world type of test scenario...

    # Scenario selection
    if Environment["DoBSC"]:
        scenario = Scenario([ BasicSanityCheck(Environment) ])
    else:
        scenario = Scenario(
            [ InitClusterManager(Environment), PacketLoss(Environment)])

    #scenario = Scenario(
    #[        InitClusterManager(Environment)
    #,        PingFest(Environment)])

    if Environment["ListTests"] == 1 :
        Tests = TestList(cm, Audits)
        cm.log("Total %d tests"%len(Tests))
        for test in Tests :
            cm.log(str(test.name));
        sys.exit(0)

    if TruncateLog:
        cm.log("Truncating %s" % LogFile)
        lf = open(LogFile, "w");
        if lf != None:
            lf.truncate(0)
            lf.close()

    keys = []
    for key in Environment.keys():
        keys.append(key)

    keys.sort()
    for key in keys:
        cm.debug("Environment["+key+"]:\t"+str(Environment[key]))

    cm.log(">>>>>>>>>>>>>>>> BEGINNING " + repr(NumIter) + " TESTS ")
    cm.log("System log files: " + Environment["LogFileName"])
    cm.log("Schema:           %s" % Environment["Schema"])
    cm.log("Stack:            %s" % Environment["Stack"])
    cm.log("Enable Stonith:   %d" % Environment["DoStonith"])
    cm.log("Enable Fencing:   %d" % Environment["DoFencing"])
    cm.log("Enable Standby:   %d" % Environment["DoStandby"])
    cm.log("Enable Resources: %d" % Environment["CIBResource"])
    cm.ns.WaitForAllNodesToComeUp(Environment["nodes"])
    cm.log("Cluster nodes: ")
    for node in Environment["nodes"]:
        cm.log("    * %s" % (node))

    if Environment["DoBSC"]:
        test = BSC_AddResource(cm)
        Tests.append(test)
    elif TestCase != None:
        for test in TestList(cm, Audits):
            if test.name == TestCase:
                Tests.append(test)
        if Tests == []:
            usage("--choose: No applicable/valid tests chosen")        
    else:
        Tests = TestList(cm, Audits)
    
    if Environment["all-once"] or NumIter == 0:
        Environment.ScenarioTests = AllTests(scenario, cm, Tests, Audits)
    else:
        Environment.ScenarioTests = RandomTests(scenario, cm, Tests, Audits)

    try :
        overall, detailed = Environment.ScenarioTests.run(NumIter)
    except :
        cm.Env.log("Exception by %s" % sys.exc_info()[0])
        for logmethod in Environment["logger"]:
          traceback.print_exc(50, logmethod)
        
    Environment.ScenarioTests.summarize()
    if Environment.ScenarioTests.Stats["failure"] > 0:
        sys.exit(Environment.ScenarioTests.Stats["failure"])

    elif Environment.ScenarioTests.Stats["success"] != NumIter:
        cm.Env.log("No failure count but success != requested iterations")
        sys.exit(1)
        
