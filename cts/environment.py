'''
Classes related to producing and searching logs
'''

__copyright__='''
Copyright (C) 2014 Andrew Beekhof <andrew@beekhof.net>
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

import types, string, select, sys, time, re, os, struct, signal, socket
import time, syslog, random, traceback, base64, pickle, binascii, fcntl

from cts.remote import *

class Environment:

    def __init__(self, args):
        print repr(self)
        self.data = {}
        self.Nodes = []

        self["DeadTime"] = 300
        self["StartTime"] = 300
        self["StableTime"] = 30
        self["tests"] = []
        self["IPagent"] = "IPaddr2"
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
        self["LogWatcher"] = "any"
        self["SyslogFacility"] = "daemon"
        self["LogFileName"] = "/var/log/messages"
        self["Schema"] = "pacemaker-2.0"
        self["Stack"] = "openais"
        self["stonith-type"] = "external/ssh"
        self["stonith-params"] = "hostlist=all,livedangerously=yes"
        self["loop-minutes"] = 60
        self["valgrind-prefix"] = None
        self["valgrind-procs"] = "cib crmd attrd pengine stonith-ng"
        self["valgrind-opts"] = """--leak-check=full --show-reachable=yes --trace-children=no --num-callers=25 --gen-suppressions=all --suppressions="""+CTSvars.CTS_home+"""/cts.supp"""

        self["experimental-tests"] = 0
        self["container-tests"] = 0
        self["valgrind-tests"] = 0
        self["unsafe-tests"] = 1
        self["loop-tests"] = 1
        self["scenario"] = "random"
        self["stats"] = 0

        self.RandomGen = random.Random()
        self.logger = LogFactory()

        self.SeedRandom()
        self.rsh = RemoteFactory().getInstance()

        self.target = "localhost"

        self.parse_args(args)
        self.discover()
        self.validate()

    def SeedRandom(self, seed=None):
        if not seed:
            seed = int(time.time())

        if self.has_key("RandSeed"):
            self.logger.log("New random seed is: " + str(seed))
        else:
            self.logger.log("Random seed is: " + str(seed))

        self["RandSeed"] = seed
        self.RandomGen.seed(str(seed))

    def dump(self):
        keys = []
        for key in self.data.keys():
            keys.append(key)

        keys.sort()
        for key in keys:
            self.logger.debug("Environment["+key+"]:\t"+str(self[key]))

    def keys(self):
        return self.data.keys()

    def has_key(self, key):
        if key == "nodes":
            return True

        return self.data.has_key(key)

    def __getitem__(self, key):
        if key == "nodes":
            return self.Nodes

        elif key == "Name":
            return self.get_stack_short()

        elif self.data.has_key(key):
            return self.data[key]

        else:
            return None

    def __setitem__(self, key, value):
        if key == "Stack":
            self.set_stack(value)

        elif key == "node-limit":
            self.data[key] = value
            self.filter_nodes()

        elif key == "nodes":
            self.Nodes = []
            for node in value:
                # I don't think I need the IP address, etc. but this validates
                # the node name against /etc/hosts and/or DNS, so it's a
                # GoodThing(tm).
                try:
                    n = node.strip()
                    gethostbyname_ex(n)
                    self.Nodes.append(n) 
                except:
                    self.logger.log(node+" not found in DNS... aborting")
                    raise

            self.filter_nodes()

        else:
            self.data[key] = value

    def RandomNode(self):
        '''Choose a random node from the cluster'''
        return self.RandomGen.choice(self["nodes"])

    def set_stack(self, name):
        # Normalize stack names
        if name == "heartbeat" or name == "lha":
            self.data["Stack"] = "heartbeat"

        elif name == "openais" or name == "ais"  or name == "whitetank":
            self.data["Stack"] = "openais (whitetank)"

        elif name == "corosync" or name == "cs" or name == "mcp":
            self.data["Stack"] = "corosync 2.x"

        elif name == "cman":
            self.data["Stack"] = "corosync (cman)"

        elif name == "v1":
            self.data["Stack"] = "corosync (plugin v1)"

        elif name == "v0":
            self.data["Stack"] = "corosync (plugin v0)"

        else:
            print "Unknown stack: "+name
            sys.exit(1)

    def get_stack_short(self):
        # Create the Cluster Manager object
        if not self.data.has_key("Stack"):
            return "unknown"

        elif self.data["Stack"] == "heartbeat":
            return "crm-lha"

        elif self.data["Stack"] == "corosync 2.x":
            return "crm-mcp"

        elif self.data["Stack"] == "corosync (cman)":
            return "crm-cman"
        
        elif self.data["Stack"] == "corosync (plugin v1)":
            return "crm-plugin-v1"
        
        elif self.data["Stack"] == "corosync (plugin v0)":
            return "crm-plugin-v0"

        else:
            LogFactory().log("Unknown stack: "+self.data["stack"])
            sys.exit(1)

    def detect_syslog(self):
        # Detect syslog variant
        if not self.has_key("syslogd"):
            if self["have_systemd"]:
                # Systemd
                self["syslogd"] = self.rsh(self.target, "systemctl list-units | grep syslog.*\.service.*active.*running | sed 's:.service.*::'", stdout=1).strip()
            else:
                # SYS-V
                self["syslogd"] = self.rsh(self.target, "chkconfig --list | grep syslog.*on | awk '{print $1}' | head -n 1", stdout=1).strip()

            if not self.has_key("syslogd") or not self["syslogd"]:
                # default
                self["syslogd"] = "rsyslog"

    def detect_at_boot(self):
        # Detect if the cluster starts at boot
        if not self.has_key("at-boot"):
            atboot = 0

            if self["have_systemd"]:
            # Systemd
                atboot = atboot or not self.rsh(self.target, "systemctl is-enabled heartbeat.service")
                atboot = atboot or not self.rsh(self.target, "systemctl is-enabled corosync.service")
                atboot = atboot or not self.rsh(self.target, "systemctl is-enabled pacemaker.service")
            else:
                # SYS-V
                atboot = atboot or not self.rsh(self.target, "chkconfig --list | grep -e corosync.*on -e heartbeat.*on -e pacemaker.*on")

            self["at-boot"] = atboot

    def detect_ip_offset(self):
        # Try to determin an offset for IPaddr resources
        if self["CIBResource"] and not self.has_key("IPBase"):
            network=self.rsh(self.target, "ip addr | grep inet | grep -v -e link -e inet6 -e '/32' -e ' lo' | awk '{print $2}'", stdout=1).strip()
            self["IPBase"] = self.rsh(self.target, "nmap -sn -n %s | grep 'scan report' | awk '{print $NF}' | sed 's:(::' | sed 's:)::' | sort -V | tail -n 1" % network, stdout=1).strip()
            if not self["IPBase"]:
                self["IPBase"] = " fe80::1234:56:7890:1000"
                self.logger.log("Could not determine an offset for IPaddr resources.  Perhaps nmap is not installed on the nodes.")
                self.logger.log("Defaulting to '%s', use --test-ip-base to override" % self["IPBase"])

            elif int(self["IPBase"].split('.')[3]) >= 240:
                self.logger.log("Could not determine an offset for IPaddr resources. Upper bound is too high: %s %s"
                                % (self["IPBase"], self["IPBase"].split('.')[3]))
                self["IPBase"] = " fe80::1234:56:7890:1000"
                self.logger.log("Defaulting to '%s', use --test-ip-base to override" % self["IPBase"])

    def filter_nodes(self):
        if self["node-limit"] > 0:
            if len(self["nodes"]) > self["node-limit"]:
                self.logger.log("Limiting the number of nodes configured=%d (max=%d)"
                                %(len(self["nodes"]), self["node-limit"]))
                while len(self["nodes"]) > self["node-limit"]:
                    self["nodes"].pop(len(self["nodes"])-1)

    def validate(self):
        if len(self["nodes"]) < 1:
            print "No nodes specified!"
            sys.exit(1)

    def discover(self):
        self.target = random.Random().choice(self["nodes"])

        master = socket.gethostname()

        # Use the IP where possible to avoid name lookup failures
        for ip in socket.gethostbyname_ex(master)[2]:
            if ip != "127.0.0.1":
                master = ip
                break;
        self["cts-master"] = master

        if self.has_key("have_systemd"):
            self["have_systemd"] = not rsh(discover, "systemctl list-units")

        self.detect_syslog()
        self.detect_at_boot()
        self.detect_ip_offset()

        self.validate()

    def parse_args(self, args):
        skipthis=None

        if not args:
            args=sys.argv[1:]

        for i in range(0, len(args)):
            if skipthis:
                skipthis=None
                continue

            elif args[i] == "-l" or args[i] == "--limit-nodes":
                skipthis=1
                self["node-limit"] = int(args[i+1])

            elif args[i] == "-r" or args[i] == "--populate-resources":
                self["CIBResource"] = 1
                self["ClobberCIB"] = 1

            elif args[i] == "--outputfile":
                skipthis=1
                LogFactory().add_file(args[i+1])

            elif args[i] == "-L" or args[i] == "--logfile":
                skipthis=1
                self["LogWatcher"] = "remote"
                self["LogAuditDisabled"] = 1
                self["LogFileName"] = args[i+1]

            elif args[i] == "--ip" or args[i] == "--test-ip-base":
                skipthis=1
                self["IPBase"] = args[i+1]
                self["CIBResource"] = 1
                self["ClobberCIB"] = 1

            elif args[i] == "--oprofile":
                skipthis=1
                self["oprofile"] = args[i+1].split(' ')

            elif args[i] == "--trunc":
                self["TruncateLog"]=1

            elif args[i] == "--list-tests" or args[i] == "--list" :
                self["ListTests"]=1

            elif args[i] == "--benchmark":
                self["benchmark"]=1

            elif args[i] == "--bsc":
                self["DoBSC"] = 1
                self["scenario"] = "basic-sanity"

            elif args[i] == "--qarsh":
                RemoteFactory().enable_qarsh()

            elif args[i] == "--stonith" or args[i] == "--fencing":
                skipthis=1
                if args[i+1] == "1" or args[i+1] == "yes":
                    self["DoFencing"]=1
                elif args[i+1] == "0" or args[i+1] == "no":
                    self["DoFencing"]=0
                elif args[i+1] == "rhcs" or args[i+1] == "xvm" or args[i+1] == "virt":
                    self["DoStonith"]=1
                    self["stonith-type"] = "fence_xvm"
                    self["stonith-params"] = "pcmk_arg_map=domain:uname,delay=0"
                elif args[i+1] == "scsi":
                    self["DoStonith"]=1
                    self["stonith-type"] = "fence_scsi"
                    self["stonith-params"] = "delay=0"
                elif args[i+1] == "ssh" or args[i+1] == "lha":
                    self["DoStonith"]=1
                    self["stonith-type"] = "external/ssh"
                    self["stonith-params"] = "hostlist=all,livedangerously=yes"
                elif args[i+1] == "north":
                    self["DoStonith"]=1
                    self["stonith-type"] = "fence_apc"
                    self["stonith-params"] = "ipaddr=north-apc,login=apc,passwd=apc,pcmk_host_map=north-01:2;north-02:3;north-03:4;north-04:5;north-05:6;north-06:7;north-07:9;north-08:10;north-09:11;north-10:12;north-11:13;north-12:14;north-13:15;north-14:18;north-15:17;north-16:19;"
                elif args[i+1] == "south":
                    self["DoStonith"]=1
                    self["stonith-type"] = "fence_apc"
                    self["stonith-params"] = "ipaddr=south-apc,login=apc,passwd=apc,pcmk_host_map=south-01:2;south-02:3;south-03:4;south-04:5;south-05:6;south-06:7;south-07:9;south-08:10;south-09:11;south-10:12;south-11:13;south-12:14;south-13:15;south-14:18;south-15:17;south-16:19;"
                elif args[i+1] == "east":
                    self["DoStonith"]=1
                    self["stonith-type"] = "fence_apc"
                    self["stonith-params"] = "ipaddr=east-apc,login=apc,passwd=apc,pcmk_host_map=east-01:2;east-02:3;east-03:4;east-04:5;east-05:6;east-06:7;east-07:9;east-08:10;east-09:11;east-10:12;east-11:13;east-12:14;east-13:15;east-14:18;east-15:17;east-16:19;"
                elif args[i+1] == "west":
                    self["DoStonith"]=1
                    self["stonith-type"] = "fence_apc"
                    self["stonith-params"] = "ipaddr=west-apc,login=apc,passwd=apc,pcmk_host_map=west-01:2;west-02:3;west-03:4;west-04:5;west-05:6;west-06:7;west-07:9;west-08:10;west-09:11;west-10:12;west-11:13;west-12:14;west-13:15;west-14:18;west-15:17;west-16:19;"
                elif args[i+1] == "openstack":
                    self["DoStonith"]=1
                    self["stonith-type"] = "fence_openstack"
                    
                    print "Obtaining OpenStack credentials from the current environment"
                    self["stonith-params"] = "region=%s,tenant=%s,auth=%s,user=%s,password=%s" % (
                        os.environ['OS_REGION_NAME'],
                        os.environ['OS_TENANT_NAME'],
                        os.environ['OS_AUTH_URL'],
                        os.environ['OS_USERNAME'],
                        os.environ['OS_PASSWORD']
                    )
                    
                elif args[i+1] == "rhevm":
                    self["DoStonith"]=1
                    self["stonith-type"] = "fence_rhevm"
                    
                    print "Obtaining RHEV-M credentials from the current environment"
                    self["stonith-params"] = "login=%s,passwd=%s,ipaddr=%s,ipport=%s,ssl=1,shell_timeout=10" % (
                        os.environ['RHEVM_USERNAME'],
                        os.environ['RHEVM_PASSWORD'],
                        os.environ['RHEVM_SERVER'],
                        os.environ['RHEVM_PORT'],
                    )
                    
                else:
                    self.usage(args[i+1])

            elif args[i] == "--stonith-type":
                self["stonith-type"] = args[i+1]
                skipthis=1

            elif args[i] == "--stonith-args":
                self["stonith-params"] = args[i+1]
                skipthis=1

            elif args[i] == "--standby":
                skipthis=1
                if args[i+1] == "1" or args[i+1] == "yes":
                    self["DoStandby"] = 1
                elif args[i+1] == "0" or args[i+1] == "no":
                    self["DoStandby"] = 0
                else:
                    self.usage(args[i+1])

            elif args[i] == "--clobber-cib" or args[i] == "-c":
                self["ClobberCIB"] = 1
                
            elif args[i] == "--cib-filename":
                skipthis=1
                self["CIBfilename"] = args[i+1]

            elif args[i] == "--xmit-loss":
                try:
                    float(args[i+1])
                except ValueError:
                    print ("--xmit-loss parameter should be float")
                    self.usage(args[i+1])
                skipthis=1
                self["XmitLoss"] = args[i+1]

            elif args[i] == "--recv-loss":
                try:
                    float(args[i+1])
                except ValueError:
                    print ("--recv-loss parameter should be float")
                    self.usage(args[i+1])
                skipthis=1
                self["RecvLoss"] = args[i+1]

            elif args[i] == "--choose":
                skipthis=1
                self["tests"].append(args[i+1])
                self["scenario"] = "sequence"

            elif args[i] == "--nodes":
                skipthis=1
                self["nodes"] = args[i+1].split(' ')

            elif args[i] == "-g" or args[i] == "--group" or args[i] == "--dsh-group":
                skipthis=1
                self["OutputFile"] = "%s/cluster-%s.log" % (os.environ['HOME'], args[i+1])
                LogFactory().add_file(self["OutputFile"], "CTS")

                dsh_file = "%s/.dsh/group/%s" % (os.environ['HOME'], args[i+1])

                # Hacks to make my life easier
                if args[i+1] == "r6":
                    self["Stack"] = "cman"
                    self["DoStonith"]=1
                    self["stonith-type"] = "fence_xvm"
                    self["stonith-params"] = "delay=0"
                    self["IPBase"] = " fe80::1234:56:7890:4000"

                elif args[i+1] == "virt1":
                    self["Stack"] = "corosync"
                    self["DoStonith"]=1
                    self["stonith-type"] = "fence_xvm"
                    self["stonith-params"] = "delay=0"
                    self["IPBase"] = " fe80::1234:56:7890:1000"

                elif args[i+1] == "east16" or args[i+1] == "nsew":
                    self["Stack"] = "corosync"
                    self["DoStonith"]=1
                    self["stonith-type"] = "fence_apc"
                    self["stonith-params"] = "ipaddr=east-apc,login=apc,passwd=apc,pcmk_host_map=east-01:2;east-02:3;east-03:4;east-04:5;east-05:6;east-06:7;east-07:9;east-08:10;east-09:11;east-10:12;east-11:13;east-12:14;east-13:15;east-14:18;east-15:17;east-16:19;"
                    self["IPBase"] = " fe80::1234:56:7890:2000"

                    if args[i+1] == "east16":
                        # Requires newer python than available via nsew
                        self["IPagent"] = "Dummy"

                elif args[i+1] == "corosync8":
                    self["Stack"] = "corosync"
                    self["DoStonith"]=1
                    self["stonith-type"] = "fence_rhevm"

                    print "Obtaining RHEV-M credentials from the current environment"
                    self["stonith-params"] = "login=%s,passwd=%s,ipaddr=%s,ipport=%s,ssl=1,shell_timeout=10" % (
                        os.environ['RHEVM_USERNAME'],
                        os.environ['RHEVM_PASSWORD'],
                        os.environ['RHEVM_SERVER'],
                        os.environ['RHEVM_PORT'],
                   )
                    self["IPBase"] = " fe80::1234:56:7890:3000"

                if os.path.isfile(dsh_file):
                    self["nodes"] = []
                    f = open(dsh_file, 'r')
                    for line in f:
                        l = line.strip().rstrip()
                        if not l.startswith('#'):
                            self["nodes"].append(l)
                    f.close()

                else:
                    print("Unknown DSH group: %s" % args[i+1])

            elif args[i] == "--syslog-facility" or args[i] == "--facility":
                skipthis=1
                self["SyslogFacility"] = args[i+1]
                
            elif args[i] == "--seed":
                skipthis=1
                self.SeedRandom(args[i+1])

            elif args[i] == "--warn-inactive":
                self["warn-inactive"] = 1

            elif args[i] == "--schema":
                skipthis=1
                self["Schema"] = args[i+1]

            elif args[i] == "--ais":
                self["Stack"] = "openais"

            elif args[i] == "--at-boot" or args[i] == "--cluster-starts-at-boot":
                skipthis=1
                if args[i+1] == "1" or args[i+1] == "yes":
                    self["at-boot"] = 1
                elif args[i+1] == "0" or args[i+1] == "no":
                    self["at-boot"] = 0
                else:
                    self.usage(args[i+1])

            elif args[i] == "--heartbeat" or args[i] == "--lha":
                self["Stack"] = "heartbeat"

            elif args[i] == "--hae":
                self["Stack"] = "openais"
                self["Schema"] = "hae"

            elif args[i] == "--stack":
                if args[i+1] == "fedora" or args[i+1] == "fedora-17" or args[i+1] == "fedora-18":
                    self["Stack"] = "corosync"
                elif args[i+1] == "rhel-6":
                    self["Stack"] = "cman"
                elif args[i+1] == "rhel-7":
                    self["Stack"] = "corosync"
                else:
                    self["Stack"] = args[i+1]
                skipthis=1

            elif args[i] == "--once":
                self["scenario"] = "all-once"

            elif args[i] == "--boot":
                self["scenario"] = "boot"

            elif args[i] == "--valgrind-tests":
                self["valgrind-tests"] = 1

            elif args[i] == "--no-loop-tests":
                self["loop-tests"] = 0

            elif args[i] == "--loop-minutes":
                skipthis=1
                try:
                    self["loop-minutes"]=int(args[i+1])
                except ValueError:
                    self.usage(args[i])

            elif args[i] == "--no-unsafe-tests":
                self["unsafe-tests"] = 0

            elif args[i] == "--experimental-tests":
                self["experimental-tests"] = 1

            elif args[i] == "--container-tests":
                self["container-tests"] = 1

            elif args[i] == "--set":
                skipthis=1
                (name, value) = args[i+1].split('=')
                self[name] = value
                print "Setting %s = %s" % (name, value)
                
            elif args[i] == "--":
                break

            else:
                try:
                    NumIter=int(args[i])
                    self["iterations"] = NumIter
                except ValueError:
                    self.usage(args[i])

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
        print "\t [--fencing (1 | 0 | yes | no | rhcs | lha | openstack )]"
        print "\t [--stonith-type type]"
        print "\t [--stonith-args name=value]"
        print "\t [--bsc]"
        print "\t [--no-loop-tests]            dont run looping/time-based tests"
        print "\t [--no-unsafe-tests]          dont run tests that are unsafe for use with ocfs2/drbd"
        print "\t [--valgrind-tests]           include tests using valgrind"
        print "\t [--experimental-tests]       include experimental tests"
        print "\t [--container-tests]          include pacemaker_remote tests that run in lxc container resources"
        print "\t [--oprofile 'node list']     list of cluster nodes to run oprofile on]"
        print "\t [--qarsh]                    use the QARSH backdoor to access nodes instead of SSH"
        print "\t [--seed random_seed]"
        print "\t [--set option=value]"
        print "\t "
        print "\t Example: "
        print "\t    python sys.argv[0] -g virt1 --stack cs -r --stonith ssh --schema pacemaker-1.0 500"

        sys.exit(status)

class EnvFactory:
    instance = None
    def __init__(self):
        pass

    def getInstance(self, args=None):
        if not EnvFactory.instance:
            EnvFactory.instance = Environment(args)
        return EnvFactory.instance
