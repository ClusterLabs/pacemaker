""" Test environment classes for Pacemaker's Cluster Test Suite (CTS)
"""

__copyright__ = "Copyright 2014-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import sys, time, os, socket, random

from pacemaker._cts.logging import LogFactory
from pacemaker._cts.remote import RemoteFactory

class Environment(object):

    def __init__(self, args):
        self.data = {}
        self.Nodes = []

        self["DeadTime"] = 300
        self["StartTime"] = 300
        self["StableTime"] = 30
        self["tests"] = []
        self["IPagent"] = "IPaddr2"
        self["DoFencing"] = True
        self["XmitLoss"] = "0.0"
        self["RecvLoss"] = "0.0"
        self["ClobberCIB"] = False
        self["CIBfilename"] = None
        self["CIBResource"] = False
        self["DoBSC"]    = 0
        self["oprofile"] = []
        self["warn-inactive"] = False
        self["ListTests"] = False
        self["benchmark"] = 0
        self["LogWatcher"] = "any"
        self["SyslogFacility"] = "daemon"
        self["LogFileName"] = "/var/log/messages"
        self["Schema"] = "pacemaker-3.0"
        self["Stack"] = "corosync"
        self["stonith-type"] = "external/ssh"
        self["stonith-params"] = "hostlist=all,livedangerously=yes"
        self["notification-agent"] = "/var/lib/pacemaker/notify.sh"
        self["notification-recipient"] = "/var/lib/pacemaker/notify.log"
        self["loop-minutes"] = 60
        self["valgrind-procs"] = "pacemaker-attrd pacemaker-based pacemaker-controld pacemaker-execd pacemaker-fenced pacemaker-schedulerd"
        self["experimental-tests"] = False
        self["container-tests"] = False
        self["valgrind-tests"] = False
        self["unsafe-tests"] = True
        self["loop-tests"] = True
        self["scenario"] = "random"
        self["stats"] = False
        self["continue"] = False

        self.RandomGen = random.Random()
        self.logger = LogFactory()

        self.SeedRandom()
        self.rsh = RemoteFactory().getInstance()

        self.target = "localhost"

        self.parse_args(args)
        if not self["ListTests"]:
            self.validate()
            self.discover()

    def SeedRandom(self, seed=None):
        if not seed:
            seed = int(time.time())

        self["RandSeed"] = seed
        self.RandomGen.seed(str(seed))

    def dump(self):
        keys = []
        for key in list(self.data.keys()):
            keys.append(key)

        keys.sort()
        for key in keys:
            self.logger.debug("Environment["+key+"]:\t"+str(self[key]))

    def keys(self):
        return list(self.data.keys())

    def has_key(self, key):
        if key == "nodes":
            return True

        return key in self.data

    def __getitem__(self, key):
        if str(key) == "0":
            raise ValueError("Bad call to 'foo in X', should reference 'foo in X.keys()' instead")

        if key == "nodes":
            return self.Nodes

        elif key == "Name":
            return self.get_stack_short()

        elif key in self.data:
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
                    socket.gethostbyname_ex(n)
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
        if name == "corosync" or name == "cs" or name == "mcp":
            self.data["Stack"] = "corosync 2+"

        else:
            raise ValueError("Unknown stack: "+name)

    def get_stack_short(self):
        # Create the Cluster Manager object
        if not "Stack" in self.data:
            return "unknown"

        elif self.data["Stack"] == "corosync 2+":
            return "crm-corosync"

        else:
            LogFactory().log("Unknown stack: "+self["stack"])
            raise ValueError("Unknown stack: "+self["stack"])

    def detect_syslog(self):
        # Detect syslog variant
        if not "syslogd" in self.data:
            if self["have_systemd"]:
                # Systemd
                (_, lines) = self.rsh(self.target, "systemctl list-units | grep syslog.*\.service.*active.*running | sed 's:.service.*::'", verbose=1)
                self["syslogd"] = lines[0].strip()
            else:
                # SYS-V
                (_, lines) = self.rsh(self.target, "chkconfig --list | grep syslog.*on | awk '{print $1}' | head -n 1", verbose=1)
                self["syslogd"] = lines[0].strip()

            if not "syslogd" in self.data or not self["syslogd"]:
                # default
                self["syslogd"] = "rsyslog"

    def disable_service(self, node, service):
        if self["have_systemd"]:
            # Systemd
            (rc, _) = self.rsh(node, "systemctl disable %s" % service)
            return rc

        else:
            # SYS-V
            (rc, _) = self.rsh(node, "chkconfig %s off" % service)
            return rc

    def enable_service(self, node, service):
        if self["have_systemd"]:
            # Systemd
            (rc, _) = self.rsh(node, "systemctl enable %s" % service)
            return rc

        else:
            # SYS-V
            (rc, _) = self.rsh(node, "chkconfig %s on" % service)
            return rc

    def service_is_enabled(self, node, service):
        if self["have_systemd"]:
            # Systemd

            # With "systemctl is-enabled", we should check if the service is
            # explicitly "enabled" instead of the return code. For example it returns
            # 0 if the service is "static" or "indirect", but they don't really count
            # as "enabled".
            (rc, _) = self.rsh(node, "systemctl is-enabled %s | grep enabled" % service)
            return rc == 0

        else:
            # SYS-V
            (rc, _) = self.rsh(node, "chkconfig --list | grep -e %s.*on" % service)
            return rc == 0

    def detect_at_boot(self):
        # Detect if the cluster starts at boot
        if not "at-boot" in self.data:
            self["at-boot"] = self.service_is_enabled(self.target, "corosync") \
                              or self.service_is_enabled(self.target, "pacemaker")

    def detect_ip_offset(self):
        # Try to determine an offset for IPaddr resources
        if self["CIBResource"] and not "IPBase" in self.data:
            (_, lines) = self.rsh(self.target, "ip addr | grep inet | grep -v -e link -e inet6 -e '/32' -e ' lo' | awk '{print $2}'", verbose=0)
            network = lines[0].strip()

            (_, lines) = self.rsh(self.target, "nmap -sn -n %s | grep 'scan report' | awk '{print $NF}' | sed 's:(::' | sed 's:)::' | sort -V | tail -n 1" % network, verbose=0)
            self["IPBase"] = lines[0].strip()

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
        if self['node-limit'] is not None and self["node-limit"] > 0:
            if len(self["nodes"]) > self["node-limit"]:
                self.logger.log("Limiting the number of nodes configured=%d (max=%d)"
                                %(len(self["nodes"]), self["node-limit"]))
                while len(self["nodes"]) > self["node-limit"]:
                    self["nodes"].pop(len(self["nodes"])-1)

    def validate(self):
        if len(self["nodes"]) < 1:
            print("No nodes specified!")
            sys.exit(1)

    def discover(self):
        self.target = random.Random().choice(self["nodes"])

        exerciser = socket.gethostname()

        # Use the IP where possible to avoid name lookup failures
        for ip in socket.gethostbyname_ex(exerciser)[2]:
            if ip != "127.0.0.1":
                exerciser = ip
                break;
        self["cts-exerciser"] = exerciser

        if not "have_systemd" in self.data:
            (rc, _) = self.rsh(self.target, "systemctl list-units", verbose=0)
            self["have_systemd"] = rc == 0

        self.detect_syslog()
        self.detect_at_boot()
        self.detect_ip_offset()

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
                self["CIBResource"] = True
                self["ClobberCIB"] = True

            elif args[i] == "--outputfile":
                skipthis=1
                self["OutputFile"] = args[i+1]
                LogFactory().add_file(self["OutputFile"])

            elif args[i] == "-L" or args[i] == "--logfile":
                skipthis=1
                self["LogWatcher"] = "remote"
                self["LogAuditDisabled"] = 1
                self["LogFileName"] = args[i+1]

            elif args[i] == "--ip" or args[i] == "--test-ip-base":
                skipthis=1
                self["IPBase"] = args[i+1]
                self["CIBResource"] = True
                self["ClobberCIB"] = True

            elif args[i] == "--oprofile":
                skipthis=1
                self["oprofile"] = args[i+1].split(' ')

            elif args[i] == "--trunc":
                self["TruncateLog"]=1

            elif args[i] == "--list-tests" or args[i] == "--list" :
                self["ListTests"] = True

            elif args[i] == "--benchmark":
                self["benchmark"]=1

            elif args[i] == "--bsc":
                self["DoBSC"] = 1
                self["scenario"] = "basic-sanity"

            elif args[i] == "--qarsh":
                RemoteFactory().enable_qarsh()

            elif args[i] == "--yes" or args[i] == "-y":
                self["continue"] = True
            elif args[i] == "--stonith" or args[i] == "--fencing":
                skipthis=1
                if args[i+1] == "1" or args[i+1] == "yes":
                    self["DoFencing"] = True
                elif args[i+1] == "0" or args[i+1] == "no":
                    self["DoFencing"] = False
                elif args[i+1] == "rhcs" or args[i+1] == "xvm" or args[i+1] == "virt":
                    self["DoStonith"]=1
                    self["stonith-type"] = "fence_xvm"
                elif args[i+1] == "scsi":
                    self["DoStonith"]=1
                    self["stonith-type"] = "fence_scsi"
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
                    
                    print("Obtaining OpenStack credentials from the current environment")
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
                    
                    print("Obtaining RHEV-M credentials from the current environment")
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

            elif args[i] == "--clobber-cib" or args[i] == "-c":
                self["ClobberCIB"] = True
                
            elif args[i] == "--cib-filename":
                skipthis=1
                self["CIBfilename"] = args[i+1]

            elif args[i] == "--xmit-loss":
                try:
                    float(args[i+1])
                except ValueError:
                    print("--xmit-loss parameter should be float")
                    self.usage(args[i+1])
                skipthis=1
                self["XmitLoss"] = args[i+1]

            elif args[i] == "--recv-loss":
                try:
                    float(args[i+1])
                except ValueError:
                    print("--recv-loss parameter should be float")
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
                if args[i+1] == "virt1":
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

                    print("Obtaining RHEV-M credentials from the current environment")
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
                self["warn-inactive"] = True

            elif args[i] == "--schema":
                skipthis=1
                self["Schema"] = args[i+1]

            elif args[i] == "--at-boot" or args[i] == "--cluster-starts-at-boot":
                skipthis=1
                if args[i+1] == "1" or args[i+1] == "yes":
                    self["at-boot"] = 1
                elif args[i+1] == "0" or args[i+1] == "no":
                    self["at-boot"] = 0
                else:
                    self.usage(args[i+1])

            elif args[i] == "--stack":
                if args[i+1] == "fedora" or args[i+1] == "fedora-17" or args[i+1] == "fedora-18":
                    self["Stack"] = "corosync"
                elif args[i+1] == "rhel-7":
                    self["Stack"] = "corosync"
                else:
                    self["Stack"] = args[i+1]
                skipthis=1

            elif args[i] == "--once":
                self["scenario"] = "all-once"

            elif args[i] == "--boot":
                self["scenario"] = "boot"

            elif args[i] == "--notification-agent":
                self["notification-agent"] = args[i+1]
                skipthis = 1

            elif args[i] == "--notification-recipient":
                self["notification-recipient"] = args[i+1]
                skipthis = 1

            elif args[i] == "--valgrind-tests":
                self["valgrind-tests"] = True

            elif args[i] == "--valgrind-procs":
                self["valgrind-procs"] = args[i+1]
                skipthis = 1

            elif args[i] == "--no-loop-tests":
                self["loop-tests"] = False

            elif args[i] == "--loop-minutes":
                skipthis=1
                try:
                    self["loop-minutes"]=int(args[i+1])
                except ValueError:
                    self.usage(args[i])

            elif args[i] == "--no-unsafe-tests":
                self["unsafe-tests"] = False

            elif args[i] == "--experimental-tests":
                self["experimental-tests"] = True

            elif args[i] == "--container-tests":
                self["container-tests"] = True

            elif args[i] == "--set":
                skipthis=1
                (name, value) = args[i+1].split('=')
                self[name] = value
                print("Setting %s = %s" % (name, value))
                
            elif args[i] == "--help":
                self.usage(args[i], 0)

            elif args[i] == "--":
                break

            else:
                try:
                    NumIter=int(args[i])
                    self["iterations"] = NumIter
                except ValueError:
                    self.usage(args[i])

    def usage(self, arg, status=1):
        if status:
            print("Illegal argument %s" % arg)

        print("""usage: %s [options] number-of-iterations

Common options:
\t [--nodes 'node list']        list of cluster nodes separated by whitespace
\t [--group | -g 'name']        use the nodes listed in the named DSH group (~/.dsh/groups/$name)
\t [--limit-nodes max]          only use the first 'max' cluster nodes supplied with --nodes
\t [--stack corosync]           which cluster stack is installed
\t [--list-tests]               list the valid tests
\t [--benchmark]                add the timing information

Options that CTS will usually auto-detect correctly:
\t [--logfile path]             where should the test software look for logs from cluster nodes
\t [--syslog-facility name]     which syslog facility should the test software log to
\t [--at-boot (1|0)]            does the cluster software start at boot time
\t [--test-ip-base ip]          offset for generated IP address resources

Options for release testing:
\t [--populate-resources | -r]  generate a sample configuration
\t [--choose name]              run only the named test
\t [--stonith (1 | 0 | yes | no | rhcs | ssh)]
\t [--once]                     run all valid tests once

Additional (less common) options:
\t [--clobber-cib | -c ]        erase any existing configuration
\t [--outputfile path]          optional location for the test software to write logs to
\t [--trunc]                    truncate logfile before starting
\t [--xmit-loss lost-rate(0.0-1.0)]
\t [--recv-loss lost-rate(0.0-1.0)]
\t [--fencing (1 | 0 | yes | no | rhcs | lha | openstack )]
\t [--stonith-type type]
\t [--stonith-args name=value]
\t [--bsc]
\t [--notification-agent path]  script to configure for Pacemaker alerts
\t [--notification-recipient r] recipient to pass to alert script
\t [--no-loop-tests]            don't run looping/time-based tests
\t [--no-unsafe-tests]          don't run tests that are unsafe for use with ocfs2/drbd
\t [--valgrind-tests]           include tests using valgrind
\t [--experimental-tests]       include experimental tests
\t [--container-tests]          include pacemaker_remote tests that run in lxc container resources
\t [--oprofile 'node list']     list of cluster nodes to run oprofile on]
\t [--qarsh]                    use the QARSH backdoor to access nodes instead of SSH
\t [--seed random_seed]
\t [--set option=value]
\t [--yes | -y]                 continue to run cts when there is an interaction whether to continue running pacemaker-cts

Example:
\t python %s -g virt1 -r --stonith ssh --schema pacemaker-2.0 500""" % (sys.argv[0], sys.argv[0]))

        sys.exit(status)

class EnvFactory(object):
    instance = None
    def __init__(self):
        pass

    def getInstance(self, args=None):
        if not EnvFactory.instance:
            EnvFactory.instance = Environment(args)
        return EnvFactory.instance
