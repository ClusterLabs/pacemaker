'''CTS: Cluster Testing System: CIB generator
'''
__copyright__ = '''
Author: Andrew Beekhof <abeekhof@suse.de>
Copyright (C) 2008 Andrew Beekhof
'''

import os, string, warnings

from cts.CTSvars import *


class CibBase:
    def __init__(self, Factory, tag, _id, **kwargs):
        self.tag = tag
        self.name = _id
        self.kwargs = kwargs
        self.children = []
        self.Factory = Factory

    def __repr__(self):
        return "%s-%s" % (self.tag, self.name)

    def add_child(self, child):
        self.children.append(child)

    def __setitem__(self, key, value):
        if value:
            self.kwargs[key] = value
        else:
            self.kwargs.pop(key, None)

from cib_xml import *


class ConfigBase:
    cts_cib = None
    version = "unknown"
    feature_set = "unknown"
    Factory = None

    def __init__(self, CM, factory, tmpfile=None):
        self.CM = CM
        self.Factory = factory

        if not tmpfile:
            warnings.filterwarnings("ignore")
            tmpfile = os.tmpnam()
            warnings.resetwarnings()

        self.Factory.tmpfile = tmpfile

    def version(self):
        return self.version

    def NextIP(self):
        ip = self.CM.Env["IPBase"]
        if ":" in ip:
            (prefix, sep, suffix) = ip.rpartition(":")
            suffix = str(hex(int(suffix, 16)+1)).lstrip("0x")
        else:
            (prefix, sep, suffix) = ip.rpartition(".")
            suffix = str(int(suffix)+1)

        ip = prefix + sep + suffix
        self.CM.Env["IPBase"] = ip
        return ip.strip()


class CIB11(ConfigBase):
    feature_set = "3.0"
    version = "pacemaker-1.1"
    counter = 1

    def _show(self, command=""):
        output = ""
        (rc, result) = self.Factory.rsh(self.Factory.target, "HOME=/root CIB_file="+self.Factory.tmpfile+" cibadmin -Ql "+command, None, )
        for line in result:
            output += line
            self.Factory.debug("Generated Config: "+line)
        return output

    def NewIP(self, name=None, standard="ocf"):
        if self.CM.Env["IPagent"] == "IPaddr2":
            ip = self.NextIP()
            if not name:
                if ":" in ip:
                    (prefix, sep, suffix) = ip.rpartition(":")
                    name = "r"+suffix
                else:
                    name = "r"+ip

            r = Resource(self.Factory, name, self.CM.Env["IPagent"], standard)
            r["ip"] = ip
        
            if ":" in ip:
                r["cidr_netmask"] = "64"
                r["nic"] = "eth0"
            else:
                r["cidr_netmask"] = "32"

        else:
            if not name:
                name = "r%s%d" % (self.CM.Env["IPagent"], self.counter)
                self.counter = self.counter + 1
            r = Resource(self.Factory, name, self.CM.Env["IPagent"], standard)

        r.add_op("monitor", "5s")
        return r

    def get_node_id(self, node_name):
        """ Check the cluster configuration for a node ID. """

        # We can't account for every possible configuration,
        # so we only return a node ID if:
        # * The node is specified in /etc/corosync/corosync.conf
        #   with "ring0_addr:" equal to node_name and "nodeid:"
        #   explicitly specified.
        # * Or, the node is specified in /etc/cluster/cluster.conf
        #   with name="node_name" nodeid="X"
        # In all other cases, we return 0.
        node_id = 0

        # awkward command: use } as record separator
        # so each corosync.conf "object" is one record;
        # match the "node {" record that has "ring0_addr: node_name";
        # then print the substring of that record after "nodeid:"
        (rc, output) = self.Factory.rsh(self.Factory.target,
            r"""awk -v RS="}" """
            r"""'/^(\s*nodelist\s*{)?\s*node\s*{.*ring0_addr:\s*%s(\s+|$)/"""
            r"""{gsub(/.*nodeid:\s*/,"");gsub(/\s+.*$/,"");print}'"""
            r""" /etc/corosync/corosync.conf""" % node_name, None)
        if rc == 0 and len(output) == 1:
            try:
                node_id = int(output[0])
            except ValueError:
                node_id = 0

        # another awkward command: use < or > as record separator
        # so each cluster.conf XML tag is one record;
        # match the clusternode record that has name="node_name";
        # then print the substring of that record for nodeid="X"
        if node_id == 0:
            (rc, output) = self.Factory.rsh(self.Factory.target,
                r"""awk -v RS="[<>]" """
                r"""'/^clusternode\s+.*name="%s".*/"""
                r"""{gsub(/.*nodeid="/,"");gsub(/".*/,"");print}'"""
                r""" /etc/cluster/cluster.conf""" % node_name, None)
            if rc == 0 and len(output) == 1:
                try:
                    node_id = int(output[0])
                except ValueError:
                    node_id = 0

        return node_id

    def install(self, target):
        old = self.Factory.tmpfile

        # Force a rebuild
        self.cts_cib = None

        self.Factory.tmpfile = CTSvars.CRM_CONFIG_DIR+"/cib.xml"
        self.contents(target)
        self.Factory.rsh(self.Factory.target, "chown "+CTSvars.CRM_DAEMON_USER+" "+self.Factory.tmpfile)

        self.Factory.tmpfile = old

    def contents(self, target=None):
        # fencing resource
        if self.cts_cib:
            return self.cts_cib

        if target:
            self.Factory.target = target

        self.Factory.rsh(self.Factory.target, "HOME=/root cibadmin --empty %s > %s" % (self.version, self.Factory.tmpfile))
        #cib_base = self.cib_template % (self.feature_set, self.version, ''' remote-tls-port='9898' remote-clear-port='9999' ''')

        self.num_nodes = len(self.CM.Env["nodes"])

        no_quorum = "stop"
        if self.num_nodes < 3:
            no_quorum = "ignore"
            self.Factory.log("Cluster only has %d nodes, configuring: no-quorum-policy=ignore" % self.num_nodes)

        # We don't need a nodes section unless we add attributes
        stn = None

        # Fencing resource
        # Define first so that the shell doesn't reject every update
        if self.CM.Env["DoFencing"]:

            # Define the "real" fencing device
            st = Resource(self.Factory, "Fencing", ""+self.CM.Env["stonith-type"], "stonith")

            # Set a threshold for unreliable stonith devices such as the vmware one
            st.add_meta("migration-threshold", "5")
            st.add_op("monitor", "120s", timeout="120s")
            st.add_op("stop", "0", timeout="60s")
            st.add_op("start", "0", timeout="60s")

            # For remote node tests, a cluster node is stopped and brought back up
            # as a remote node with the name "remote_OLDNAME". To allow fencing
            # devices to fence these nodes, create a list of all possible node names.
            all_node_names = [ prefix+n for n in self.CM.Env["nodes"] for prefix in ('', 'remote_') ]

            # Add all parameters specified by user
            entries = string.split(self.CM.Env["stonith-params"], ',')
            for entry in entries:
                (name, value) = string.split(entry, '=')

                # Allow user to specify "all" as the node list, and expand it here
                if name in [ "hostlist", "pcmk_host_list" ] and value == "all":
                    value = string.join(all_node_names, " ")

                st[name] = value

            st.commit()

            # Test advanced fencing logic
            if True:
                stf_nodes = []
                stt_nodes = []
                attr_nodes = {}

                # Create the levels
                stl = FencingTopology(self.Factory)
                for node in self.CM.Env["nodes"]:
                    # Remote node tests will rename the node
                    remote_node = "remote_" + node

                    # Randomly assign node to a fencing method
                    ftype = self.CM.Env.RandomGen.choice(["levels-and", "levels-or ", "broadcast "])

                    # For levels-and, randomly choose targeting by node name or attribute
                    by = ""
                    if ftype == "levels-and":
                        if self.CM.Env.RandomGen.choice([True, False]):
                            node_id = self.get_node_id(node)
                            if node_id == 0:
                                # We couldn't find a node ID, so revert to targeting by name
                                by = " (by name)"
                            else:
                                attr_nodes[node] = node_id
                                by = " (by attribute)"
                        else:
                            by = " (by name)"

                    self.CM.log(" - Using %s fencing for node: %s%s" % (ftype, node, by))

                    if ftype == "levels-and":
                        # If targeting by name, add a topology level for this node
                        if node not in attr_nodes:
                            stl.level(1, node, "FencingPass,Fencing")

                        # Always target remote nodes by name, otherwise we would need to add
                        # an attribute to the remote node only during remote tests (we don't
                        # want nonexistent remote nodes showing up in the non-remote tests).
                        # That complexity is not worth the effort.
                        stl.level(1, remote_node, "FencingPass,Fencing")

                        # Add the node (and its remote equivalent) to the list of levels-and nodes.
                        stt_nodes.extend([node, remote_node])

                    elif ftype == "levels-or ":
                        for n in [ node, remote_node ]:
                            stl.level(1, n, "FencingFail")
                            stl.level(2, n, "Fencing")
                        stf_nodes.extend([node, remote_node])

                # If any levels-and nodes were targeted by attribute,
                # create the attributes and a level for the attribute.
                if attr_nodes:
                    stn = Nodes(self.Factory)
                    for (node_name, node_id) in attr_nodes.items():
                        stn.add_node(node_name, node_id, { "cts-fencing" : "levels-and" })
                    stl.level(1, "cts-fencing=levels-and", "FencingPass,Fencing")

                # Create a Dummy agent that always passes for levels-and
                if len(stt_nodes):
                    self.CM.install_helper("fence_dummy", destdir="/usr/sbin", sourcedir=CTSvars.Fencing_home)
                    stt = Resource(self.Factory, "FencingPass", "fence_dummy", "stonith")
                    stt["pcmk_host_list"] = string.join(stt_nodes, " ")
                    # Wait this many seconds before doing anything, handy for letting disks get flushed too
                    stt["random_sleep_range"] = "30"
                    stt["mode"] = "pass"
                    stt.commit()

                # Create a Dummy agent that always fails for levels-or
                if len(stf_nodes):
                    self.CM.install_helper("fence_dummy", destdir="/usr/sbin", sourcedir=CTSvars.Fencing_home)
                    stf = Resource(self.Factory, "FencingFail", "fence_dummy", "stonith")
                    stf["pcmk_host_list"] = string.join(stf_nodes, " ")
                    # Wait this many seconds before doing anything, handy for letting disks get flushed too
                    stf["random_sleep_range"] = "30"
                    stf["mode"] = "fail"
                    stf.commit()

                # Now commit the levels themselves
                stl.commit()

        o = Option(self.Factory, "stonith-enabled", self.CM.Env["DoFencing"])
        o["start-failure-is-fatal"] = "false"
        o["pe-input-series-max"] = "5000"
        o["default-action-timeout"] = "90s"
        o["shutdown-escalation"] = "5min"
        o["batch-limit"] = "10"
        o["dc-deadtime"] = "5s"
        o["no-quorum-policy"] = no_quorum
        o["expected-quorum-votes"] = self.num_nodes
        o["notification-agent"] = "/var/lib/pacemaker/notify.sh"
        o["notification-recipient"] = "/var/lib/pacemaker/notify.log"

        if self.CM.Env["DoBSC"] == 1:
            o["ident-string"] = "Linux-HA TEST configuration file - REMOVEME!!"

        o.commit()

        # Commit the nodes section if we defined one
        if stn is not None:
            stn.commit()

        # Add resources?
        if self.CM.Env["CIBResource"] == 1:
            self.add_resources()

        if self.CM.cluster_monitor == 1:
            mon = Resource(self.Factory, "cluster_mon", "ocf", "ClusterMon", "pacemaker")
            mon.add_op("start", "0", requires="nothing")
            mon.add_op("monitor", "5s", requires="nothing")
            mon["update"] = "10"
            mon["extra_options"] = "-r -n"
            mon["user"] = "abeekhof"
            mon["htmlfile"] = "/suse/abeekhof/Export/cluster.html"
            mon.commit()

            #self._create('''location prefer-dc cluster_mon rule -INFINITY: \#is_dc eq false''')

        # generate cib
        self.cts_cib = self._show()

        if self.Factory.tmpfile != CTSvars.CRM_CONFIG_DIR+"/cib.xml":
            self.Factory.rsh(self.Factory.target, "rm -f "+self.Factory.tmpfile)

        return self.cts_cib

    def add_resources(self):
        # Per-node resources
        for node in self.CM.Env["nodes"]:
            name = "rsc_"+node
            r = self.NewIP(name)
            r.prefer(node, "100")
            r.commit()

        # Migrator
        # Make this slightly sticky (since we have no other location constraints) to avoid relocation during Reattach
        m = Resource(self.Factory, "migrator","Dummy",  "ocf", "pacemaker")
        m["passwd"] = "whatever"
        m.add_meta("resource-stickiness","1")
        m.add_meta("allow-migrate", "1")
        m.add_op("monitor", "P10S")
        m.commit()

        # Ping the test master
        p = Resource(self.Factory, "ping-1","ping",  "ocf", "pacemaker")
        p.add_op("monitor", "60s")
        p["host_list"] = self.CM.Env["cts-master"]
        p["name"] = "connected"
        p["debug"] = "true"

        c = Clone(self.Factory, "Connectivity", p)
        c["globally-unique"] = "false"
        c.commit()

        #master slave resource
        s = Resource(self.Factory, "stateful-1", "Stateful", "ocf", "pacemaker")
        s.add_op("monitor", "15s", timeout="60s")
        s.add_op("monitor", "16s", timeout="60s", role="Master")
        ms = Master(self.Factory, "master-1", s)
        ms["clone-max"] = self.num_nodes
        ms["master-max"] = 1
        ms["clone-node-max"] = 1
        ms["master-node-max"] = 1

        # Require conectivity to run the master
        r = Rule(self.Factory, "connected", "-INFINITY", op="or")
        r.add_child(Expression(self.Factory, "m1-connected-1", "connected", "lt", "1"))
        r.add_child(Expression(self.Factory, "m1-connected-2", "connected", "not_defined", None))
        ms.prefer("connected", rule=r)

        ms.commit()

        # Group Resource
        g = Group(self.Factory, "group-1")
        g.add_child(self.NewIP())

        if self.CM.Env["have_systemd"]:
            # It would be better to put the python in a separate file, so we
            # could loop "while True" rather than sleep for 24 hours. We can't
            # put a loop in a single-line python command; only simple commands
            # may be separated by semicolon in python.
            dummy_service_file = """
[Unit]
Description=Dummy resource that takes a while to start

[Service]
Type=notify
ExecStart=/usr/bin/python -c 'import time, systemd.daemon; time.sleep(10); systemd.daemon.notify("READY=1"); time.sleep(86400)'
ExecStop=/bin/sleep 10
ExecStop=/bin/kill -s KILL \$MAINPID
"""

            os.system("cat <<-END >/tmp/DummySD.service\n%s\nEND" % (dummy_service_file))

            self.CM.install_helper("DummySD.service", destdir="/usr/lib/systemd/system/", sourcedir="/tmp")
            sysd = Resource(self.Factory, "petulant", "DummySD",  "service")
            sysd.add_op("monitor", "P10S")
            g.add_child(sysd)
        else:
            g.add_child(self.NewIP())

        g.add_child(self.NewIP())

        # Group with the master
        g.after("master-1", first="promote", then="start")
        g.colocate("master-1", "INFINITY", withrole="Master")

        g.commit()

        # LSB resource
        lsb_agent = self.CM.install_helper("LSBDummy")

        lsb = Resource(self.Factory, "lsb-dummy",lsb_agent,  "lsb")
        lsb.add_op("monitor", "5s")

        # LSB with group
        lsb.after("group-1")
        lsb.colocate("group-1")

        lsb.commit()


class CIB12(CIB11):
    feature_set = "3.0"
    version = "pacemaker-1.2"

class CIB20(CIB11):
    feature_set = "3.0"
    version = "pacemaker-2.0"

#class HASI(CIB10):
#    def add_resources(self):
#        # DLM resource
#        self._create('''primitive dlm ocf:pacemaker:controld op monitor interval=120s''')
#        self._create('''clone dlm-clone dlm meta globally-unique=false interleave=true''')

        # O2CB resource
#        self._create('''primitive o2cb ocf:ocfs2:o2cb op monitor interval=120s''')
#        self._create('''clone o2cb-clone o2cb meta globally-unique=false interleave=true''')
#        self._create('''colocation o2cb-with-dlm INFINITY: o2cb-clone dlm-clone''')
#        self._create('''order start-o2cb-after-dlm mandatory: dlm-clone o2cb-clone''')


class ConfigFactory:
    def __init__(self, CM):
        self.CM = CM
        self.rsh = self.CM.rsh
        self.register("pacemaker11", CIB11, CM, self)
        self.register("pacemaker12", CIB12, CM, self)
        self.register("pacemaker20", CIB20, CM, self)
#        self.register("hae", HASI, CM, self)
        self.target = self.CM.Env["nodes"][0]
        self.tmpfile = None

    def log(self, args):
        self.CM.log("cib: %s" % args)

    def debug(self, args):
        self.CM.debug("cib: %s" % args)

    def register(self, methodName, constructor, *args, **kargs):
        """register a constructor"""
        _args = [constructor]
        _args.extend(args)
        setattr(self, methodName, ConfigFactoryItem(*_args, **kargs))

    def unregister(self, methodName):
        """unregister a constructor"""
        delattr(self, methodName)

    def createConfig(self, name="pacemaker-1.0"):
        if name == "pacemaker-1.0":
            name = "pacemaker10";
        elif name == "pacemaker-1.1":
            name = "pacemaker11";
        elif name == "pacemaker-1.2":
            name = "pacemaker12";
        elif name == "pacemaker-2.0":
            name = "pacemaker20";
        elif name == "hasi":
            name = "hae";

        if hasattr(self, name):
            return getattr(self, name)()
        else:
            self.CM.log("Configuration variant '%s' is unknown.  Defaulting to latest config" % name)

        return self.pacemaker12()


class ConfigFactoryItem:
    def __init__(self, function, *args, **kargs):
        self._function = function
        self._args = args
        self._kargs = kargs

    def __call__(self, *args, **kargs):
        """call function"""
        _args = list(self._args)
        _args.extend(args)
        _kargs = self._kargs.copy()
        _kargs.update(kargs)
        return self._function(*_args,**_kargs)

if __name__ == '__main__':
    """ Unit test (pass cluster node names as command line arguments) """

    import CTS
    import CM_ais
    import sys

    if len(sys.argv) < 2:
        print("Usage: %s <node> ..." % sys.argv[0])
        sys.exit(1)

    args = [
        "--nodes", " ".join(sys.argv[1:]),
        "--clobber-cib",
        "--populate-resources",
        "--stack", "corosync",
        "--test-ip-base", "fe80::1234:56:7890:1000",
        "--stonith", "rhcs",
        "--stonith-args", "pcmk_arg_map=domain:uname"
    ]
    env = CTS.CtsLab(args)
    cm = CM_ais.crm_mcp(env)
    CibFactory = ConfigFactory(cm)
    cib = CibFactory.createConfig("pacemaker-1.1")
    print(cib.contents())
