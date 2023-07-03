""" CIB generator for Pacemaker's Cluster Test Suite (CTS)
"""

__all__ = ["ConfigFactory"]
__copyright__ = "Copyright 2008-2023 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import warnings
import tempfile

from pacemaker.buildoptions import BuildOptions
from pacemaker._cts.cibxml import Alerts, Clone, Expression, FencingTopology, Group, Nodes, OpDefaults, Option, Resource, Rule
from pacemaker._cts.network import next_ip


class CIB:
    def __init__(self, cm, version, factory, tmpfile=None):
        # pylint: disable=invalid-name
        self._cib = None
        self._cm = cm
        self._counter = 1
        self._factory = factory
        self._num_nodes = 0

        self.version = version

        if not tmpfile:
            warnings.filterwarnings("ignore")

            # pylint: disable=consider-using-with
            f = tempfile.NamedTemporaryFile(delete=True)
            f.close()
            tmpfile = f.name

            warnings.resetwarnings()

        self._factory.tmpfile = tmpfile

    def _show(self, command=""):
        output = ""
        (_, result) = self._factory.rsh(self._factory.target, "HOME=/root CIB_file=%s cibadmin -Ql %s" % (self._factory.tmpfile, command), verbose=1)

        for line in result:
            output += line
            self._factory.debug("Generated Config: %s" % line)

        return output

    def new_ip(self, name=None, standard="ocf"):
        if self._cm.Env["IPagent"] == "IPaddr2":
            ip = next_ip(self._cm.Env["IPBase"])
            if not name:
                if ":" in ip:
                    (_, _, suffix) = ip.rpartition(":")
                    name = "r%s" % suffix
                else:
                    name = "r%s" % ip

            r = Resource(self._factory, name, self._cm.Env["IPagent"], standard)
            r["ip"] = ip

            if ":" in ip:
                r["cidr_netmask"] = "64"
                r["nic"] = "eth0"
            else:
                r["cidr_netmask"] = "32"

        else:
            if not name:
                name = "r%s%d" % (self._cm.Env["IPagent"], self._counter)
                self._counter += 1

            r = Resource(self._factory, name, self._cm.Env["IPagent"], standard)

        r.add_op("monitor", "5s")
        return r

    def get_node_id(self, node_name):
        """ Check the cluster configuration for a node ID. """

        # We can't account for every possible configuration,
        # so we only return a node ID if:
        # * The node is specified in /etc/corosync/corosync.conf
        #   with "ring0_addr:" equal to node_name and "nodeid:"
        #   explicitly specified.
        # In all other cases, we return 0.
        node_id = 0

        # awkward command: use } as record separator
        # so each corosync.conf "object" is one record;
        # match the "node {" record that has "ring0_addr: node_name";
        # then print the substring of that record after "nodeid:"
        (rc, output) = self._factory.rsh(self._factory.target,
            r"""awk -v RS="}" """
            r"""'/^(\s*nodelist\s*{)?\s*node\s*{.*(ring0_addr|name):\s*%s(\s+|$)/"""
            r"""{gsub(/.*nodeid:\s*/,"");gsub(/\s+.*$/,"");print}' %s"""
            % (node_name, BuildOptions.COROSYNC_CONFIG_FILE), verbose=1)

        if rc == 0 and len(output) == 1:
            try:
                node_id = int(output[0])
            except ValueError:
                node_id = 0

        return node_id

    def install(self, target):
        old = self._factory.tmpfile

        # Force a rebuild
        self._cib = None

        self._factory.tmpfile = "%s/cib.xml" % BuildOptions.CIB_DIR
        self.contents(target)
        self._factory.rsh(self._factory.target, "chown %s %s" % (BuildOptions.DAEMON_USER, self._factory.tmpfile))

        self._factory.tmpfile = old

    def contents(self, target=None):
        # fencing resource
        if self._cib:
            return self._cib

        if target:
            self._factory.target = target

        self._factory.rsh(self._factory.target, "HOME=/root cibadmin --empty %s > %s" % (self.version, self._factory.tmpfile))
        self._num_nodes = len(self._cm.Env["nodes"])

        no_quorum = "stop"
        if self._num_nodes < 3:
            no_quorum = "ignore"
            self._factory.log("Cluster only has %d nodes, configuring: no-quorum-policy=ignore" % self._num_nodes)

        # We don't need a nodes section unless we add attributes
        stn = None

        # Fencing resource
        # Define first so that the shell doesn't reject every update
        if self._cm.Env["DoFencing"]:

            # Define the "real" fencing device
            st = Resource(self._factory, "Fencing", self._cm.Env["stonith-type"], "stonith")

            # Set a threshold for unreliable stonith devices such as the vmware one
            st.add_meta("migration-threshold", "5")
            st.add_op("monitor", "120s", timeout="120s")
            st.add_op("stop", "0", timeout="60s")
            st.add_op("start", "0", timeout="60s")

            # For remote node tests, a cluster node is stopped and brought back up
            # as a remote node with the name "remote-OLDNAME". To allow fencing
            # devices to fence these nodes, create a list of all possible node names.
            all_node_names = [ prefix+n for n in self._cm.Env["nodes"] for prefix in ('', 'remote-') ]

            # Add all parameters specified by user
            entries = self._cm.Env["stonith-params"].split(',')
            for entry in entries:
                try:
                    (name, value) = entry.split('=', 1)
                except ValueError:
                    print("Warning: skipping invalid fencing parameter: %s" % entry)
                    continue

                # Allow user to specify "all" as the node list, and expand it here
                if name in [ "hostlist", "pcmk_host_list" ] and value == "all":
                    value = ' '.join(all_node_names)

                st[name] = value

            st.commit()

            # Test advanced fencing logic
            stf_nodes = []
            stt_nodes = []
            attr_nodes = {}

            # Create the levels
            stl = FencingTopology(self._factory)
            for node in self._cm.Env["nodes"]:
                # Remote node tests will rename the node
                remote_node = "remote-%s" % node

                # Randomly assign node to a fencing method
                ftype = self._cm.Env.random_gen.choice(["levels-and", "levels-or ", "broadcast "])

                # For levels-and, randomly choose targeting by node name or attribute
                by = ""

                if ftype == "levels-and":
                    node_id = self.get_node_id(node)

                    if node_id == 0 or self._cm.Env.random_gen.choice([True, False]):
                        by = " (by name)"
                    else:
                        attr_nodes[node] = node_id
                        by = " (by attribute)"

                self._cm.log(" - Using %s fencing for node: %s%s" % (ftype, node, by))

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
                stn = Nodes(self._factory)

                for (node_name, node_id) in attr_nodes.items():
                    stn.add_node(node_name, node_id, { "cts-fencing" : "levels-and" })

                stl.level(1, None, "FencingPass,Fencing", "cts-fencing", "levels-and")

            # Create a Dummy agent that always passes for levels-and
            if stt_nodes:
                stt = Resource(self._factory, "FencingPass", "fence_dummy", "stonith")
                stt["pcmk_host_list"] = " ".join(stt_nodes)
                # Wait this many seconds before doing anything, handy for letting disks get flushed too
                stt["random_sleep_range"] = "30"
                stt["mode"] = "pass"
                stt.commit()

            # Create a Dummy agent that always fails for levels-or
            if stf_nodes:
                stf = Resource(self._factory, "FencingFail", "fence_dummy", "stonith")
                stf["pcmk_host_list"] = " ".join(stf_nodes)
                # Wait this many seconds before doing anything, handy for letting disks get flushed too
                stf["random_sleep_range"] = "30"
                stf["mode"] = "fail"
                stf.commit()

            # Now commit the levels themselves
            stl.commit()

        o = Option(self._factory)
        o["stonith-enabled"] = self._cm.Env["DoFencing"]
        o["start-failure-is-fatal"] = "false"
        o["pe-input-series-max"] = "5000"
        o["shutdown-escalation"] = "5min"
        o["batch-limit"] = "10"
        o["dc-deadtime"] = "5s"
        o["no-quorum-policy"] = no_quorum

        o.commit()

        o = OpDefaults(self._factory)
        o["timeout"] = "90s"
        o.commit()

        # Commit the nodes section if we defined one
        if stn is not None:
            stn.commit()

        # Add an alerts section if possible
        if self._factory.rsh.exists_on_all(self._cm.Env["notification-agent"], self._cm.Env["nodes"]):
            alerts = Alerts(self._factory)
            alerts.add_alert(self._cm.Env["notification-agent"],
                             self._cm.Env["notification-recipient"])
            alerts.commit()

        # Add resources?
        if self._cm.Env["CIBResource"]:
            self.add_resources()

        # generate cib
        self._cib = self._show()

        if self._factory.tmpfile != "%s/cib.xml" % BuildOptions.CIB_DIR:
            self._factory.rsh(self._factory.target, "rm -f %s" % self._factory.tmpfile)

        return self._cib

    def add_resources(self):
        # Per-node resources
        for node in self._cm.Env["nodes"]:
            name = "rsc_%s" % node
            r = self.new_ip(name)
            r.prefer(node, "100")
            r.commit()

        # Migrator
        # Make this slightly sticky (since we have no other location constraints) to avoid relocation during Reattach
        m = Resource(self._factory, "migrator","Dummy",  "ocf", "pacemaker")
        m["passwd"] = "whatever"
        m.add_meta("resource-stickiness","1")
        m.add_meta("allow-migrate", "1")
        m.add_op("monitor", "P10S")
        m.commit()

        # Ping the test exerciser
        p = Resource(self._factory, "ping-1","ping",  "ocf", "pacemaker")
        p.add_op("monitor", "60s")
        p["host_list"] = self._cm.Env["cts-exerciser"]
        p["name"] = "connected"
        p["debug"] = "true"

        c = Clone(self._factory, "Connectivity", p)
        c["globally-unique"] = "false"
        c.commit()

        # promotable clone resource
        s = Resource(self._factory, "stateful-1", "Stateful", "ocf", "pacemaker")
        s.add_op("monitor", "15s", timeout="60s")
        s.add_op("monitor", "16s", timeout="60s", role="Promoted")
        ms = Clone(self._factory, "promotable-1", s)
        ms["promotable"] = "true"
        ms["clone-max"] = self._num_nodes
        ms["clone-node-max"] = 1
        ms["promoted-max"] = 1
        ms["promoted-node-max"] = 1

        # Require connectivity to run the promotable clone
        r = Rule(self._factory, "connected", "-INFINITY", op="or")
        r.add_child(Expression(self._factory, "m1-connected-1", "connected", "lt", "1"))
        r.add_child(Expression(self._factory, "m1-connected-2", "connected", "not_defined", None))
        ms.prefer("connected", rule=r)

        ms.commit()

        # Group Resource
        g = Group(self._factory, "group-1")
        g.add_child(self.new_ip())

        if self._cm.Env["have_systemd"]:
            sysd = Resource(self._factory, "petulant", "pacemaker-cts-dummyd@10", "service")
            sysd.add_op("monitor", "P10S")
            g.add_child(sysd)
        else:
            g.add_child(self.new_ip())

        g.add_child(self.new_ip())

        # Make group depend on the promotable clone
        g.after("promotable-1", first="promote", then="start")
        g.colocate("promotable-1", "INFINITY", withrole="Promoted")

        g.commit()

        # LSB resource
        lsb = Resource(self._factory, "lsb-dummy", "LSBDummy", "lsb")
        lsb.add_op("monitor", "5s")

        # LSB with group
        lsb.after("group-1")
        lsb.colocate("group-1")

        lsb.commit()


class ConfigFactory:
    def __init__(self, cm):
        # pylint: disable=invalid-name
        self._cm = cm
        self.rsh = self._cm.rsh
        if not self._cm.Env["ListTests"]:
            self.target = self._cm.Env["nodes"][0]
        self.tmpfile = None

    def log(self, args):
        self._cm.log("cib: %s" % args)

    def debug(self, args):
        self._cm.debug("cib: %s" % args)

    def create_config(self, name="pacemaker-1.0"):
        return CIB(self._cm, name, self)
