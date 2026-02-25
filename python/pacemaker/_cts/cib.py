"""CIB generator for Pacemaker's Cluster Test Suite (CTS)."""

__all__ = ["ConfigFactory", "create_config"]
__copyright__ = "Copyright 2008-2026 the Pacemaker project contributors"
__license__ = "GNU General Public License version 2 or later (GPLv2+) WITHOUT ANY WARRANTY"

import warnings
import tempfile

from pacemaker.buildoptions import BuildOptions
from pacemaker._cts.cibxml import Alerts, Clone, Expression, FencingTopology, Group, Nodes, OpDefaults, Option, Resource, Rule
from pacemaker._cts import logging
from pacemaker._cts.network import next_ip
from pacemaker._cts.remote import RemoteExec


class CIB:
    """A class for generating, representing, and installing a CIB file onto cluster nodes."""

    def __init__(self, env, version, node):
        """
        Create a new CIB instance.

        Arguments:
        env     -- An EnvFactory instance
        version -- The schema syntax version
        node    -- The node to install this CIB to
        """
        self._cib = None
        self._counter = 1
        self._env = env
        self._node = node
        self._num_nodes = 0
        self._rsh = RemoteExec()
        self._tmpfile = None

        self.version = version

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")

            # FIXME: When we support python >= 3.12, we can use a context
            # manager here and pass delete_on_close=False
            # pylint: disable=consider-using-with
            f = tempfile.NamedTemporaryFile(delete=True)
            f.close()
            self._tmpfile = f.name

    def _show(self):
        """Query a cluster node for its generated CIB; log and return the result."""
        output = ""
        (_, result) = self._rsh.call(self._node, f"HOME=/root CIB_file={self._tmpfile} cibadmin -Q", verbose=1)

        for line in result:
            output += line
            logging.debug(f"cib: Generated Config: {line}")

        return output

    def new_ip(self, name=None):
        """Generate an IP resource for the next available IP address, optionally specifying the resource's name."""
        ip = next_ip(self._env["IPBase"])
        if not name:
            if ":" in ip:
                (_, _, suffix) = ip.rpartition(":")
                name = f"r{suffix}"
            else:
                name = f"r{ip}"

        r = Resource(self._node, name, "IPaddr2", "ocf")
        r["ip"] = ip

        if self._env["nic"] is not None:
            r["nic"] = self._env["nic"]

        if ":" in ip:
            r["cidr_netmask"] = "64"

            if self._env["nic"] is None and ip.lstrip().startswith("fe80::"):
                # "nic" parameter is mandatory for an IPv6 link local address
                r["nic"] = "eth0"

        else:
            r["cidr_netmask"] = "32"

        r.add_op("monitor", "5s")
        return r

    def get_node_id(self, node_name):
        """Check the cluster configuration for the node ID for the given node_name."""
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
        awk = r"""awk -v RS="}" """ \
              r"""'/^(\s*nodelist\s*{)?\s*node\s*{.*(ring0_addr|name):\s*%s(\s+|$)/""" \
              r"""{gsub(/.*nodeid:\s*/,"");gsub(/\s+.*$/,"");print}' %s""" \
              % (node_name, BuildOptions.COROSYNC_CONFIG_FILE)

        (rc, output) = self._rsh.call(self._node, awk, verbose=1)

        if rc == 0 and len(output) == 1:
            try:
                node_id = int(output[0])
            except ValueError:
                node_id = 0

        return node_id

    def install(self, node):
        """Generate a CIB file and install it to the given cluster node."""
        old = self._tmpfile

        # Force a rebuild
        self._cib = None

        self._tmpfile = f"{BuildOptions.CIB_DIR}/cib.xml"
        self.contents(node)
        self._rsh.call(self._node, f"chown {BuildOptions.DAEMON_USER} {self._tmpfile}")

        self._tmpfile = old

    def contents(self, node):
        """Generate a complete CIB file."""
        if self._cib:
            return self._cib

        if node:
            self._node = node

        self._rsh.call(self._node, f"HOME=/root cibadmin --empty {self.version} > {self._tmpfile}")
        self._num_nodes = len(self._env["nodes"])

        no_quorum = "stop"
        if self._num_nodes < 3:
            no_quorum = "ignore"
            logging.log(f"cib: Cluster only has {self._num_nodes} nodes, configuring: no-quorum-policy=ignore")

        # We don't need a nodes section unless we add attributes
        stn = None

        # Fencing resource
        # Define first so that the shell doesn't reject every update
        if self._env["fencing_enabled"]:

            # Define the "real" fencing device
            st = Resource(self._node, "Fencing", self._env["fencing_agent"], "stonith")

            # Set a threshold for unreliable stonith devices such as the vmware one
            st.add_meta("migration-threshold", "5")
            st.add_op("monitor", "120s", timeout="120s")
            st.add_op("stop", "0", timeout="60s")
            st.add_op("start", "0", timeout="60s")

            # For remote node tests, a cluster node is stopped and brought back up
            # as a remote node with the name "remote-OLDNAME". To allow fencing
            # devices to fence these nodes, create a list of all possible node names.
            all_node_names = [prefix + n for n in self._env["nodes"] for prefix in ('', 'remote-')]

            # Add all parameters specified by user
            for param in self._env["fencing_params"]:
                try:
                    (name, value) = param.split('=', 1)
                except ValueError:
                    print(f"Warning: skipping invalid fencing parameter: {param}")
                    continue

                # Allow user to specify "all" as the node list, and expand it here
                if name in ["hostlist", "pcmk_host_list"] and value == "all":
                    value = ' '.join(all_node_names)

                st[name] = value

            st.commit(self._tmpfile)

            # Test advanced fencing logic
            stf_nodes = []
            stt_nodes = []
            attr_nodes = {}

            # Create the levels
            stl = FencingTopology(self._node)
            for n in self._env["nodes"]:
                # Remote node tests will rename the node
                remote_node = f"remote-{n}"

                # Randomly assign node to a fencing method
                # @TODO What does "broadcast" do, if anything?
                types = ["levels-and", "levels-or", "broadcast"]
                width = max(len(t) for t in types)
                ftype = self._env.random_gen.choice(types)

                # For levels-and, randomly choose targeting by node name or attribute
                by = ""

                if ftype == "levels-and":
                    node_id = self.get_node_id(n)

                    if node_id == 0 or self._env.random_gen.choice([True, False]):
                        by = " (by name)"
                    else:
                        attr_nodes[n] = node_id
                        by = " (by attribute)"

                logging.log(f" - Using {ftype:{width}} fencing for node: {n}{by}")

                if ftype == "levels-and":
                    # If targeting by name, add a topology level for this node
                    if n not in attr_nodes:
                        stl.level(1, n, "FencingPass,Fencing")

                    # Always target remote nodes by name, otherwise we would need to add
                    # an attribute to the remote node only during remote tests (we don't
                    # want nonexistent remote nodes showing up in the non-remote tests).
                    # That complexity is not worth the effort.
                    stl.level(1, remote_node, "FencingPass,Fencing")

                    # Add the node (and its remote equivalent) to the list of levels-and nodes.
                    stt_nodes.extend([n, remote_node])

                elif ftype == "levels-or":
                    stl.level(1, n, "FencingFail")
                    stl.level(2, n, "Fencing")
                    stl.level(1, remote_node, "FencingFail")
                    stl.level(2, remote_node, "Fencing")
                    stf_nodes.extend([n, remote_node])

            # If any levels-and nodes were targeted by attribute,
            # create the attributes and a level for the attribute.
            if attr_nodes:
                stn = Nodes(self._node)

                for (node_name, node_id) in attr_nodes.items():
                    stn.add_node(node_name, node_id, {"cts-fencing": "levels-and"})

                stl.level(1, None, "FencingPass,Fencing", "cts-fencing", "levels-and")

            # Create a Dummy agent that always passes for levels-and
            if stt_nodes:
                stt = Resource(self._node, "FencingPass", "fence_dummy", "stonith")
                stt["pcmk_host_list"] = " ".join(stt_nodes)
                # Wait this many seconds before doing anything, handy for letting disks get flushed too
                stt["random_sleep_range"] = "30"
                stt["mode"] = "pass"
                stt.commit(self._tmpfile)

            # Create a Dummy agent that always fails for levels-or
            if stf_nodes:
                stf = Resource(self._node, "FencingFail", "fence_dummy", "stonith")
                stf["pcmk_host_list"] = " ".join(stf_nodes)
                # Wait this many seconds before doing anything, handy for letting disks get flushed too
                stf["random_sleep_range"] = "30"
                stf["mode"] = "fail"
                stf.commit(self._tmpfile)

            # Now commit the levels themselves
            stl.commit(self._tmpfile)

        o = Option(self._node)
        o["fencing-enabled"] = self._env["fencing_enabled"]
        o["start-failure-is-fatal"] = "false"
        o["pe-input-series-max"] = "5000"
        o["shutdown-escalation"] = "5min"
        o["batch-limit"] = "10"
        o["dc-deadtime"] = "5s"
        o["no-quorum-policy"] = no_quorum

        o.commit(self._tmpfile)

        o = OpDefaults(self._node)
        o["timeout"] = "90s"
        o.commit(self._tmpfile)

        # Commit the nodes section if we defined one
        if stn is not None:
            stn.commit(self._tmpfile)

        # Add an alerts section if possible
        if self._rsh.exists_on_all(self._env["notification-agent"], self._env["nodes"]):
            alerts = Alerts(self._node)
            alerts.add_alert(self._env["notification-agent"],
                             self._env["notification-recipient"])
            alerts.commit(self._tmpfile)

        # Add resources?
        if self._env["create_resources"]:
            self.add_resources()

        # generate cib
        self._cib = self._show()

        if self._tmpfile != f"{BuildOptions.CIB_DIR}/cib.xml":
            self._rsh.call(self._node, f"rm -f {self._tmpfile}")

        return self._cib

    def add_resources(self):
        """Add various resources and their constraints to the CIB."""
        # Per-node resources
        for node in self._env["nodes"]:
            name = f"rsc_{node}"
            r = self.new_ip(name)
            r.prefer(node, "100")
            r.commit(self._tmpfile)

        # Migrator
        # Make this slightly sticky (since we have no other location constraints) to avoid relocation during Reattach
        m = Resource(self._node, "migrator", "Dummy", "ocf", "pacemaker")
        m["passwd"] = "whatever"
        m.add_meta("resource-stickiness", "1")
        m.add_meta("allow-migrate", "1")
        m.add_op("monitor", "P10S")
        m.commit(self._tmpfile)

        # Ping the test exerciser
        p = Resource(self._node, "ping-1", "ping", "ocf", "pacemaker")
        p.add_op("monitor", "60s")
        p["host_list"] = self._env["cts-exerciser"]
        p["name"] = "connected"
        p["debug"] = "true"

        c = Clone(self._node, "Connectivity", p)
        c["globally-unique"] = "false"
        c.commit(self._tmpfile)

        # promotable clone resource
        s = Resource(self._node, "stateful-1", "Stateful", "ocf", "pacemaker")
        s.add_op("monitor", "15s", timeout="60s")
        s.add_op("monitor", "16s", timeout="60s", role="Promoted")
        ms = Clone(self._node, "promotable-1", s)
        ms["promotable"] = "true"
        ms["clone-max"] = self._num_nodes
        ms["clone-node-max"] = 1
        ms["promoted-max"] = 1
        ms["promoted-node-max"] = 1

        # Require connectivity to run the promotable clone
        r = Rule(self._node, "connected", "-INFINITY", op="or")
        r.add_child(Expression(self._node, "m1-connected-1", "connected", "lt", "1"))
        r.add_child(Expression(self._node, "m1-connected-2", "connected", "not_defined", None))
        ms.prefer("connected", rule=r)

        ms.commit(self._tmpfile)

        # Group Resource
        g = Group(self._node, "group-1")
        g.add_child(self.new_ip())

        if self._env["have_systemd"]:
            sysd = Resource(self._node, "petulant", "pacemaker-cts-dummyd@10", "service")
            sysd.add_op("monitor", "P10S")
            g.add_child(sysd)
        else:
            g.add_child(self.new_ip())

        g.add_child(self.new_ip())

        # Make group depend on the promotable clone
        g.after("promotable-1", first="promote", then="start")
        g.colocate("promotable-1", "INFINITY", withrole="Promoted")

        g.commit(self._tmpfile)

        # LSB resource dependent on group-1
        if BuildOptions.INIT_DIR is not None:
            lsb = Resource(self._node, "lsb-dummy", "LSBDummy", "lsb")
            lsb.add_op("monitor", "5s")
            lsb.after("group-1")
            lsb.colocate("group-1")
            lsb.commit(self._tmpfile)


def create_config(env):
    """Return a CIB object for the environment's schema version."""
    node = None

    if not env["ListTests"]:
        node = env["nodes"][0]

    return CIB(env, env["Schema"], node)


class ConfigFactory:
    """Singleton to generate a CIB file for the environment's schema version."""

    def __init__(self, env):
        """
        Create a new ConfigFactory instance.

        Arguments:
        env     -- An Environment instance
        """
        self._env = env
        if not self._env["ListTests"]:
            self.node = self._env["nodes"][0]

    def create_config(self, name=f"pacemaker-{BuildOptions.CIB_SCHEMA_VERSION}"):
        """Return a CIB object for the given schema version."""
        return CIB(self._env, name, self.node)
