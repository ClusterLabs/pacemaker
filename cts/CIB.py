'''CTS: Cluster Testing System: CIB generator
'''
__copyright__='''
Author: Andrew Beekhof <abeekhof@suse.de>
Copyright (C) 2008 Andrew Beekhof
'''

from UserDict import UserDict
import sys, time, types, syslog, os, struct, string, signal, traceback, warnings, socket

from cts.CTSvars import *
from cts.CTS     import ClusterManager

class CibBase:
    cts_cib = None
    cib_tmpfile = None
    version = "unknown"
    feature_set = "unknown"
    target = None

    def __init__(self, CM, tmpfile=None):
        self.CM = CM
        #self.target = self.CM.Env["nodes"][0]

        if not tmpfile:
            warnings.filterwarnings("ignore")
            self.cib_tmpfile=os.tmpnam()
            warnings.resetwarnings()
        else:
            self.cib_tmpfile = tmpfile

    def version(self):
        return self.version

    def NextIP(self):
        fields = string.split(self.CM.Env["IPBase"], '.')
        fields[3] = str(int(fields[3])+1)
        ip = string.join(fields, '.')
        self.CM.Env["IPBase"] = ip
        return ip

class CIB10(CibBase):
    feature_set = "3.0"
    version = "pacemaker-1.0"
    cib_template = '''
<cib crm_feature_set='%s' admin_epoch='1' epoch='0' num_updates='0' validate-with='%s' %s>
   <configuration>
      <crm_config/>
      <nodes/>
      <resources/>
      <constraints/>
   </configuration>
   <status/>
</cib>'''

    def _create(self, command):
        fixed = "HOME=/root CIB_file="+self.cib_tmpfile+" crm --force configure " + command 
        rc = self.CM.rsh(self.target, fixed)
        if rc != 0:
            self.CM.log("Configure call failed: "+fixed)
            sys.exit(1)

    def _show(self, command=""):
        output = ""
        (rc, result) = self.CM.rsh(self.target, "HOME=/root CIB_file="+self.cib_tmpfile+" crm configure show "+command, None, )
        for line in result:
            output += line
            self.CM.debug("Generated Config: "+line)
        return output

    def NewIP(self, name=None, standard="ocf:heartbeat"):
        ip = self.NextIP()
        if not name:
            name = "r"+ip

        if not standard:
            standard = ""
        else:
            standard += ":"

        self._create('''primitive %s %sIPaddr params ip=%s cidr_netmask=32 op monitor interval=5s''' 
                  % (name, standard, ip))
        return name

    def install(self, target):
        old = self.cib_tmpfile

        # Force a rebuild
        self.cts_cib = None

        self.cib_tmpfile = CTSvars.CRM_CONFIG_DIR+"/cib.xml"
        self.contents(target)
        self.CM.rsh(self.target, "chown "+CTSvars.CRM_DAEMON_USER+" "+self.cib_tmpfile)

        self.cib_tmpfile = old

    def contents(self, target=None):
        # fencing resource
        if self.cts_cib:
            return self.cts_cib
        
        if not target:
            self.target = self.CM.Env["nodes"][0]
        else:
            self.target = target

        cib_base = self.cib_template % (self.feature_set, self.version, ''' remote-tls-port='9898' remote-clear-port='9999' ''')
        self.CM.rsh(self.target, '''echo "%s" > %s''' % (cib_base, self.cib_tmpfile))
        #self.CM.rsh.cp(self.cib_tmpfile, "root@%s:%s" % (self.target, self.cib_tmpfile))

        nodelist = ""
        self.num_nodes = 0
        for node in self.CM.Env["nodes"]:
            nodelist += node + " "
            self.num_nodes = self.num_nodes + 1

        no_quorum = "stop"
        if self.num_nodes < 3:
            no_quorum = "ignore"
            self.CM.log("Cluster only has %d nodes, configuring: no-quroum-policy=ignore" % self.num_nodes) 


        # The shell no longer functions when the lrmd isn't running, how wonderful
        # Start one here and let the cluster clean it up when the full stack starts
        # Just hope target has the same location for lrmd
        self.CM.rsh(self.target, CTSvars.CRM_DAEMON_DIR+"/lrmd", synchronous=0)

        # Tell the shell to mind its own business, we know what we're doing
        self.CM.rsh(self.target, "crm options check-mode relaxed")

        # Fencing resource
        # Define first so that the shell doesn't reject every update
        if self.CM.Env["DoFencing"]:
            params = None
            entries = string.split(self.CM.Env["stonith-params"], ',')
            for entry in entries:
                (name, value) = string.split(entry, '=')
                if name == "hostlist" and value == "all":
                    value = string.join(self.CM.Env["nodes"], " ")

                if params:
                    params = ("""%s '%s="%s"' """ % (params, name, value))
                else:
                    params = ("""'%s="%s"' """ % (name, value))

            if params:
                params = "params %s" % params
            else:
                params = ""

            # Set a threshold for unreliable stonith devices such as the vmware one
            self._create('''primitive Fencing stonith::%s %s meta migration-threshold=5 op monitor interval=120s timeout=300 op start interval=0 timeout=180s op stop interval=0 timeout=180s''' % (self.CM.Env["stonith-type"], params))

        self._create('''property stonith-enabled=%s''' % (self.CM.Env["DoFencing"]))
        self._create('''property start-failure-is-fatal=false pe-input-series-max=5000 default-action-timeout=60s''')
        self._create('''property shutdown-escalation=5min batch-limit=10 dc-deadtime=5s''')
        self._create('''property no-quorum-policy=%s expected-quorum-votes=%d''' % (no_quorum, self.num_nodes))

        if self.CM.Env["DoBSC"] == 1:
            self._create('''property ident-string="Linux-HA TEST configuration file - REMOVEME!!"''')

        # Add resources?
        if self.CM.Env["CIBResource"] == 1:
            self.add_resources()

        if self.CM.cluster_monitor == 1:
            self._create('''primitive cluster_mon ocf:pacemaker:ClusterMon params update=10 extra_options="-r -n" user=abeekhof htmlfile=/suse/abeekhof/Export/cluster.html op start interval=0 requires=nothing op monitor interval=5s requires=nothing''')
            self._create('''location prefer-dc cluster_mon rule -INFINITY: \#is_dc eq false''')

        # generate cib
        self.cts_cib = self._show("xml")

        if self.cib_tmpfile != CTSvars.CRM_CONFIG_DIR+"/cib.xml":
            self.CM.rsh(self.target, "rm -f "+self.cib_tmpfile)

        return self.cts_cib

    def add_resources(self):
        # Group Resource
        r1 = self.NewIP()
        #ip = self.NextIP()
        #r2 = "r"+ip
        #self._create('''primitive %s heartbeat::IPaddr params 1=%s/32 op monitor interval=5s''' % (r2, ip))
        r2 = self.NewIP()
        r3 = self.NewIP()
        self._create('''group group-1 %s %s %s''' % (r1, r2, r3))

        # Per-node resources
        for node in self.CM.Env["nodes"]:
            r = self.NewIP("rsc_"+node)
            self._create('''location prefer-%s %s rule 100: \#uname eq %s''' % (node, r, node))
                
        # LSB resource
        lsb_agent = self.CM.install_helper("LSBDummy")
    
        self._create('''primitive lsb-dummy lsb::''' +lsb_agent+ ''' op monitor interval=5s''')
        self._create('''colocation lsb-with-group INFINITY: lsb-dummy group-1''')
        self._create('''order lsb-after-group mandatory: group-1 lsb-dummy symmetrical=true''')

        # Migrator
        # Make this slightly sticky (since we have no other location constraints) to avoid relocation during Reattach 
        self._create('''primitive migrator ocf:pacemaker:Dummy meta resource-stickiness=1 allow-migrate=1 op monitor interval=P10S''')

        # Ping the test master
        self._create('''primitive ping-1 ocf:pacemaker:ping params host_list=%s name=connected debug=true op monitor interval=60s''' % self.CM.Env["cts-master"])
        self._create('''clone Connectivity ping-1 meta globally-unique=false''')

        #master slave resource
        self._create('''primitive stateful-1 ocf:pacemaker:Stateful op monitor interval=15s timeout=60s op monitor interval=16s role=Master timeout=60s ''')
        self._create('''ms master-1 stateful-1 meta clone-max=%d clone-node-max=%d master-max=%d master-node-max=%d'''
                     % (self.num_nodes, 1, 1, 1))

        # Require conectivity to run the master
        self._create('''location %s-is-connected %s rule -INFINITY: connected lt %d or not_defined connected''' % ("m1", "master-1", 1))

        # Group with the master
        self._create('''colocation group-with-master INFINITY: group-1 master-1:Master''')
        self._create('''order group-after-master mandatory: master-1:promote group-1:start symmetrical=true''')

class HASI(CIB10):
    def add_resources(self):
        # DLM resource
        self._create('''primitive dlm ocf:pacemaker:controld op monitor interval=120s''')
        self._create('''clone dlm-clone dlm meta globally-unique=false interleave=true''')

        # O2CB resource
        self._create('''primitive o2cb ocf:ocfs2:o2cb op monitor interval=120s''')
        self._create('''clone o2cb-clone o2cb meta globally-unique=false interleave=true''')
        self._create('''colocation o2cb-with-dlm INFINITY: o2cb-clone dlm-clone''')
        self._create('''order start-o2cb-after-dlm mandatory: dlm-clone o2cb-clone''')

class ConfigFactory:      
    def __init__(self, CM):
        self.CM = CM
        self.register("pacemaker10", CIB10, CM)
        self.register("hae", HASI, CM)


    def register(self, methodName, constructor, *args, **kargs):
        """register a constructor"""
        _args = [constructor]
        _args.extend(args)
        setattr(self, methodName, apply(ConfigFactoryItem,_args, kargs))
        
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
        elif name == "hasi":
            name = "hae";

        if hasattr(self, name):
            return getattr(self, name)()
        else:
            self.CM.log("Configuration variant '%s' is unknown.  Defaulting to latest config" % name)

        return self.pacemaker10()

class ConfigFactoryItem:
    def __init__(self, function, *args, **kargs):
        assert callable(function), "function should be a callable obj"
        self._function = function
        self._args = args
        self._kargs = kargs
        
    def __call__(self, *args, **kargs):
        """call function"""
        _args = list(self._args)
        _args.extend(args)
        _kargs = self._kargs.copy()
        _kargs.update(kargs)
        return apply(self._function,_args,_kargs)


#CibFactory = ConfigFactory()
