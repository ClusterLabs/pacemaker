'''CTS: Cluster Testing System: CIB generator
'''
__copyright__='''
Author: Andrew Beekhof <abeekhof@suse.de>
Copyright (C) 2008 Andrew Beekhof
'''

from UserDict import UserDict
import sys, time, types, syslog, os, struct, string, signal, traceback, warnings, socket

from cts.CTSvars import *
from cts.CTS     import ClusterManager, RemoteExec

class CibBase:
    cts_cib = None
    cib_tmpfile = None
    version = "unknown"
    feature_set = "unknown"
    Factory = None

    def __init__(self, CM, factory, tmpfile=None):
        self.CM = CM
        self.Factory = factory

        if not tmpfile:
            warnings.filterwarnings("ignore")
            self.cib_tmpfile=os.tmpnam()
            warnings.resetwarnings()
        else:
            self.cib_tmpfile = tmpfile

        self.Factory.tmpfile = self.cib_tmpfile

    def version(self):
        return self.version

    def NextIP(self):
        fields = string.split(self.CM.Env["IPBase"], '.')
        fields[3] = str(int(fields[3])+1)
        ip = string.join(fields, '.')
        self.CM.Env["IPBase"] = ip
        return ip

class Option:
    def __init__(self, Factory, name, value, section="cib-bootstrap-options"):
        self.Factory = Factory
        self.id = "%s-%s" % (section, name)
        self.section = section
        self.name = name
        self.value = value

        self.target = "pcmk-1"
        self.cib_tmpfile = CTSvars.CRM_CONFIG_DIR+"/cib.xml"

    def show(self):
        text = '''<crm_config>'''
        text += ''' <cluster_property_set id="%s">''' % self.section
        text += '''  <nvpair id="cts-%s" name="%s" value="%s"/>''' % (self.id, self.name, self.value)
        text += ''' </cluster_property_set>'''
        text += '''</crm_config>'''
        return text
        
    def commit(self):
        self.Factory.debug("Writing out %s" % self.id)
        fixed = "HOME=/root CIB_file="+self.cib_tmpfile+" cibadmin --modify --xml-text '%s'" % self.show() 
        rc = self.Factory.rsh(self.target, fixed)
        if rc != 0:
            self.Factory.log("Configure call failed: "+fixed)
            sys.exit(1)

class CibXml:
    def __init__(self, tag, name, **kwargs):
        self.tag = tag
        self.name = name
        self.kwargs = kwargs

    def __setitem__(self, key, value):
        self.kwargs[key] = value

    def show(self):
        text = '''<%s id="%s"''' % (self.tag, self.name)
        for k in self.kwargs.keys():
            text += ''' %s="%s"''' % (k, self.kwargs[k])
        text += '''/>'''
        return text

class Expression(CibXml):
    def __init__(self, name, attr, op, value=None):
        CibXml.__init__(self, "expression", name, attribute=attr, operation=op)
        if value:
            self["value"] = value

class ResourceOp(CibXml):
    def __init__(self, resource, name, interval, **kwargs):
        CibXml.__init__(self, "op", "%s-%s-%s" % (resource, name, interval), **kwargs)
        self["name"] = name
        self["interval"] = interval

class Rule:
    def __init__(self, name, score, op="and", expr=None):
        self.id = name
        self.op = op
        self.score = score
        self.expr = []
        if expr:
            self.add_exp(expr)

    def add_exp(self, e):
        self.expr.append(e)

    def show(self):
        text = '''<rule id="%s" score="%s">''' % (self.id, self.score)
        for e in self.expr:
            text += e.show()
        text += '''</rule>'''
        return text

class Resource:
    def __init__(self, Factory, name, rtype, standard, provider=None):
        self.Factory = Factory

        self.name = name
        self.rtype = rtype
        self.standard = standard
        self.provider = provider

        self.op=[]
        self.meta={}
        self.param={}

        self.scores={}
        self.needs={}
        self.coloc={}

        if self.standard == "ocf" and not provider:
            self.provider = "heartbeat"
        elif self.standard == "lsb":
            self.provider = None

    def __setitem__(self, key, value):
        self.add_param(key, value)
        
    def add_op(self, name, interval, **kwargs):
        self.op.append(ResourceOp(self.name, name, interval, **kwargs))

    def add_param(self, name, value):
        self.param[name] = value

    def add_meta(self, name, value):
        self.meta[name] = value

    def prefer(self, node, score="INFINITY", rule=None):
        if not rule:
            rule = Rule("prefer-%s-r" % node, score, expr=Expression("prefer-%s-e" % node, "#uname", "eq", node))
        self.scores[node] = rule

    def _needs(self, resource, kind="Mandatory", first="start", then="start", **kwargs):
        kargs = kwargs.copy()
        kargs["kind"] = kind
        if then:
            kargs["first-action"] = "start"
            kargs["then-action"] = then

        if first:
            kargs["first-action"] = first

        self.needs[resource] = kargs

    def _coloc(self, resource, score="INFINITY", role=None, withrole=None, **kwargs):
        kargs = kwargs.copy()
        kargs["score"] = score
        if role:
            kargs["rsc-role"] = role
        if withrole:
            kargs["with-rsc-role"] = withrole
        
        self.coloc[resource] = kargs

    def constraints(self):
        text = "<constraints>"

        for k in self.scores.keys():
            text += '''<rsc_location id="prefer-%s" rsc="%s">''' % (k, self.name)
            text += self.scores[k].show()
            text += '''</rsc_location>'''

        for k in self.needs.keys():
            text += '''<rsc_order id="%s-after-%s" first="%s" then="%s"''' % (self.name, k, k, self.name)
            kargs = self.needs[k]
            for kw in kargs.keys():
                text += ''' %s="%s"''' % (kw, kargs[kw])
            text += '''/>'''

        for k in self.coloc.keys():
            text += '''<rsc_colocation id="%s-with-%s" rsc="%s" with-rsc="%s"''' % (self.name, k, self.name, k)
            kargs = self.coloc[k]
            for kw in kargs.keys():
                text += ''' %s="%s"''' % (kw, kargs[kw])
            text += '''/>'''

        text += "</constraints>"
        return text

    def show(self):
        text = '''<primitive id="%s" class="%s" type="%s"''' % (self.name, self.standard, self.rtype)
        if self.provider:
            text += ''' provider="%s"''' % (self.provider)
        text += '''>'''

        if len(self.meta) > 0:
            text += '''<meta_attributes id="%s-meta">''' % self.name
            for p in self.meta.keys():
                text += '''<nvpair id="%s-%s" name="%s" value="%s"/>''' % (self.name, p, p, self.meta[p])
            text += '''</meta_attributes>'''

        if len(self.param) > 0:
            text += '''<instance_attributes id="%s-params">''' % self.name
            for p in self.param.keys():
                text += '''<nvpair id="%s-%s" name="%s" value="%s"/>''' % (self.name, p, p, self.param[p])
            text += '''</instance_attributes>'''

        if len(self.op) > 0:
            text += '''<operations>'''
            for o in self.op:
                text += o.show()
            text += '''</operations>'''

        text += '''</primitive>'''
        return text

    def commit(self):
        self.Factory.debug("Writing out %s" % self.name)
        fixed = "HOME=/root CIB_file="+self.Factory.tmpfile+" cibadmin --create --scope resources --xml-text '%s'" % self.show() 
        rc = self.Factory.rsh(self.Factory.target, fixed)
        if rc != 0:
            self.Factory.log("Configure call failed: "+fixed)
            sys.exit(1)

        fixed = "HOME=/root CIB_file="+self.Factory.tmpfile+" cibadmin --modify --xml-text '%s'" % self.constraints() 
        rc = self.Factory.rsh(self.Factory.target, fixed)
        if rc != 0:
            self.Factory.log("Configure call failed: "+fixed)
            sys.exit(1)

class Group(Resource):
    def __init__(self, Factory, name):
        self.name = name
        self.children = []
        self.object = "group"
        Resource.__init__(self, Factory, name, None, None)

    def add_child(self, resource):
        self.children.append(resource)

    def __setitem__(self, key, value):
        self.add_meta(key, value)
        
    def show(self):
        text = '''<%s id="%s">''' % (self.object, self.name)

        if len(self.meta) > 0:
            text += '''<meta_attributes id="%s-meta">''' % self.name
            for p in self.meta.keys():
                text += '''<nvpair id="%s-%s" name="%s" value="%s"/>''' % (self.name, p, p, self.meta[p])
            text += '''</meta_attributes>'''

        for c in self.children:
            text += c.show()
        text += '''</%s>''' % self.object
        return text

class Clone(Group):
    def __init__(self, Factory, name, child=None):
        Group.__init__(self, Factory, name)
        self.object = "clone"
        if child:
            self.add_child(child)

    def add_child(self, resource):
        if not self.children:
            self.children.append(resource)
        else:
            self.Factory.log("Clones can only have a single child. Ignoring %s" % resource.name)

class Master(Clone):
    def __init__(self, Factory, name, child=None):
        Clone.__init__(self, Factory, name, child)
        self.object = "master"

class CIB12(CibBase):
    feature_set = "3.0"
    version = "pacemaker-1.2"

    def _show(self, command=""):
        output = ""
        (rc, result) = self.Factory.rsh(self.Factory.target, "HOME=/root CIB_file="+self.Factory.tmpfile+" cibadmin -Ql "+command, None, )
        for line in result:
            output += line
            self.Factory.debug("Generated Config: "+line)
        return output

    def NewIP(self, name=None, standard="ocf"):
        ip = self.NextIP()
        if not name:
            name = "r"+ip
            
        r = Resource(self.Factory, name, "IPaddr2", standard)
        r["ip"] = ip
        r["cidr_netmask"] = "32"
        r.add_op("monitor", "5s")
        return r

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

        self.Factory.rsh(self.Factory.target, "HOME=/root cibadmin --empty > %s" % self.Factory.tmpfile)
        #cib_base = self.cib_template % (self.feature_set, self.version, ''' remote-tls-port='9898' remote-clear-port='9999' ''')

        nodelist = ""
        self.num_nodes = 0
        for node in self.CM.Env["nodes"]:
            nodelist += node + " "
            self.num_nodes = self.num_nodes + 1

        no_quorum = "stop"
        if self.num_nodes < 3:
            no_quorum = "ignore"
            self.Factory.log("Cluster only has %d nodes, configuring: no-quroum-policy=ignore" % self.num_nodes) 

        # Fencing resource
        # Define first so that the shell doesn't reject every update
        if self.CM.Env["DoFencing"]:
            st = Resource(self.Factory, "Fencing", self.CM.Env["stonith-type"], "stonith")
            # Set a threshold for unreliable stonith devices such as the vmware one
            st.add_meta("migration-threshold", "5")
            st.add_op("monitor", "120s", timeout="300s")
            st.add_op("stop", "0", timeout="180s")
            st.add_op("start", "0", timeout="180s")

            entries = string.split(self.CM.Env["stonith-params"], ',')
            for entry in entries:
                (name, value) = string.split(entry, '=')
                if name == "hostlist" and value == "all":
                    value = string.join(self.CM.Env["nodes"], " ")

                st[name] = value

            st.commit()

        Option(self.Factory, "stonith-enabled", self.CM.Env["DoFencing"]).commit()
        Option(self.Factory, "start-failure-is-fatal", "false").commit()
        Option(self.Factory, "pe-input-series-max", "5000").commit()
        Option(self.Factory, "default-action-timeout", "60s").commit()
        Option(self.Factory, "shutdown-escalation", "5min").commit()
        Option(self.Factory, "batch-limit", "10").commit()
        Option(self.Factory, "dc-deadtime", "5s").commit()
        Option(self.Factory, "no-quorum-policy", no_quorum).commit()
        Option(self.Factory, "expected-quorum-votes", self.num_nodes).commit()

        if self.CM.Env["DoBSC"] == 1:
            Option(self.Factory, "ident-string", "Linux-HA TEST configuration file - REMOVEME!!").commit()

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
        m.add_meta("resource-stickiness","1")
        m.add_meta("allow-migrate", "1")
        m.add_op("monitor", "P10S")
        m.commit()

        # Ping the test master
        p = Resource(self.Factory, "ping-1","ping",  "ocf", "pacemaker")
        p.add_op("monitor", "60s")
        p["host-list"] = self.CM.Env["cts-master"]
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
        r = Rule("connected", "-INFINITY", op="or")
        r.add_exp(Expression("m1-connected-1", "connected", "lt", "1"))
        r.add_exp(Expression("m1-connected-2", "connected", "not_defined", None))
        ms.prefer("connected", rule=r)
        
        ms.commit()

        # Group Resource
        g = Group(self.Factory, "group-1")
        g.add_child(self.NewIP())
        g.add_child(self.NewIP())
        g.add_child(self.NewIP())

        # Group with the master
        g._coloc("master-1", "INFINITY", withrole="Master")
        g._needs("master-1", first="promote", then="start")

        g.commit()


        # LSB resource
        lsb_agent = self.CM.install_helper("LSBDummy")
    
        lsb = Resource(self.Factory, "lsb-dummy",lsb_agent,  "lsb")
        lsb.add_op("monitor", "5s")

        # LSB with group
        lsb._needs("group-1")
        lsb._coloc("group-1")

        lsb.commit()

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
        self.register("pacemaker11", CIB12, CM, self)
        self.register("pacemaker12", CIB12, CM, self)
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

        return self.pacemaker12()

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

# Basic Sanity Testing
if __name__ == '__main__': 
    import CTSlab
    env = CTSlab.LabEnvironment()
    env["nodes"] = []
    env["nodes"].append("pcmk-1")
    env["nodes"].append("pcmk-2")
    env["nodes"].append("pcmk-3")
    env["nodes"].append("pcmk-4")

    env["CIBResource"] = 1
    env["IPBase"] = "10.0.0.10"
    env["DoStonith"]=1
    env["stonith-type"] = "fence_xvm"
    env["stonith-params"] = "pcmk_arg_map=domain:uname"

    manager = ClusterManager(env)
    manager.cluster_monitor = False

    CibFactory = ConfigFactory(manager)
    cib = CibFactory.createConfig("pacemaker-1.0")
    print cib.contents()
