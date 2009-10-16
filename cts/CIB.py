'''CTS: Cluster Testing System: CIB generator
'''
__copyright__='''
Author: Andrew Beekhof <abeekhof@suse.de>
Copyright (C) 2008 Andrew Beekhof
'''

from UserDict import UserDict
import sys, time, types, syslog, os, struct, string, signal, traceback, warnings

from CTSvars import *
from CTS  import ClusterManager

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

class CIB06(CibBase):
    version = "transitional-0.6"
    coloc_template = """<rsc_colocation id="%s" from="%s" to="%s" to_role="%s" score="%s"/>"""

    cib_template ='''
<cib admin_epoch="1" epoch="0" num_updates="0" remote_access_port="9898">
  <configuration>
     <crm_config>  %s 
     </crm_config>
     <nodes/>
     <resources> %s 
     </resources>
     <constraints> %s 
     </constraints>
    </configuration>
    <status/>
</cib> '''

    cib_option_template = '''
    <cluster_property_set id="cib-bootstrap-options"><attributes>
        <nvpair id="cib-bootstrap-1" name="start-failure-is-fatal" value="false"/>
        <nvpair id="cib-bootstrap-2" name="stonith-enabled"      value="%d"/>
        <nvpair id="cib-bootstrap-3" name="pe-input-series-max"  value="30000"/>
        <nvpair id="cib-bootstrap-4" name="shutdown-escalation"  value="5min"/>
        <nvpair id="cib-bootstrap-5" name="startup-fencing"      value="false"/>
        <nvpair id="cib-bootstrap-6" name="batch-limit"          value="10"/>
        <nvpair id="cib-bootstrap-7" name="no-quorum-policy"     value="%s"/>
  </attributes></cluster_property_set>'''

    lsb_resource = ''' 
        <primitive id="lsb_dummy" class="lsb" type="''' +CTSvars.CTS_home+ '''/LSBDummy">
          <operations>
            <op id="ocf_lsb_monitor" name="monitor" interval="5s"/>
          </operations>
        </primitive> '''

    clustermon_location_constraint = ''' 
        <rsc_location id="run_cluster_mon" rsc="cluster_mon">
          <rule id="cant_run_cluster_mon" score="-INFINITY" boolean_op="and">
             <expression id="mon_expr" attribute="#is_dc" operation="eq" value="false"/>
          </rule>
        </rsc_location> '''

    resource_group_template = '''<group id="group-1">%s %s %s</group>'''

    per_node_constraint_template = ''' 
        <rsc_location id="preferred-%s" rsc="%s" node="%s" score="100"/>''' 

    pingd_constraint_template = '''
        <rsc_location id="%s-is-connected" rsc="%s">
          <rule id="%s-connected-rule" role="%s" score="-INFINITY">
            <expression id="%s-connected-expr" attribute="connected" operation="lt" value="%d"/>
          </rule>
        </rsc_location>''' 

    dummy_resource_template = ''' 
        <primitive id="%s" class="ocf" type="Dummy" provider="heartbeat">
          <operations>
             <op id="mon-%s" name="monitor" interval="10s"/>
          </operations>
          <instance_attributes id="%s-attrs"><attributes>
               <nvpair id="migrate-%s" name="allow_migrate" value="1"/>
           </attributes></instance_attributes>
        </primitive> '''
    
    clustermon_resource_template = ''' 
        <primitive id="cluster_mon" class="ocf" type="ClusterMon" provider="heartbeat">
          <operations>
            <op id="cluster_mon-1" name="monitor" interval="5s" prereq="nothing"/>
            <op id="cluster_mon-2" name="start" prereq="nothing"/>
          </operations>
          <instance_attributes id="cluster_mon-attrs">
            <attributes>
               <nvpair id="cluster_mon-1" name="htmlfile" value="/suse/abeekhof/Export/cluster.html"/>
               <nvpair id="cluster_mon-2" name="update" value="10"/>
               <nvpair id="cluster_mon-3" name="extra_options" value="-n -r"/>
               <nvpair id="cluster_mon-4" name="user" value="abeekhof"/>
           </attributes>
          </instance_attributes>
        </primitive> ''' 

    master_slave_resource = ''' 
        <master_slave id="master-1">
          <instance_attributes id="master_rsc">
            <attributes>
              <nvpair id="clone_max_1" name="clone_max" value="%d"/>
              <nvpair id="clone_node_max_2" name="clone_node_max" value="%d"/>
              <nvpair id="master_max_3" name="master_max" value="%d"/>
              <nvpair id="master_node_max_4" name="master_node_max" value="%d"/>
            </attributes>
          </instance_attributes>
          <primitive id="ocf_msdummy" class="ocf" type="Stateful" provider="heartbeat">
            <operations>
              <op id="ocf_msdummy_monitor" name="monitor" interval="15s"/>
              <op id="ocf_msdummy_monitor_master" name="monitor" interval="16s" role="Master"/>
            </operations>
          </primitive>
        </master_slave>'''

    pingd_resource_template = """ 
        <clone id="Connectivity">
          <meta_attributes id="pingd-opts">
            <attributes>
              <nvpair id="pingd-opt-1" name="globally_unique" value="false"/>
            </attributes>
          </meta_attributes>
          <primitive id="pingd" class="ocf" provider="pacemaker" type="pingd">
            <operations>
              <op id="pingd-op-1" name="monitor" interval="120s"/>
            </operations>
            <instance_attributes id="pingd-attrs">
              <attributes>
                <nvpair id="pingd-attr-1" name="host_list" value="%s"/>
                <nvpair id="pingd-attr-2" name="name" value="connected"/>
              </attributes>
            </instance_attributes>
          </primitive>
        </clone>"""

    stonith_resource_template = """ 
        <clone id="DoFencing">
          <meta_attributes id="fencing">
            <attributes>
              <nvpair id="DoFencing-attr-1" name="resource_failure_stickiness" value="-1"/>
              <nvpair id="DoFencing-attr-2" name="globally_unique" value="false"/>
            </attributes>
          </meta_attributes>
          <primitive id="child_DoFencing" class="stonith" type="%s">
            <operations>
              <op id="DoFencing-op-1" name="monitor" interval="120s" prereq="nothing" timeout="300s"/>
              <op id="DoFencing-op-2" name="start" prereq="nothing"  timeout="180s"/>
              <op id="DoFencing-op-3" name="stop" timeout="180s"/>
            </operations>
            <instance_attributes id="fencing-child">
              <attributes>
                <nvpair id="child_DoFencing-1" name="%s" value="%s"/>
                <nvpair id="child_DoFencing-2" name="livedangerously" value="yes"/>
              </attributes>
            </instance_attributes>
          </primitive>
        </clone>"""

    bsc_template = '''
     <cluster_property_set id="bsc-options">
       <attributes>
         <nvpair id="bsc-options-ident-string" name="ident-string" value="Linux-HA TEST configuration file - REMOVEME!!"/>
       </attributes>
    </cluster_property_set>'''

    def NewIP(self, name=None):
        template = ''' 
        <primitive id="%s" class="ocf" type="IPaddr" provider="heartbeat">
          <operations>
            <op id="mon-%s" name="monitor" interval="5s"/>
          </operations>
          <instance_attributes id="attrs-%s"><attributes>
              <nvpair id="netmask-%s" name="cidr_netmask" value="32"/>
              <nvpair id="ip-%s" name="ip" value="%s"/>
          </attributes></instance_attributes>
        </primitive> '''

        ip = self.NextIP()
        if not name:
            name = "r"+ip

        return template % (name, name, name, name, name, ip)

    def NewDummy(self, name):
        return self.dummy_resource_template % (name, name, name, name)

    def install(self, target):
        self.CM.rsh("localhost", "echo \'" + self.contents(target) + "\' > " + self.cib_tmpfile)
        rc = self.CM.rsh.cp(cib_file, "root@%s:%s/cib.xml" + (target, CTSvars.CRM_CONFIG_DIR))
        if rc != 0:
            raise ValueError("Can not copy %s to %s (%d)"%(self.cib_tmpfile, target, rc))

        self.CM.rsh(target, "chown "+CTSvars.CRM_DAEMON_USER+" "+CTSvars.CRM_CONFIG_DIR+"/cib.xml")
        self.CM.rsh("localhost", "rm -f "+self.cib_tmpfile)

    def contents(self, target=None):
        # fencing resource
        if self.cts_cib:
            return self.cts_cib            

        nodelist = ""
        num_nodes = 0
        for node in self.CM.Env["nodes"]:
            nodelist += node + " "
            num_nodes = num_nodes + 1

        no_quorum = "stop"
        if num_nodes < 3:
            no_quorum = "ignore"
            self.CM.debug("Cluster only has %d nodes, ignoring quorum" % num_nodes) 

        #make up crm config
        cib_options = self.cib_option_template % (self.CM.Env["DoFencing"], no_quorum)

        #create resources and their constraints
        resources = ""
        constraints = ""

        if self.CM.Env["DoBSC"] == 1:
            cib_options = cib_options + self.bsc_template

        if self.CM.Env["CIBResource"] != 1:
            # generate cib
            self.cts_cib = self.cib_template %  (cib_options, resources, constraints)
            return self.cts_cib

        if self.CM.cluster_monitor == 1:
            resources += self.clustermon_resource_template
            constraints += self.clustermon_location_constraint
            
        ip1_rsc = self.NewIP()
        ip2_rsc = self.NewIP() 
        ip3_rsc = self.NewIP() 
        resources += self.resource_group_template % (ip1_rsc, ip2_rsc, ip3_rsc)

        # lsb resource
        resources += self.lsb_resource

        # Mirgator
        resources += self.NewDummy("migrator")
        constraints += self.coloc_template % ("group-with-master", "group-1", "master-1", "Master", "INFINITY")
        constraints += self.coloc_template % ("lsb-with-group", "lsb_dummy", "group-1", "Started", "INFINITY")

        # per node resource
        for node in self.CM.Env["nodes"]:
            per_node_resources = self.NewIP("rsc_"+node)
            per_node_constraint = self.per_node_constraint_template % (node, "rsc_"+node, node)
                
            resources += per_node_resources
            constraints += per_node_constraint    

        # Ping the test master
        resources += self.pingd_resource_template % os.uname()[1]

        # Require conectivity to run
        constraints += self.pingd_constraint_template % ("master-1", "master-1", "m", "Started", "m", 1)

        if self.CM.Env["DoFencing"]:
            p_name = None
            p_value = None
            entries = string.split(self.CM.Env["stonith-params"], ',')
            for entry in entries:
                (p_name, p_value) = string.split(entry, '=')
                if p_name == "hostlist" and p_value == "all":
                    p_value = string.join(self.CM.Env["nodes"], " ")

            stonith_resource = self.stonith_resource_template % (self.CM.Env["stonith-type"], p_name, p_value)
            resources += stonith_resource
        
        #master slave resource
        resources += self.master_slave_resource % (num_nodes, 1, 1, 1)

        # generate cib
        self.cts_cib = self.cib_template % (cib_options, resources, constraints)
        return self.cts_cib


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
        fixed = "CIB_file="+self.cib_tmpfile+" crm configure " + command 
        rc = self.CM.rsh(self.target, fixed)
        if rc != 0:
            self.CM.log("Configure call failed: "+fixed)
            sys.exit(1)

    def _show(self, command=""):
        output = ""
        (rc, result) = self.CM.rsh(self.target, "CIB_file="+self.cib_tmpfile+" crm configure show "+command, None, )
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

        cib_base = self.cib_template % (self.feature_set, self.version, ''' remote-tls-port='9898' ''')
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
            self.CM.debug("Cluster only has %d nodes, ignoring quorum" % self.num_nodes) 

        self._create('''property start-failure-is-fatal=false pe-input-series-max=5000''')
        self._create('''property shutdown-escalation=5min startup-fencing=false batch-limit=10''')
        self._create('''property no-quorum-policy=%s stonith-enabled=%s''' % (no_quorum, self.CM.Env["DoFencing"]))
        self._create('''property expected-quorum-votes=%d''' % self.num_nodes)

        if self.CM.Env["DoBSC"] == 1:
            self._create('''property ident-string="Linux-HA TEST configuration file - REMOVEME!!"''')

        # Add resources?
        if self.CM.Env["CIBResource"] == 1:
            self.add_resources()

        # Fencing resource
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

            self._create('''primitive FencingChild stonith::%s %s livedangerously=yes op monitor interval=120s timeout=300 op start interval=0 timeout=180s op stop interval=0 timeout=180s''' % (self.CM.Env["stonith-type"], params))
            # Set a threshold for unreliable stonith devices such as the vmware one
            self._create('''clone Fencing FencingChild meta globally-unique=false migration-threshold=5''')
        
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
        ip = self.NextIP()
        r2 = self.NewIP()
        ip = self.NextIP()
        r3 = self.NewIP()
        self._create('''group group-1 %s %s %s''' % (r1, r2, r3))

        # Per-node resources
        for node in self.CM.Env["nodes"]:
            r = self.NewIP("rsc_"+node)
            self._create('''location prefer-%s %s rule 100: \#uname eq %s''' % (node, r, node))
                
        # LSB resource
        self._create('''primitive lsb-dummy lsb::''' +CTSvars.CTS_home+ '''/LSBDummy op monitor interval=5s''')
        self._create('''colocation lsb-with-group INFINITY: lsb-dummy group-1''')
        self._create('''order lsb-after-group mandatory: group-1 lsb-dummy symmetrical=true''')

        # Migrator
        self._create('''primitive migrator ocf:pacemaker:Dummy meta allow-migrate=1 op monitor interval=10s''')

        # Ping the test master
        self._create('''primitive ping-1 ocf:pacemaker:pingd params host_list=%s name=connected op monitor interval=120s''' % os.uname()[1])
        self._create('''clone Connectivity ping-1 meta globally-unique=false''')

        #master slave resource
        self._create('''primitive stateful-1 ocf:pacemaker:Stateful op monitor interval=15s op monitor interval=16s role=Master''')
        self._create('''ms master-1 stateful-1 meta clone-max=%d clone-node-max=%d master-max=%d master-node-max=%d'''
                     % (self.num_nodes, 1, 1, 1))

        # Require conectivity to run the master
        self._create('''location %s-is-connected %s rule -INFINITY: connected lt %d''' % ("m1", "master-1", 1))

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
        self.register("pacemaker06", CIB06, CM)
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
        if name == "pacemaker-0.6":
            name = "pacemaker06";
        elif name == "pacemaker-1.0":
            name = "pacemaker10";
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
