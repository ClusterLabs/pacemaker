Configuration Recap
-------------------

Final Cluster Configuration
###########################

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource
      * ClusterIP	(ocf::heartbeat:IPaddr2):	 Started pcmk-1
      * WebSite	(ocf::heartbeat:apache):	 Started pcmk-1
      * Clone Set: WebData-clone [WebData] (promotable):
        * Masters: [ pcmk-1 pcmk-2 ]
      * Clone Set: dlm-clone [dlm]:
        * Started: [ pcmk-1 pcmk-2 ]
      * Clone Set: WebFS-clone [WebFS]:
        * Started: [ pcmk-1 pcmk-2 ]

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource op defaults
    Meta Attrs: op_defaults-meta_attributes
      timeout=240s

.. code-block:: none

    [root@pcmk-1 ~]# pcs stonith
      * ipmi-fencing	(stonith:fence_ipmilan): 	Started pcmk-1

.. code-block:: none

    [root@pcmk-1 ~]# pcs constraint
    Location Constraints:
    Ordering Constraints:
      start ClusterIP then start WebSite (kind:Mandatory)
      promote WebDataClone then start WebFS-clone (kind:Mandatory)
      start WebFS-clone then start WebSite (kind:Mandatory)
      start dlm-clone then start WebFS-clone (kind:Mandatory)
    Colocation Constraints:
      WebSite with ClusterIP (score:INFINITY)
      WebFS-clone with WebDataClone (score:INFINITY) (with-rsc-role:Master)
      WebSite with WebFS-clone (score:INFINITY)
      WebFS-clone with dlm-clone (score:INFINITY)
    Ticket Constraints:

.. code-block:: none

    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Stack: corosync
    Current DC: pcmk-1 (version 1.1.18-11.el7_5.3-2b07d5c5a9) - partition with quorum
    Last updated: Fri Jul 16 09:00:56 2021
    Last change: Wed Jul 14 11:06:25 2021 by root via cibadmin on pcmk-1

    2 nodes configured
    11 resources configured

    Online: [ pcmk-1 pcmk-2 ]

    Full List of Resources:
      * ipmi-fencing	(stonith:fence_ipmilan):	 Stopped
      * ClusterIP	(ocf::heartbeat:IPaddr2):	 Started pcmk-1
      * WebSite	(ocf::heartbeat:apache):	 Started pcmk-1
      * Clone Set: WebData-clone [WebData] (promotable):
        * Masters: [ pcmk-1 pcmk-2 ]
      * Clone Set: dlm-clone [dlm]:
        * Started: [ pcmk-1 pcmk-2 ]
      * Clone Set: WebFS-clone [WebFS]:
        * Started: [ pcmk-1 pcmk-2 ]

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled

.. code-block:: none

    [root@pcmk-1 ~]# pcs cluster cib --config

.. code-block:: xml

    <configuration>
      <crm_config>
        <cluster_property_set id="cib-bootstrap-options">
          <nvpair id="cib-bootstrap-options-stonith-enabled" name="stonith-enabled" value="true"/>
          <nvpair id="cib-bootstrap-options-have-watchdog" name="have-watchdog" value="false"/>
          <nvpair id="cib-bootstrap-options-dc-version" name="dc-version" value="2.1.0-3.el8-7c3f660707"/>
          <nvpair id="cib-bootstrap-options-cluster-infrastructure" name="cluster-infrastructure" value="corosync"/>
          <nvpair id="cib-bootstrap-options-cluster-name" name="cluster-name" value="mycluster"/>
          <nvpair id="cib-bootstrap-options-no-quorum-policy" name="no-quorum-policy" value="freeze"/>
        </cluster_property_set>
      </crm_config>
      <nodes>
        <node id="1" uname="pcmk-1"/>
        <node id="2" uname="pcmk-2"/>
      </nodes>
      <resources>
        <primitive class="stonith" id="ipmi-fencing" type="fence_ipmilan">
          <instance_attributes id="ipmi-fencing-instance_attributes">
            <nvpair id="ipmi-fencing-instance_attributes-ipaddr" name="ipaddr" value="10.0.0.1"/>
            <nvpair id="ipmi-fencing-instance_attributes-login" name="login" value="testuser"/>
            <nvpair id="ipmi-fencing-instance_attributes-passwd" name="passwd" value="acd123"/>
            <nvpair id="ipmi-fencing-instance_attributes-pcmk_host_list" name="pcmk_host_list" value="pcmk-1 pcmk-2"/>
          </instance_attributes>
          <operations>
            <op id="ipmi-fencing-monitor-interval-60s" interval="60s" name="monitor"/>
          </operations>
        </primitive>
        <primitive class="ocf" id="ClusterIP" provider="heartbeat" type="IPaddr2">
          <instance_attributes id="ClusterIP-instance_attributes">
            <nvpair id="ClusterIP-instance_attributes-cidr_netmask" name="cidr_netmask" value="24"/>
            <nvpair id="ClusterIP-instance_attributes-ip" name="ip" value="192.168.122.120"/>
          </instance_attributes>
          <operations>
            <op id="ClusterIP-monitor-interval-30s" interval="30s" name="monitor"/>
            <op id="ClusterIP-start-interval-0s" interval="0s" name="start" timeout="20s"/>
            <op id="ClusterIP-stop-interval-0s" interval="0s" name="stop" timeout="20s"/>
          </operations>
        </primitive>
        <primitive class="ocf" id="WebSite" provider="heartbeat" type="apache">
          <instance_attributes id="WebSite-instance_attributes">
            <nvpair id="WebSite-instance_attributes-configfile" name="configfile" value="/etc/httpd/conf/httpd.conf"/>
            <nvpair id="WebSite-instance_attributes-statusurl" name="statusurl" value="http://localhost/server-status"/>
          </instance_attributes>
          <operations>
            <op id="WebSite-monitor-interval-1min" interval="1min" name="monitor"/>
            <op id="WebSite-start-interval-0s" interval="0s" name="start" timeout="40s"/>
            <op id="WebSite-stop-interval-0s" interval="0s" name="stop" timeout="60s"/>
          </operations>
        </primitive>
        <clone id="WebData-clone">
          <primitive class="ocf" id="WebData" provider="linbit" type="drbd">
            <instance_attributes id="WebData-instance_attributes">
              <nvpair id="WebData-instance_attributes-drbd_resource" name="drbd_resource" value="wwwdata"/>
            </instance_attributes>
            <operations>
              <op id="WebData-demote-interval-0s" interval="0s" name="demote" timeout="90"/>
              <op id="WebData-monitor-interval-60s" interval="60s" name="monitor"/>
              <op id="WebData-notify-interval-0s" interval="0s" name="notify" timeout="90"/>
              <op id="WebData-promote-interval-0s" interval="0s" name="promote" timeout="90"/>
              <op id="WebData-reload-interval-0s" interval="0s" name="reload" timeout="30"/>
              <op id="WebData-start-interval-0s" interval="0s" name="start" timeout="240"/>
              <op id="WebData-stop-interval-0s" interval="0s" name="stop" timeout="100"/>
            </operations>
          </primitive>
          <meta_attributes id="WebData-clone-meta_attributes">
            <nvpair id="WebData-clone-meta_attributes-clone-max" name="clone-max" value="2"/>
            <nvpair id="WebData-clone-meta_attributes-clone-node-max" name="clone-node-max" value="1"/>
            <nvpair id="WebData-clone-meta_attributes-notify" name="notify" value="true"/>
            <nvpair id="WebData-clone-meta_attributes-promotable" name="promotable" value="true"/>
            <nvpair id="WebData-clone-meta_attributes-promoted-max" name="promoted-max" value="2"/>
            <nvpair id="WebData-clone-meta_attributes-promoted-node-max" name="promoted-node-max" value="1"/>
          </meta_attributes>
        </clone>
        <clone id="dlm-clone">
          <primitive class="ocf" id="dlm" provider="pacemaker" type="controld">
            <operations>
              <op id="dlm-monitor-interval-60s" interval="60s" name="monitor"/>
              <op id="dlm-start-interval-0s" interval="0s" name="start" timeout="90s"/>
              <op id="dlm-stop-interval-0s" interval="0s" name="stop" timeout="100s"/>
            </operations>
          </primitive>
          <meta_attributes id="dlm-clone-meta_attributes">
            <nvpair id="dlm-clone-meta_attributes-clone-max" name="clone-max" value="2"/>
            <nvpair id="dlm-clone-meta_attributes-clone-node-max" name="clone-node-max" value="1"/>
          </meta_attributes>
        </clone>
        <clone id="WebFS-clone">
          <primitive class="ocf" id="WebFS" provider="heartbeat" type="Filesystem">
            <meta_attributes id="WebFS-meta_attributes"/>
            <instance_attributes id="WebFS-instance_attributes">
              <nvpair id="WebFS-instance_attributes-device" name="device" value="/dev/drbd1"/>
              <nvpair id="WebFS-instance_attributes-directory" name="directory" value="/var/www/html"/>
              <nvpair id="WebFS-instance_attributes-fstype" name="fstype" value="gfs2"/>
            </instance_attributes>
            <operations>
              <op id="WebFS-monitor-interval-20s" interval="20s" name="monitor" timeout="40s"/>
              <op id="WebFS-notify-interval-0s" interval="0s" name="notify" timeout="60"/>
              <op id="WebFS-start-interval-0s" interval="0s" name="start" timeout="60s"/>
              <op id="WebFS-stop-interval-0s" interval="0s" name="stop" timeout="60s"/>
            </operations>
          </primitive>
        </clone>
      </resources>
      <constraints>
        <rsc_colocation id="colocation-WebSite-ClusterIP-INFINITY" rsc="WebSite" score="INFINITY" with-rsc="ClusterIP"/>
        <rsc_order first="ClusterIP" first-action="start" id="order-ClusterIP-WebSite-mandatory" then="WebSite" then-action="start"/>
        <rsc_location id="location-WebSite-pcmk-1-50" node="pcmk-1" rsc="WebSite" score="50"/>
        <rsc_colocation id="colocation-WebFS-WebData-clone-INFINITY" rsc="WebFS-clone" score="INFINITY" with-rsc="WebData-clone" with-rsc-role="Master"/>
        <rsc_order first="WebData-clone" first-action="promote" id="order-WebData-clone-WebFS-mandatory" then="WebFS-clone" then-action="start"/>
        <rsc_colocation id="colocation-WebSite-WebFS-INFINITY" rsc="WebSite" score="INFINITY" with-rsc="WebFS-clone"/>
        <rsc_order first="WebFS-clone" first-action="start" id="order-WebFS-WebSite-mandatory" then="WebSite" then-action="start"/>
      </constraints>
      <op_defaults>
        <meta_attributes id="op_defaults-meta_attributes">
          <nvpair id="op_defaults-meta_attributes-timeout" name="timeout" value="240s"/>
        </meta_attributes>
      </op_defaults>
    </configuration>

Node List
#########

.. code-block:: none

    [root@pcmk-1 ~]# pcs status nodes
    Pacemaker Nodes:
     Online: pcmk-1 pcmk-2
     Standby:
     Standby with resource(s) running:
     Maintenance:
     Offline:
    Pacemaker Remote Nodes:
     Online:
     Standby:
     Standby with resource(s) running:
     Maintenance:
     Offline:

Cluster Options
###############

.. code-block:: none

    [root@pcmk-1 ~]# pcs property
    Cluster Properties:
     cluster-infrastructure: corosync
     cluster-name: mycluster
     dc-version: 2.1.0-3.el8-7c3f660707
     have-watchdog: false
     no-quorum-policy: freeze
     stonith-enabled: true

The output shows state information automatically obtained about the cluster, including:

* **cluster-infrastructure** - the cluster communications layer in use
* **cluster-name** - the cluster name chosen by the administrator when the cluster was created
* **dc-version** - the version (including upstream source-code hash) of Pacemaker
  used on the Designated Controller, which is the node elected to determine what
  actions are needed when events occur

The output also shows options set by the administrator that control the way the cluster operates, including:

* **stonith-enabled=true** - whether the cluster is allowed to use STONITH resources

Resources
#########

Default Options
_______________

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource defaults
    resource-stickiness: 100

This shows cluster option defaults that apply to every resource that does not
explicitly set the option itself. Above:

* **resource-stickiness** - Specify how strongly a resource prefers to remain
  on its current node. Alternatively, you can view this as the level of
  aversion to moving healthy resources to other machines.

Fencing
_______

.. code-block:: none

    [root@pcmk-1 ~]# pcs stonith status
      * impi-fencing	(stonith:fence_ipmilan): 	Started pcmk-1
    [root@pcmk-1 ~]# pcs stonith config
    Resource: ipmi-fencing (class=stonith type=fence_ipmilan)
      Attributes: ipaddr=10.0.0.1 login=testuser passwd=acd123 pcmk_host_list="pcmk-1 pcmk-2"
      Operations: monitor interval=60s (ipmi-fencing-monitor-interval-60s)

Service Address
_______________

Users of the services provided by the cluster require an unchanging
address with which to access it.

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource config ClusterIP
    Resource: ClusterIP (class=ocf provider=heartbeat type=IPaddr2)
      Attributes: cidr_netmask=24 ip=192.168.122.120
      Meta Attrs: resource-stickiness=0
      Operations: monitor interval=30s (ClusterIP-monitor-interval-30s)
                  start interval=0s timeout=20s (ClusterIP-start-interval-0s)
                  stop interval=0s timeout=20s (ClusterIP-stop-interval-0s)

DRBD - Shared Storage
_____________________

Here, we define the DRBD service and specify which DRBD resource (from
/etc/drbd.d/\*.res) it should manage. We make it a promotable clone resource
and, in order to have an active/active setup, allow both instances to be
promoted at the same time. We also set the notify option so that the cluster
will tell DRBD agent when its peer changes state.

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource show WebData-clone
     Clone: WebData-clone
      Meta Attrs: clone-max=2 clone-node-max=1 notify=true promotable=true promoted-max=2 promoted-node-max=1
      Resource: WebData (class=ocf provider=linbit type=drbd)
      Attributes: drbd_resource=wwwdata
      Operations: demote interval=0s timeout=90 (WebData-demote-interval-0s)
                  monitor interval=60s (WebData-monitor-interval-60s)
                  notify interval=0s timeout=90 (WebData-notify-interval-0s)
                  promote interval=0s timeout=90 (WebData-promote-interval-0s)
                  reload interval=0s timeout=30 (WebData-reload-interval-0s)
                  start interval=0s timeout=240 (WebData-start-interval-0s)
                  stop interval=0s timeout=100 (WebData-stop-interval-0s)
    [root@pcmk-1 ~]# pcs constraint ref WebData-clone
    Resource: WebData-clone
      colocation-WebFS-WebDataClone-INFINITY
      order-WebDataClone-WebFS-mandatory

Cluster Filesystem
__________________

The cluster filesystem ensures that files are read and written correctly.
We need to specify the block device (provided by DRBD), where we want it
mounted and that we are using GFS2. Again, it is a clone because it is
intended to be active on both nodes. The additional constraints ensure
that it can only be started on nodes with active DLM and DRBD instances.

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource show WebFS-clone
     Clone: WebFS-clone
      Resource: WebFS (class=ocf provider=heartbeat type=Filesystem)
       Attributes: device=/dev/drbd1 directory=/var/www/html fstype=gfs2
       Operations: monitor interval=20 timeout=40 (WebFS-monitor-interval-20)
                   notify interval=0s timeout=60 (WebFS-notify-interval-0s)
                   start interval=0s timeout=60 (WebFS-start-interval-0s)
                   stop interval=0s timeout=60 (WebFS-stop-interval-0s)
    [root@pcmk-1 ~]# pcs constraint ref WebFS-clone
    Resource: WebFS-clone
      colocation-WebFS-WebDataClone-INFINITY
      colocation-WebSite-WebFS-INFINITY
      colocation-WebFS-dlm-clone-INFINITY
      order-WebDataClone-WebFS-mandatory
      order-WebFS-WebSite-mandatory
      order-dlm-clone-WebFS-mandatory

Apache
______

Lastly, we have the actual service, Apache. We need only tell the cluster
where to find its main configuration file and restrict it to running on
a node that has the required filesystem mounted and the IP address active.

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource show WebSite
    Resource: WebSite (class=ocf provider=heartbeat type=apache)
     Attributes: configfile=/etc/httpd/conf/httpd.conf statusurl=http://localhost/server-status
     Operations: monitor interval=1min (WebSite-monitor-interval-1min)
                 start interval=0s timeout=40s (WebSite-start-interval-0s)
                 stop interval=0s timeout=60s (WebSite-stop-interval-0s)
    [root@pcmk-1 ~]# pcs constraint ref WebSite
    Resource: WebSite
      colocation-WebSite-ClusterIP-INFINITY
      colocation-WebSite-WebFS-INFINITY
      order-ClusterIP-WebSite-mandatory
      order-WebFS-WebSite-mandatory
