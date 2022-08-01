Configuration Recap
-------------------

Final Cluster Configuration
###########################

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource
      * ClusterIP	(ocf:heartbeat:IPaddr2):	 Started pcmk-1
      * WebSite	(ocf:heartbeat:apache):	 Started pcmk-1
      * Clone Set: WebData-clone [WebData] (promotable):
        * Promoted: [ pcmk-1 pcmk-2 ]
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
      * fence_dev	(stonith:some_fence_agent):	 Started pcmk-1

.. code-block:: none

    [root@pcmk-1 ~]# pcs constraint
    Location Constraints:
      Resource: WebSite
        Enabled on:
          Node: pcmk-2 (score:50)
    Ordering Constraints:
      start ClusterIP then start WebSite (kind:Mandatory)
      promote WebData-clone then start WebFS-clone (kind:Mandatory)
      start WebFS-clone then start WebSite (kind:Mandatory)
      start dlm-clone then start WebFS-clone (kind:Mandatory)
    Colocation Constraints:
      WebSite with ClusterIP (score:INFINITY)
      WebFS-clone with WebData-clone (score:INFINITY) (rsc-role:Started) (with-rsc-role:Promoted)
      WebSite with WebFS-clone (score:INFINITY)
      WebFS-clone with dlm-clone (score:INFINITY)
    Ticket Constraints:

.. code-block:: none

    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync
      * Current DC: pcmk-1 (version 2.1.2-4.el9-ada5c3b36e2) - partition with quorum
      * Last updated: Wed Jul 27 08:57:57 2022
      * Last change:  Wed Jul 27 08:55:00 2022 by root via cibadmin on pcmk-1
      * 2 nodes configured
      * 9 resource instances configured

    Node List:
      * Online: [ pcmk-1 pcmk-2 ]

    Full List of Resources:
      * fence_dev	(stonith:some_fence_agent):	 Started pcmk-1
      * ClusterIP	(ocf:heartbeat:IPaddr2):	 Started pcmk-1
      * WebSite	(ocf:heartbeat:apache):	 Started pcmk-1
      * Clone Set: WebData-clone [WebData] (promotable):
        * Promoted: [ pcmk-1 pcmk-2 ]
      * Clone Set: dlm-clone [dlm]:
        * Started: [ pcmk-1 pcmk-2 ]
      * Clone Set: WebFS-clone [WebFS]:
        * Started: [ pcmk-1 pcmk-2 ]

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled

.. code-block:: none

    [root@pcmk-1 ~]# pcs config
    Cluster Name: mycluster
    Corosync Nodes:
     pcmk-1 pcmk-2
    Pacemaker Nodes:
     pcmk-1 pcmk-2
    
    Resources:
     Resource: ClusterIP (class=ocf provider=heartbeat type=IPaddr2)
      Attributes: cidr_netmask=24 ip=192.168.122.120
      Operations: monitor interval=30s (ClusterIP-monitor-interval-30s)
                  start interval=0s timeout=20s (ClusterIP-start-interval-0s)
                  stop interval=0s timeout=20s (ClusterIP-stop-interval-0s)
     Resource: WebSite (class=ocf provider=heartbeat type=apache)
      Attributes: configfile=/etc/httpd/conf/httpd.conf statusurl=http://localhost/server-status
      Operations: monitor interval=1min (WebSite-monitor-interval-1min)
                  start interval=0s timeout=40s (WebSite-start-interval-0s)
                  stop interval=0s timeout=60s (WebSite-stop-interval-0s)
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
     Clone: dlm-clone
      Meta Attrs: interleave=true ordered=true
      Resource: dlm (class=ocf provider=pacemaker type=controld)
       Operations: monitor interval=60s (dlm-monitor-interval-60s)
                   start interval=0s timeout=90s (dlm-start-interval-0s)
                   stop interval=0s timeout=100s (dlm-stop-interval-0s)
     Clone: WebFS-clone
      Resource: WebFS (class=ocf provider=heartbeat type=Filesystem)
       Attributes: device=/dev/drbd1 directory=/var/www/html fstype=gfs2
       Operations: monitor interval=20s timeout=40s (WebFS-monitor-interval-20s)
                   start interval=0s timeout=60s (WebFS-start-interval-0s)
                   stop interval=0s timeout=60s (WebFS-stop-interval-0s)
    
    Stonith Devices:
     Resource: fence_dev (class=stonith type=some_fence_agent)
      Attributes: pcmk_delay_base=pcmk-1:5s;pcmk-2:0s pcmk_host_map=pcmk-1:almalinux9-1;pcmk-2:almalinux9-2
      Operations: monitor interval=60s (fence_dev-monitor-interval-60s)
    Fencing Levels:
    
    Location Constraints:
      Resource: WebSite
        Enabled on:
          Node: pcmk-2 (score:50) (id:location-WebSite-pcmk-2-50)
    Ordering Constraints:
      start ClusterIP then start WebSite (kind:Mandatory) (id:order-ClusterIP-WebSite-mandatory)
      promote WebData-clone then start WebFS-clone (kind:Mandatory) (id:order-WebData-clone-WebFS-mandatory)
      start WebFS-clone then start WebSite (kind:Mandatory) (id:order-WebFS-WebSite-mandatory)
      start dlm-clone then start WebFS-clone (kind:Mandatory) (id:order-dlm-clone-WebFS-mandatory)
    Colocation Constraints:
      WebSite with ClusterIP (score:INFINITY) (id:colocation-WebSite-ClusterIP-INFINITY)
      WebFS-clone with WebData-clone (score:INFINITY) (rsc-role:Started) (with-rsc-role:Promoted) (id:colocation-WebFS-WebData-clone-INFINITY)
      WebSite with WebFS-clone (score:INFINITY) (id:colocation-WebSite-WebFS-INFINITY)
      WebFS-clone with dlm-clone (score:INFINITY) (id:colocation-WebFS-dlm-clone-INFINITY)
    Ticket Constraints:
    
    Alerts:
     No alerts defined
    
    Resources Defaults:
      Meta Attrs: build-resource-defaults
        resource-stickiness=100
    Operations Defaults:
      Meta Attrs: op_defaults-meta_attributes
        timeout=240s
    
    Cluster Properties:
     cluster-infrastructure: corosync
     cluster-name: mycluster
     dc-version: 2.1.2-4.el9-ada5c3b36e2
     have-watchdog: false
     last-lrm-refresh: 1658896047
     no-quorum-policy: freeze
     stonith-enabled: true
    
    Tags:
     No tags defined
    
    Quorum:
      Options:

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
     dc-version: 2.1.2-4.el9-ada5c3b36e2
     have-watchdog: false
     no-quorum-policy: freeze
     stonith-enabled: true

The output shows cluster-wide configuration options, as well as some baseline-
level state information. The output includes:

* **cluster-infrastructure** - the cluster communications layer in use
* **cluster-name** - the cluster name chosen by the administrator when the cluster was created
* **dc-version** - the version (including upstream source-code hash) of Pacemaker
  used on the Designated Controller, which is the node elected to determine what
  actions are needed when events occur
* **have-watchdog** - whether watchdog integration is enabled; set
  automatically when SBD is enabled
* **stonith-enabled=true** - whether the cluster is allowed to use STONITH resources

.. NOTE::

    This command is equivalent to ``pcs property config``.

Resources
#########

Default Options
_______________

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource defaults
    Meta Attrs: build-resource-defaults
      resource-stickiness=100

This shows cluster option defaults that apply to every resource that does not
explicitly set the option itself. Above:

* **resource-stickiness** - Specify how strongly a resource prefers to remain
  on its current node. Alternatively, you can view this as the level of
  aversion to moving healthy resources to other machines.

Fencing
_______

.. code-block:: none

    [root@pcmk-1 ~]# pcs stonith status
      * fence_dev	(stonith:some_fence_agent):	 Started pcmk-1
    [root@pcmk-1 ~]# pcs stonith config
     Resource: fence_dev (class=stonith type=some_fence_agent)
      Attributes: pcmk_delay_base=pcmk-1:5s;pcmk-2:0s pcmk_host_map=pcmk-1:almalinux9-1;pcmk-2:almalinux9-2
      Operations: monitor interval=60s (fence_dev-monitor-interval-60s)

Service Address
_______________

Users of the services provided by the cluster require an unchanging
address with which to access it.

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource config ClusterIP
     Resource: ClusterIP (class=ocf provider=heartbeat type=IPaddr2)
      Attributes: cidr_netmask=24 ip=192.168.122.120
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

    [root@pcmk-1 ~]# pcs resource config WebData-clone
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
      colocation-WebFS-WebData-clone-INFINITY
      order-WebData-clone-WebFS-mandatory

Cluster Filesystem
__________________

The cluster filesystem ensures that files are read and written correctly.
We need to specify the block device (provided by DRBD), where we want it
mounted and that we are using GFS2. Again, it is a clone because it is
intended to be active on both nodes. The additional constraints ensure
that it can only be started on nodes with active DLM and DRBD instances.

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource config WebFS-clone
     Clone: WebFS-clone
      Resource: WebFS (class=ocf provider=heartbeat type=Filesystem)
       Attributes: device=/dev/drbd1 directory=/var/www/html fstype=gfs2
       Operations: monitor interval=20s timeout=40s (WebFS-monitor-interval-20s)
                   start interval=0s timeout=60s (WebFS-start-interval-0s)
                   stop interval=0s timeout=60s (WebFS-stop-interval-0s)
    [root@pcmk-1 ~]# pcs constraint ref WebFS-clone
    Resource: WebFS-clone
      colocation-WebFS-WebData-clone-INFINITY
      colocation-WebSite-WebFS-INFINITY
      colocation-WebFS-dlm-clone-INFINITY
      order-WebData-clone-WebFS-mandatory
      order-WebFS-WebSite-mandatory
      order-dlm-clone-WebFS-mandatory

Apache
______

Lastly, we have the actual service, Apache. We need only tell the cluster
where to find its main configuration file and restrict it to running on
a node that has the required filesystem mounted and the IP address active.

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource config WebSite
     Resource: WebSite (class=ocf provider=heartbeat type=apache)
      Attributes: configfile=/etc/httpd/conf/httpd.conf statusurl=http://localhost/server-status
      Operations: monitor interval=1min (WebSite-monitor-interval-1min)
                  start interval=0s timeout=40s (WebSite-start-interval-0s)
                  stop interval=0s timeout=60s (WebSite-stop-interval-0s)
    [root@pcmk-1 ~]# pcs constraint ref WebSite
    Resource: WebSite
      colocation-WebSite-ClusterIP-INFINITY
      colocation-WebSite-WebFS-INFINITY
      location-WebSite-pcmk-2-50
      order-ClusterIP-WebSite-mandatory
      order-WebFS-WebSite-mandatory
