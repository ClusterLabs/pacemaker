Start and Verify Cluster
------------------------

Start the Cluster
#################

Now that corosync is configured, it is time to start the cluster.
The command below will start corosync and pacemaker on both nodes
in the cluster.

.. code-block:: none

    [root@pcmk-1 ~]# pcs cluster start --all
    pcmk-1: Starting Cluster...
    pcmk-2: Starting Cluster...

.. NOTE::

    An alternative to using the ``pcs cluster start --all`` command
    is to issue either of the below command sequences on each node in the
    cluster separately:

    .. code-block:: none

        # pcs cluster start
        Starting Cluster...

    or

    .. code-block:: none

        # systemctl start corosync.service
        # systemctl start pacemaker.service

.. IMPORTANT::

    In this example, we are not enabling the corosync and pacemaker services
    to start at boot. If a cluster node fails or is rebooted, you will need to
    run ``pcs cluster start [<NODENAME> | --all]`` to start the cluster on it.
    While you can enable the services to start at boot (for example, using
    ``pcs cluster enable [<NODENAME> | --all]``), requiring a manual start of
    cluster services gives you the opportunity to do a post-mortem
    investigation of a node failure before returning it to the cluster.

Verify Corosync Installation
############################

First, use ``corosync-cfgtool`` to check whether cluster communication is happy:

.. code-block:: none

    [root@pcmk-1 ~]# corosync-cfgtool -s
    Printing link status.
    Local node ID 1
    LINK ID 0
	    addr	= 192.168.122.101
	    status:
		    nodeid  1:	localhost
		    nodeid  2:	connected

We can see here that everything appears normal with our fixed IP
address (not a 127.0.0.x loopback address) listed as the **addr**, and **localhost** and **connected** for the statuses of nodeid 1 and nodeid 2, respectively.

If you see something different, you might want to start by checking
the node's network, firewall, and SELinux configurations.

Next, check the membership and quorum APIs:

.. code-block:: none

    [root@pcmk-1 ~]# corosync-cmapctl | grep members 
    runtime.members.1.config_version (u64) = 0
    runtime.members.1.ip (str) = r(0) ip(192.168.122.101) 
    runtime.members.1.join_count (u32) = 1
    runtime.members.1.status (str) = joined
    runtime.members.2.config_version (u64) = 0
    runtime.members.2.ip (str) = r(0) ip(192.168.122.102) 
    runtime.members.2.join_count (u32) = 1
    runtime.members.2.status (str) = joined
    [root@pcmk-1 ~]# pcs status corosync 

    Membership information
    ----------------------
        Nodeid      Votes Name
             1          1 pcmk-1 (local)
             2          1 pcmk-2

You should see both nodes have joined the cluster.

Verify Pacemaker Installation
#############################

Now that we have confirmed that Corosync is functional, we can check
the rest of the stack. Pacemaker has already been started, so verify
the necessary processes are running:

.. code-block:: none

    [root@pcmk-1 ~]# ps axf
      PID TTY      STAT   TIME COMMAND
        2 ?        S      0:00 [kthreadd]
    ...lots of processes...
    17121 ?        SLsl   0:01 /usr/sbin/corosync -f
    17133 ?        Ss     0:00 /usr/sbin/pacemakerd
    17134 ?        Ss     0:00  \_ /usr/libexec/pacemaker/pacemaker-based
    17135 ?        Ss     0:00  \_ /usr/libexec/pacemaker/pacemaker-fenced
    17136 ?        Ss     0:00  \_ /usr/libexec/pacemaker/pacemaker-execd
    17137 ?        Ss     0:00  \_ /usr/libexec/pacemaker/pacemaker-attrd
    17138 ?        Ss     0:00  \_ /usr/libexec/pacemaker/pacemaker-schedulerd
    17139 ?        Ss     0:00  \_ /usr/libexec/pacemaker/pacemaker-controld

If that looks OK, check the ``pcs status`` output:

.. code-block:: none

    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    
    WARNINGS:
    No stonith devices and stonith-enabled is not false
    
    Cluster Summary:
      * Stack: corosync
      * Current DC: pcmk-2 (version 2.0.5-4.el8-ba59be7122) - partition with quorum
      * Last updated: Wed Jan 20 07:54:02 2021
      * Last change:  Wed Jan 20 07:48:25 2021 by hacluster via crmd on pcmk-2
      * 2 nodes configured
      * 0 resource instances configured
    
    Node List:
      * Online: [ pcmk-1 pcmk-2 ]
    
    Full List of Resources:
      * No resources

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled

Finally, ensure there are no start-up errors from corosync or pacemaker (aside
from messages relating to not having STONITH configured, which are OK at this
point):

.. code-block:: none

    [root@pcmk-1 ~]# journalctl -b | grep -i error

.. NOTE::

    Other operating systems may report startup errors in other locations
    (for example, ``/var/log/messages``).

Repeat these checks on the other node. The results should be the same.

Explore the Existing Configuration
##################################

For those who are not of afraid of XML, you can see the raw cluster
configuration and status by using the ``pcs cluster cib`` command.

.. topic:: The last XML you'll see in this document

    .. code-block:: none

        [root@pcmk-1 ~]# pcs cluster cib

    .. code-block:: xml

        <cib crm_feature_set="3.7.1" validate-with="pacemaker-3.6" epoch="5" num_updates="4" admin_epoch="0" cib-last-written="Tue Feb 16 16:20:57 2021" update-origin="pcmk-1" update-client="crmd" update-user="hacluster" have-quorum="1" dc-uuid="1">
          <configuration>
            <crm_config>
              <cluster_property_set id="cib-bootstrap-options">
                <nvpair id="cib-bootstrap-options-have-watchdog" name="have-watchdog" value="false"/>
                <nvpair id="cib-bootstrap-options-dc-version" name="dc-version" value="2.0.5-7.el8-ba59be7122"/>
                <nvpair id="cib-bootstrap-options-cluster-infrastructure" name="cluster-infrastructure" value="corosync"/>
                <nvpair id="cib-bootstrap-options-cluster-name" name="cluster-name" value="mycluster"/>
              </cluster_property_set>
            </crm_config>
            <nodes>
              <node id="1" uname="pcmk-1"/>
              <node id="2" uname="pcmk-2"/>
            </nodes>
            <resources/>
            <constraints/>
          </configuration>
          <status>
            <node_state id="2" uname="pcmk-2" in_ccm="true" crmd="online" crm-debug-origin="do_state_transition" join="member" expected="member">
              <lrm id="2">
                <lrm_resources/>
              </lrm>
            </node_state>
            <node_state id="1" uname="pcmk-1" in_ccm="true" crmd="online" crm-debug-origin="do_state_transition" join="member" expected="member">
              <lrm id="1">
                <lrm_resources/>
              </lrm>
            </node_state>
          </status>
        </cib>

Before we make any changes, it's a good idea to check the validity of
the configuration.

.. code-block:: none

    [root@pcmk-1 ~]# pcs cluster verify --full
    Error: invalid cib:
    (unpack_resources) 	error: Resource start-up disabled since no STONITH resources have been defined
    (unpack_resources) 	error: Either configure some or disable STONITH with the stonith-enabled option
    (unpack_resources) 	error: NOTE: Clusters with shared data need STONITH to ensure data integrity
    crm_verify: Errors found during check: config not valid

    Error: Errors have occurred, therefore pcs is unable to continue

As you can see, the tool has found some errors. The cluster will not start any
resources until we configure STONITH.
