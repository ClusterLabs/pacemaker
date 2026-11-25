Start and Verify Cluster
------------------------

Start the Cluster
#################

Now that Corosync is configured, it is time to start the cluster.
The command below will start the ``corosync`` and ``pacemaker`` services on
both nodes in the cluster.

.. code-block:: console

    [root@pcmk-1 ~]# pcs cluster start --all
    pcmk-1: Starting Cluster...
    pcmk-2: Starting Cluster...

.. NOTE::

    An alternative to using the ``pcs cluster start --all`` command
    is to issue either of the below command sequences on each node in the
    cluster separately:

    .. code-block:: console

        # pcs cluster start
        Starting Cluster...

    or

    .. code-block:: console

        # systemctl start corosync.service
        # systemctl start pacemaker.service

.. IMPORTANT::

    In this example, we are not enabling the ``corosync`` and ``pacemaker``
    services to start at boot. If a cluster node fails or is rebooted, you will
    need to run ``pcs cluster start [<NODENAME> | --all]`` to start the cluster
    on it. While you can enable the services to start at boot (for example,
    using ``pcs cluster enable [<NODENAME> | --all]``), requiring a manual
    start of cluster services gives you the opportunity to do a post-mortem
    investigation of a node failure before returning it to the cluster.

Verify Corosync Installation
################################

First, use ``corosync-cfgtool`` to check whether cluster communication is happy:

.. code-block:: console

    [root@pcmk-1 ~]# corosync-cfgtool -s
    Local node ID 1, transport knet
    LINK ID 0 udp
	    addr	= 192.168.122.101
	    status:
		    nodeid:          1:	localhost
		    nodeid:          2:	connected

We can see here that everything appears normal with our fixed IP address (not a
``127.0.0.x`` loopback address) listed as the ``addr``, and ``localhost`` and
``connected`` for the statuses of nodeid 1 and nodeid 2, respectively.

If you see something different, you might want to start by checking
the node's network, firewall, and SELinux configurations.

Next, check the membership and quorum APIs:

.. code-block:: console

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
#################################

Now that we have confirmed that Corosync is functional, we can check
the rest of the stack. Pacemaker has already been started, so verify
the necessary processes are running:

.. code-block:: console

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

.. code-block:: console

    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster

    WARNINGS:
    No stonith devices and stonith-enabled is not false
    error: Resource start-up disabled since no STONITH resources have been defined
    error: Either configure some or disable STONITH with the stonith-enabled option
    error: NOTE: Clusters with shared data need STONITH to ensure data integrity
    error: CIB did not pass schema validation
    Configuration invalid (with errors)

    Cluster Summary:
      * Stack: corosync (Pacemaker is running)
      * Current DC: pcmk-1 (version 3.0.1-3.el10-6a90427) - partition with quorum
      * Last updated: Tue Feb 24 14:55:38 2026 on pcmk-1
      * Last change:  Tue Feb 24 14:54:39 2026 by hacluster via hacluster on pcmk-1
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

Finally, ensure there are no start-up errors from ``corosync`` or ``pacemaker``
(aside from messages relating to not having STONITH configured, which are OK at
this point):

.. code-block:: console

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

    .. code-block:: console

        [root@pcmk-1 ~]# pcs cluster cib

    .. code-block:: xml

        <cib crm_feature_set="3.20.1" validate-with="pacemaker-4.0" epoch="5" num_updates="10" admin_epoch="0" cib-last-written="Tue Feb 24 14:54:39 2026" update-origin="pcmk-1" update-client="hacluster" update-user="hacluster" have-quorum="1" dc-uuid="2">
          <configuration>
            <crm_config>
              <cluster_property_set id="cib-bootstrap-options">
                <nvpair id="cib-bootstrap-options-have-watchdog" name="have-watchdog" value="false"/>
                <nvpair id="cib-bootstrap-options-dc-version" name="dc-version" value="3.0.1-3.el10-6a90427"/>
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
            <rsc_defaults>
              <meta_attributes id="build-resource-defaults">
                <nvpair id="build-resource-stickiness" name="resource-stickiness" value="1"/>
              </meta_attributes>
            </rsc_defaults>
          </configuration>
          <status>
            <node_state id="2" uname="pcmk-2" in_ccm="1771962858" crmd="1771962858" crm-debug-origin="do_state_transition" join="member" expected="member">
              <transient_attributes id="2">
                <instance_attributes id="status-2">
                  <nvpair id="status-2-.feature-set" name="#feature-set" value="3.20.1"/>
                </instance_attributes>
              </transient_attributes>
              <lrm id="2">
                <lrm_resources/>
              </lrm>
            </node_state>
            <node_state id="1" uname="pcmk-1" in_ccm="1771962857" crmd="1771962857" crm-debug-origin="do_state_transition" join="member" expected="member">
              <lrm id="1">
                <lrm_resources/>
              </lrm>
              <transient_attributes id="1">
                <instance_attributes id="status-1">
                  <nvpair id="status-1-.feature-set" name="#feature-set" value="3.20.1"/>
                </instance_attributes>
              </transient_attributes>
            </node_state>
          </status>
        </cib>

Before we make any changes, it's a good idea to check the validity of
the configuration.

.. code-block:: console

    [root@pcmk-1 ~]# pcs cluster verify --full
    Error: invalid cib:
    error: Resource start-up disabled since no STONITH resources have been defined
    error: Either configure some or disable STONITH with the fencing-enabled option
    error: NOTE: Clusters with shared data need STONITH to ensure data integrity
    error: CIB did not pass schema validation
    Configuration invalid (with errors)

    Error: Errors have occurred, therefore pcs is unable to continue

As you can see, the tool has found some errors. The cluster will not start any
resources until we configure STONITH.
