Create an Active/Passive Cluster
--------------------------------

.. index::
   pair: resource; IP address

Add a Resource
##############

Our first resource will be a floating IP address that the cluster can bring up
on either node. Regardless of where any cluster service(s) are running, end
users need to be able to communicate with them at a consistent address. Here,
we will use **192.168.122.120** as the floating IP address, give it the
imaginative name **ClusterIP**, and tell the cluster to check whether it is
still running every 30 seconds.

.. WARNING::

    The chosen address must not already be in use on the network, on a cluster
    node or elsewhere. Do not reuse an IP address one of the nodes already has
    configured.

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource create ClusterIP ocf:heartbeat:IPaddr2 \ 
        ip=192.168.122.120 cidr_netmask=24 op monitor interval=30s

Another important piece of information here is **ocf:heartbeat:IPaddr2**.
This tells Pacemaker three things about the resource you want to add:

* The first field (**ocf** in this case) is the standard to which the resource
  agent conforms and where to find it.

* The second field (**heartbeat** in this case) is known as the provider.
  Currently, this field is supported only for OCF resources. It tells Pacemaker
  which OCF namespace the resource script is in.

* The third field (**IPaddr2** in this case) is the name of the resource agent,
  the executable file responsible for starting, stopping, monitoring, and
  possibly promoting and demoting the resource.

To obtain a list of the available resource standards (the **ocf** part of
**ocf:heartbeat:IPaddr2**), run:

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource standards
    lsb
    ocf
    service
    systemd

To obtain a list of the available OCF resource providers (the **heartbeat**
part of **ocf:heartbeat:IPaddr2**), run:

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource providers
    heartbeat
    openstack
    pacemaker

Finally, if you want to see all the resource agents available for
a specific OCF provider (the **IPaddr2** part of **ocf:heartbeat:IPaddr2**), run:

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource agents ocf:heartbeat
    apache
    aws-vpc-move-ip
    aws-vpc-route53
    awseip
    awsvip
    azure-events
    .
    . (skipping lots of resources to save space)
    .
    symlink
    tomcat
    vdo-vol
    VirtualDomain
    Xinetd

Now, verify that the IP resource has been added, and display the cluster's
status to see that it is now active:

.. code-block:: none

    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync
      * Current DC: pcmk-2 (version 2.0.5-4.el8-ba59be7122) - partition with quorum
      * Last updated: Tue Jan 26 19:22:10 2021
      * Last change:  Tue Jan 26 19:20:28 2021 by root via cibadmin on pcmk-1
      * 2 nodes configured
      * 1 resource instance configured
    
    Node List:
      * Online: [ pcmk-1 pcmk-2 ]

    Full List of Resources:
      * ClusterIP	(ocf::heartbeat:IPaddr2):	 Started pcmk-1

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled

Perform a Failover
##################

Since our ultimate goal is high availability, we should test failover of
our new resource before moving on.

First, find the node on which the IP address is running.

.. code-block:: none

    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync
      * Current DC: pcmk-2 (version 2.0.5-4.el8-ba59be7122) - partition with quorum
      * Last updated: Tue Jan 26 19:22:10 2021
      * Last change:  Tue Jan 26 19:20:28 2021 by root via cibadmin on pcmk-1
      * 2 nodes configured
      * 1 resource instance configured
    
    Node List:
      * Online: [ pcmk-1 pcmk-2 ]

    Full List of Resources:
      * ClusterIP	(ocf::heartbeat:IPaddr2):	 Started pcmk-1

You can see that the status of the **ClusterIP** resource
is **Started** on a particular node (in this example, **pcmk-1**).
Shut down Pacemaker and Corosync on that machine to trigger a failover.

.. code-block:: none

    [root@pcmk-1 ~]# pcs cluster stop pcmk-1
    pcmk-1: Stopping Cluster (pacemaker)...
    pcmk-1: Stopping Cluster (corosync)...

.. NOTE::

    A cluster command such as ``pcs cluster stop <NODENAME>`` can be run from
    any node in the cluster, not just the node where the cluster services will
    be stopped. Running ``pcs cluster stop`` without a ``<NODENAME>`` stops the
    cluster services on the local host. The same is true for ``pcs cluster
    start`` and many other such commands.

Verify that pacemaker and corosync are no longer running:

.. code-block:: none

    [root@pcmk-1 ~]# pcs status
    Error: error running crm_mon, is pacemaker running?
      Could not connect to the CIB: Transport endpoint is not connected
      crm_mon: Error: cluster is not available on this node

Go to the other node, and check the cluster status.

.. code-block:: none

    [root@pcmk-2 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync
      * Current DC: pcmk-2 (version 2.0.5-4.el8-ba59be7122) - partition with quorum
      * Last updated: Tue Jan 26 19:25:26 2021
      * Last change:  Tue Jan 26 19:20:28 2021 by root via cibadmin on pcmk-1
      * 2 nodes configured
      * 1 resource instance configured
    
    Node List:
      * Online: [ pcmk-2 ]
      * OFFLINE: [ pcmk-1 ]

    Full List of Resources:
      * ClusterIP	(ocf::heartbeat:IPaddr2):	 Started pcmk-2

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled

Notice that **pcmk-1** is **OFFLINE** for cluster purposes (its **pcsd** is still
active, allowing it to receive ``pcs`` commands, but it is not participating in
the cluster).

Also notice that **ClusterIP** is now running on **pcmk-2** -- failover happened
automatically, and no errors are reported.

.. topic:: Quorum

    If a cluster splits into two (or more) groups of nodes that can no longer
    communicate with each other (a.k.a. *partitions*), *quorum* is used to
    prevent resources from starting on more nodes than desired, which would
    risk data corruption.

    A cluster has quorum when more than half of all known nodes are online in
    the same partition, or for the mathematically inclined, whenever the following
    inequality is true:

    .. code-block:: none

        total_nodes < 2 * active_nodes

    For example, if a 5-node cluster split into 3- and 2-node paritions,
    the 3-node partition would have quorum and could continue serving resources.
    If a 6-node cluster split into two 3-node partitions, neither partition
    would have quorum; pacemaker's default behavior in such cases is to
    stop all resources, in order to prevent data corruption.

    Two-node clusters are a special case. By the above definition,
    a two-node cluster would only have quorum when both nodes are
    running. This would make the creation of a two-node cluster pointless.
    However, corosync has the ability to require only one node for quorum in a
    two-node cluster.

    The ``pcs cluster setup`` command will automatically configure **two_node: 1**
    in ``corosync.conf``, so a two-node cluster will "just work".

    .. NOTE::

        You might wonder, "What if the nodes in a two-node cluster can't
        communicate with each other? Wouldn't this **two_node: 1** setting
        create a split-brain scenario, in which each node has quorum separately
        and they both try to manage the same cluster resources?"

        As long as fencing is configured, there is no danger of this. If the
        nodes lose contact with each other, each node will try to fence the
        other node. Resource management is disabled until fencing succeeds;
        neither node is allowed to start, stop, promote, or demote resources.

        After fencing succeeds, the surviving node can safely recover any
        resources that were running on the fenced node.

        If the fenced node boots up and rejoins the cluster, it does not have
        quorum until it can communicate with the surviving node at least once.
        This prevents "fence loops," in which a node gets fenced, reboots,
        rejoins the cluster, and fences the other node. This protective
        behavior is controlled by the **wait_for_all: 1** option, which is
        enabled automatically when **two_node: 1** is configured.

    If you are using a different cluster shell, you may have to configure
    ``corosync.conf`` appropriately yourself.

Now, simulate node recovery by restarting the cluster stack on **pcmk-1**, and
check the cluster's status. (It may take a little while before the cluster
gets going on the node, but it eventually will look like the below.)

.. code-block:: none

    [root@pcmk-1 ~]# pcs cluster start pcmk-1
    pcmk-1: Starting Cluster...
    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync
      * Current DC: pcmk-2 (version 2.0.5-4.el8-ba59be7122) - partition with quorum
      * Last updated: Tue Jan 26 19:28:30 2021
      * Last change:  Tue Jan 26 19:28:27 2021 by root via cibadmin on pcmk-1
      * 2 nodes configured
      * 1 resource instance configured
    
    Node List:
      * Online: [ pcmk-1 pcmk-2 ]

    Full List of Resources:
      * ClusterIP	(ocf::heartbeat:IPaddr2):	 Started pcmk-2

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled


.. index:: stickiness

Prevent Resources from Moving after Recovery
############################################

In most circumstances, it is highly desirable to prevent healthy
resources from being moved around the cluster. Moving resources almost
always requires a period of downtime. For complex services such as
databases, this period can be quite long.

To address this, Pacemaker has the concept of resource *stickiness*,
which controls how strongly a service prefers to stay running where it
is. You may like to think of it as the "cost" of any downtime. By
default, [#]_ Pacemaker assumes there is zero cost associated with moving
resources and will do so to achieve "optimal" [#]_ resource placement.
We can specify a different stickiness for every resource, but it is
often sufficient to change the default.

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource defaults update resource-stickiness=100
    Warning: Defaults do not apply to resources which override them with their own defined values
    [root@pcmk-1 ~]# pcs resource defaults
    Meta Attrs: rsc_defaults-meta_attributes
    resource-stickiness=100


.. [#] Pacemaker may be built such that a positive resource-stickiness is
       automatically added to resource defaults. You can check your
       configuration to see if this is present.

.. [#] Pacemaker's default definition of "optimal" may not always agree with
       yours. The order in which Pacemaker processes lists of resources and
       nodes creates implicit preferences in situations where the administrator
       has not explicitly specified them.
