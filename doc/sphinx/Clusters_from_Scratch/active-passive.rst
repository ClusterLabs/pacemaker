Create an Active/Passive Cluster
--------------------------------

.. index::
   pair: resource; IP address

Add a Resource
##############

Our first resource will be a floating IP address that the cluster can bring up
on either node. Regardless of where any cluster service(s) are running, end
users need to be able to communicate with them at a consistent address. Here,
we will use ``192.168.122.120`` as the floating IP address, give it the
imaginative name ``ClusterIP``, assign the IP address to the physical device
``enp1s0``, and tell the cluster to check whether it is still running every 30
seconds.

.. WARNING::

    The chosen address must not already be in use on the network, on a cluster
    node or elsewhere. Do not reuse an IP address one of the nodes already has
    configured.

.. code-block:: console

    [root@pcmk-1 ~]# pcs resource create ClusterIP ocf:heartbeat:IPaddr2 \
        ip=192.168.122.120 cidr_netmask=24 nic=enp1s0 op monitor interval=30s

Another important piece of information here is ``ocf:heartbeat:IPaddr2``.
This tells Pacemaker three things about the resource you want to add:

* The first field (``ocf`` in this case) is the standard to which the resource
  agent conforms and where to find it.

* The second field (``heartbeat`` in this case) is known as the provider.
  Currently, this field is supported only for OCF resources. It tells
  Pacemaker which OCF namespace the resource script is in.

* The third field (``IPaddr2`` in this case) is the name of the resource agent,
  the executable file responsible for starting, stopping, monitoring, and
  possibly promoting and demoting the resource.

To obtain a list of the available resource standards (the ``ocf`` part of
``ocf:heartbeat:IPaddr2``), run:

.. code-block:: console

    [root@pcmk-1 ~]# pcs resource standards
    lsb
    ocf
    service
    systemd

To obtain a list of the available OCF resource providers (the ``heartbeat``
part of ``ocf:heartbeat:IPaddr2``), run:

.. code-block:: console

    [root@pcmk-1 ~]# pcs resource providers
    heartbeat
    openstack
    pacemaker

Finally, if you want to see all the resource agents available for
a specific OCF provider (the ``IPaddr2`` part of ``ocf:heartbeat:IPaddr2``), run:

.. code-block:: console

    [root@pcmk-1 ~]# pcs resource agents ocf:heartbeat
    apache
    conntrackd
    corosync-qnetd
    .
    . (skipping lots of resources to save space)
    .
    VirtualDomain
    Xinetd

If you want to list all resource agents available on the system, run ``pcs
resource list``. We'll skip that here.

Now, verify that the IP resource has been added, and display the cluster's
status to see that it is now active. Note: There should be a fencing device by
now, but it's okay if it doesn't look like the one below.

.. code-block:: console

    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync (Pacemaker is running)
      * Current DC: pcmk-1 (version 3.0.1-3.el10-6a90427) - partition with quorum
      * Last updated: Tue Feb 24 15:19:53 2026 on pcmk-1
      * Last change:  Tue Feb 24 15:19:16 2026 by root via root on pcmk-1
      * 2 nodes configured
      * 2 resource instances configured

    Node List:
      * Online: [ pcmk-1 pcmk-2 ]

    Full List of Resources:
      * fence_dev	(stonith:some_fence_agent):	 Started pcmk-1
      * ClusterIP	(ocf:heartbeat:IPaddr2):	 Started pcmk-2

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled

On the node where the ``ClusterIP`` resource is running, verify that the
address has been added.

.. code-block:: console

    [root@pcmk-2 ~]# ip -o addr show
    1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
    1: lo    inet6 ::1/128 scope host \       valid_lft forever preferred_lft forever
    2: enp1s0    inet 192.168.122.102/24 brd 192.168.122.255 scope global noprefixroute enp1s0\       valid_lft forever preferred_lft forever
    2: enp1s0    inet 192.168.122.120/24 scope global enp1s0\       valid_lft forever preferred_lft forever
    2: enp1s0    inet6 fe80::5054:ff:fe95:209/64 scope link noprefixroute \       valid_lft forever preferred_lft forever

Perform a Failover
##################

Since our ultimate goal is high availability, we should test failover of
our new resource before moving on.

First, from the ``pcs status`` output in the previous step, find the node on
which the IP address is running. You can see that the status of the
``ClusterIP`` resource is ``Started`` on a particular node (in this example,
``pcmk-2``). Shut down ``pacemaker`` and ``corosync`` on that machine to
trigger a failover.

.. code-block:: console

    [root@pcmk-2 ~]# pcs cluster stop pcmk-2
    pcmk-2: Stopping Cluster (pacemaker)...
    pcmk-2: Stopping Cluster (corosync)...

.. NOTE::

    A cluster command such as ``pcs cluster stop <NODENAME>`` can be run from
    any node in the cluster, not just the node where the cluster services will
    be stopped. Running ``pcs cluster stop`` without a ``<NODENAME>`` stops the
    cluster services on the local host. The same is true for ``pcs cluster
    start`` and many other such commands.

Verify that ``pacemaker`` and ``corosync`` are no longer running:

.. code-block:: console

    [root@pcmk-2 ~]# pcs status
    Error: error running crm_mon, is pacemaker running?
      crm_mon: Connection to cluster failed: Connection refused

Go to the other node, and check the cluster status.

.. code-block:: console

    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync (Pacemaker is running)
      * Current DC: pcmk-1 (version 3.0.1-3.el10-6a90427) - partition with quorum
      * Last updated: Tue Feb 24 15:23:32 2026 on pcmk-2
      * Last change:  Tue Feb 24 15:19:16 2026 by root via root on pcmk-1
      * 2 nodes configured
      * 2 resource instances configured

    Node List:
      * Online: [ pcmk-1 ]
      * OFFLINE: [ pcmk-2 ]

    Full List of Resources:
      * fence_dev	(stonith:some_fence_agent):	 Started pcmk-1
      * ClusterIP	(ocf:heartbeat:IPaddr2):	 Started pcmk-1

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled

Notice that ``pcmk-2`` is ``OFFLINE`` for cluster purposes (its ``pcsd`` is still
active, allowing it to receive ``pcs`` commands, but it is not participating in
the cluster).

Also notice that ``ClusterIP`` is now running on ``pcmk-1`` -- failover happened
automatically, and no errors are reported.

.. topic:: Quorum

    If a cluster splits into two (or more) groups of nodes that can no longer
    communicate with each other (a.k.a. *partitions*), *quorum* is used to
    prevent resources from starting on more nodes than desired, which would
    risk data corruption.

    A cluster has quorum when more than half of all known nodes are online in
    the same partition, or for the mathematically inclined, whenever the following
    inequality is true:

    .. code-block:: console

        total_nodes < 2 * active_nodes

    For example, if a 5-node cluster split into 3- and 2-node paritions,
    the 3-node partition would have quorum and could continue serving resources.
    If a 6-node cluster split into two 3-node partitions, neither partition
    would have quorum; Pacemaker's default behavior in such cases is to
    stop all resources, in order to prevent data corruption.

    Two-node clusters are a special case. By the above definition,
    a two-node cluster would only have quorum when both nodes are
    running. This would make the creation of a two-node cluster pointless.
    However, Corosync has the ability to require only one node for quorum in a
    two-node cluster.

    The ``pcs cluster setup`` command will automatically configure
    ``two_node: 1`` in ``corosync.conf``, so a two-node cluster will "just work".

    .. NOTE::

        You might wonder, "What if the nodes in a two-node cluster can't
        communicate with each other? Wouldn't this ``two_node: 1`` setting
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
        behavior is controlled by the ``wait_for_all: 1`` option, which is
        enabled automatically when ``two_node: 1`` is configured.

    If you are using a different cluster shell, you may have to configure
    ``corosync.conf`` appropriately yourself.

Now, simulate node recovery by restarting the cluster stack on ``pcmk-2``, and
check the cluster's status. (It may take a little while before the cluster
gets going on the node, but it eventually will look like the below.)

.. code-block:: console

    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync (Pacemaker is running)
      * Current DC: pcmk-1 (version 3.0.1-3.el10-6a90427) - partition with quorum
      * Last updated: Tue Feb 24 15:27:35 2026 on pcmk-2
      * Last change:  Tue Feb 24 15:19:16 2026 by root via root on pcmk-1
      * 2 nodes configured
      * 2 resource instances configured

    Node List:
      * Online: [ pcmk-1 pcmk-2 ]

    Full List of Resources:
      * fence_dev	(stonith:some_fence_agent):	 Started pcmk-1
      * ClusterIP	(ocf:heartbeat:IPaddr2):	 Started pcmk-1

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

In |CFS_DISTRO| |CFS_DISTRO_VER|, the cluster setup process automatically
configures a default resource stickiness score of 1. This is sufficient to
prevent healthy resources from moving around the cluster when there are no
user-configured constraints that influence where Pacemaker prefers to run those
resources.

.. code-block:: console

    [root@pcmk-1 ~]# pcs resource defaults
    Meta Attrs: build-resource-defaults
      resource-stickiness=1

For this example, we will increase the default resource stickiness to 100.
Later in this guide, we will configure a location constraint with a score lower
than the default resource stickiness.

.. code-block:: console

    [root@pcmk-1 ~]# pcs resource defaults update resource-stickiness=100
    Warning: Defaults do not apply to resources which override them with their own defined values
    [root@pcmk-1 ~]# pcs resource defaults
    Meta Attrs: build-resource-defaults
    resource-stickiness=100


.. [#] Zero resource stickiness is Pacemaker's default if you remove the
       default value that was created at cluster setup time, or if you're using
       an older version of Pacemaker that doesn't create this value at setup
       time.

.. [#] Pacemaker's default definition of "optimal" may not always agree with
       yours. The order in which Pacemaker processes lists of resources and
       nodes creates implicit preferences in situations where the administrator
       has not explicitly specified them.
