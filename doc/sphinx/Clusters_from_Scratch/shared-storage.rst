.. index::
   pair: storage; DRBD

Replicate Storage Using DRBD
----------------------------

Even if you're serving up static websites, having to manually synchronize
the contents of that website to all the machines in the cluster is not
ideal. For dynamic websites, such as a wiki, it's not even an option. Not
everyone can afford network-attached storage, but somehow the data needs
to be kept in sync.

Enter DRBD, which can be thought of as network-based RAID-1 [#]_.

Install the DRBD Packages
#########################

DRBD itself is included in the upstream kernel [#]_, but we do need some
utilities to use it effectively.

|CFS_DISTRO| does not ship these utilities, so we need to enable a third-party
repository to get them. Supported packages for many OSes are available from
DRBD's maker `LINBIT <http://www.linbit.com/>`_, but here we'll use the free
`ELRepo <http://elrepo.org/>`_ repository.

On both nodes, import the ELRepo package signing key, and enable the
repository:

.. code-block:: console

    [root@pcmk-1 ~]# rpm --import https://www.elrepo.org/RPM-GPG-KEY-v2-elrepo.org
    [root@pcmk-1 ~]# dnf install -y https://www.elrepo.org/elrepo-release-10.el10.elrepo.noarch.rpm

Now, we can install the DRBD kernel module and utilities:

.. code-block:: console

    # dnf install -y kmod-drbd9x drbd9x-utils

We will configure DRBD to use port 7789, so allow that port from each host to
the other:

.. code-block:: console

    [root@pcmk-1 ~]# firewall-cmd --permanent --add-rich-rule='rule family="ipv4" \
    source address="192.168.122.102" port port="7789" protocol="tcp" accept'
    success
    [root@pcmk-1 ~]# firewall-cmd --reload
    success

.. code-block:: console

    [root@pcmk-2 ~]# firewall-cmd --permanent --add-rich-rule='rule family="ipv4" \
    source address="192.168.122.101" port port="7789" protocol="tcp" accept'
    success
    [root@pcmk-2 ~]# firewall-cmd --reload
    success

.. NOTE::

    In this example, we have only two nodes, and all network traffic is on the same LAN.
    In production, it is recommended to use a dedicated, isolated network for cluster-related traffic,
    so the firewall configuration would likely be different; one approach would be to
    add the dedicated network interfaces to the trusted zone.

.. NOTE::

    If the ``firewall-cmd --add-rich-rule`` command fails with ``Error:
    INVALID_RULE: unknown element`` ensure that there is no space at the
    beginning of the second line of the command.

Allocate a Disk Volume for DRBD
###############################

DRBD will need its own block device on each node. This can be
a physical disk partition or logical volume, of whatever size
you need for your data. For this document, we will use a 512MiB logical volume,
which is more than sufficient for a single HTML file and (later) GFS2 metadata.

.. code-block:: console

    [root@pcmk-1 ~]# vgs
      VG               #PV #LV #SN Attr   VSize   VFree
      almalinux_pcmk-1   1   2   0 wz--n- <19.00g <13.00g

    [root@pcmk-1 ~]# lvcreate --name drbd-demo --size 512M almalinux_pcmk-1
      Logical volume "drbd-demo" created.
    [root@pcmk-1 ~]# lvs
      LV        VG               Attr       LSize   Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
      drbd-demo almalinux_pcmk-1 -wi-a----- 512.00m
      root      almalinux_pcmk-1 -wi-ao----   4.00g
      swap      almalinux_pcmk-1 -wi-ao----   2.00g

Repeat for the second node, making sure to use the same size:

.. code-block:: console

    [root@pcmk-1 ~]# ssh pcmk-2 -- lvcreate --name drbd-demo --size 512M almalinux_pcmk-2
     Logical volume "drbd-demo" created.

Configure DRBD
##############

There is no series of commands for building a DRBD configuration, so simply
run this on both nodes to use this sample configuration:

.. code-block:: console

    # cat <<END >/etc/drbd.d/wwwdata.res
    resource "wwwdata" {
      device minor 1;
      meta-disk internal;

      net {
        protocol C;
        allow-two-primaries yes;
        fencing resource-and-stonith;
        verify-alg sha1;
      }
      handlers {
        fence-peer "/usr/lib/drbd/crm-fence-peer.9.sh";
        unfence-peer "/usr/lib/drbd/crm-unfence-peer.9.sh";
      }
      on "pcmk-1" {
        disk "/dev/almalinux_pcmk-1/drbd-demo";
        node-id 0;
      }
      on "pcmk-2" {
        disk "/dev/almalinux_pcmk-2/drbd-demo";
        node-id 1;
      }
      connection {
        host "pcmk-1" address 192.168.122.101:7789;
        host "pcmk-2" address 192.168.122.102:7789;
      }
    }
    END


.. IMPORTANT::

    Edit the file to use the hostnames, IP addresses, and logical volume paths
    of your nodes if they differ from the ones used in this guide.

.. NOTE::

    Detailed information on the directives used in this configuration (and
    other alternatives) is available in the
    `DRBD User's Guide
    <https://linbit.com/drbd-user-guide/drbd-guide-9_0-en/#ch-configure>`_. The
    guide contains a wealth of information on such topics as core DRBD
    concepts, replication settings, network connection options, quorum, split-
    brain handling, administrative tasks, troubleshooting, and responding to
    disk or node failures, among others.

    The ``allow-two-primaries: yes`` option would not normally be used in
    an active/passive cluster. We are adding it here for the convenience
    of changing to an active/active cluster later.

Initialize DRBD
###############

With the configuration in place, we can now get DRBD running.

These commands create the local metadata for the DRBD resource,
ensure the DRBD kernel module is loaded, and bring up the DRBD resource.
Run them on one node:

.. code-block:: console

    [root@pcmk-1 ~]# drbdadm create-md wwwdata



















      --==  Thank you for participating in the global usage survey  ==--
    The server's response is:

    you are the 25212th user to install this version
    initializing activity log
    initializing bitmap (16 KB) to all zero
    Writing meta data...
    New drbd meta data block successfully created.
    success
    [root@pcmk-1 ~]# drbdadm up wwwdata

We can confirm DRBD's status on this node:

.. code-block:: console

    [root@pcmk-1 ~]# drbdadm status
    wwwdata role:Secondary
      disk:Inconsistent open:no
      pcmk-2 connection:Connecting

Because we have not yet initialized the data, this node's data
is marked as ``Inconsistent`` Because we have not yet initialized
the second node, the ``pcmk-2`` connection is ``Connecting`` (waiting for
connection).

Now, repeat the above commands on the second node, starting with creating
``wwwdata``. After giving it time to connect, when we check the status of
the first node, it shows:

.. code-block:: console

    [root@pcmk-1 ~]# drbdadm status
    wwwdata role:Secondary
      disk:Inconsistent open:no
      pcmk-2 role:Secondary
        peer-disk:Inconsistent

You can see that ``pcmk-2 connection:Connecting`` no longer appears in the
output, meaning the two DRBD nodes are communicating properly, and both
nodes are in ``Secondary`` role with ``Inconsistent`` data.

To make the data consistent, we need to tell DRBD which node should be
considered to have the correct data. In this case, since we are creating
a new resource, both have garbage, so we'll just pick ``pcmk-1``
and run this command on it:

.. code-block:: console

    [root@pcmk-1 ~]# drbdadm primary --force wwwdata

.. NOTE::

    If you are using a different version of DRBD, the required syntax may be different.
    See the documentation for your version for how to perform these commands.

If we check the status immediately, we'll see something like this:

.. code-block:: console

    [root@pcmk-1 ~]# drbdadm status
    wwwdata role:Primary
      disk:UpToDate open:no
      pcmk-2 role:Secondary
        peer-disk:Inconsistent

It will be quickly followed by this:

.. code-block:: console

    [root@pcmk-1 ~]# drbdadm status
    wwwdata role:Primary
      disk:UpToDate open:no
      pcmk-2 role:Secondary
        replication:SyncSource peer-disk:Inconsistent

We can see that the first node has the ``Primary`` role, its partner node has
the ``Secondary`` role, the first node's data is now considered ``UpToDate``,
and the partner node's data is still ``Inconsistent``.

After a while, the sync should finish, and you'll see something like:

.. code-block:: console

    [root@pcmk-1 ~]# drbdadm status
    wwwdata role:Primary
      disk:UpToDate open:no
      pcmk-1 role:Secondary
        peer-disk:UpToDate
    [root@pcmk-2 ~]# drbdadm status
    wwwdata role:Secondary
      disk:UpToDate open:no
      pcmk-1 role:Primary
        peer-disk:UpToDate

Both sets of data are now ``UpToDate``, and we can proceed to creating
and populating a filesystem for our ``WebSite`` resource's documents.

Populate the DRBD Disk
######################

On the node with the primary role (``pcmk-1`` in this example),
create a filesystem on the DRBD device:

.. code-block:: console

    [root@pcmk-1 ~]# mkfs.xfs /dev/drbd1
    meta-data=/dev/drbd1             isize=512    agcount=4, agsize=32765 blks
             =                       sectsz=512   attr=2, projid32bit=1
             =                       crc=1        finobt=1, sparse=1, rmapbt=0
             =                       reflink=1    bigtime=1 inobtcount=1 nrext64=1
             =                       exchange=0
    data     =                       bsize=4096   blocks=131059, imaxpct=25
             =                       sunit=0      swidth=0 blks
    naming   =version 2              bsize=4096   ascii-ci=0, ftype=1, parent=0
    log      =internal log           bsize=4096   blocks=16384, version=2
             =                       sectsz=512   sunit=0 blks, lazy-count=1
    realtime =none                   extsz=4096   blocks=0, rtextents=0
    Discarding blocks...Done.

.. NOTE::

    In this example, we create an xfs filesystem with no special options.
    In a production environment, you should choose a filesystem type and
    options that are suitable for your application.

Mount the newly created filesystem, populate it with our web document,
give it the same SELinux policy as the web document root,
then unmount it (the cluster will handle mounting and unmounting it later):

.. code-block:: console

    [root@pcmk-1 ~]# mount /dev/drbd1 /mnt
    [root@pcmk-1 ~]# cat <<-END >/mnt/index.html
     <html>
      <body>My Test Site - DRBD</body>
     </html>
    END
    [root@pcmk-1 ~]# chcon -R --reference=/var/www/html /mnt
    [root@pcmk-1 ~]# umount /dev/drbd1

Configure the Cluster for the DRBD device
#########################################

One handy feature ``pcs`` has is the ability to queue up several changes
into a file and commit those changes all at once. To do this, start by
populating the file with the current raw XML config from the CIB.

.. code-block:: console

    [root@pcmk-1 ~]# pcs cluster cib drbd_cfg

Using ``pcs``'s ``-f`` option, make changes to the configuration saved
in the ``drbd_cfg`` file. These changes will not be seen by the cluster until
the ``drbd_cfg`` file is pushed into the live cluster's CIB later.

Here, we create a cluster resource for the DRBD device, and an additional *clone*
resource to allow the resource to run on both nodes at the same time.

.. code-block:: console

    [root@pcmk-1 ~]# pcs -f drbd_cfg resource create WebData ocf:linbit:drbd \
         drbd_resource=wwwdata op monitor interval=29s role=Promoted \
         monitor interval=31s role=Unpromoted
    [root@pcmk-1 ~]# pcs -f drbd_cfg resource promotable WebData meta \
         promoted-max=1 promoted-node-max=1 clone-max=2 clone-node-max=1 \
         notify=true
    [root@pcmk-1 ~]# pcs resource status
     * ClusterIP	(ocf::heartbeat:IPaddr2):	Started pcmk-1
     * WebSite	(ocf::heartbeat:apache):		Started pcmk-1
    [root@pcmk-1 ~]# pcs resource config
     Resource: ClusterIP (class=ocf provider=heartbeat type=IPaddr2)
      Attributes: ClusterIP-instance_attributes
        cidr_netmask=24
        ip=192.168.122.120
        nic=enp1s0
      Operations:
        monitor: ClusterIP-monitor-interval-30s
          interval=30s
        start: ClusterIP-start-interval-0s
          interval=0s timeout=20s
        stop: ClusterIP-stop-interval-0s
          interval=0s timeout=20s
     Resource: WebSite (class=ocf provider=heartbeat type=apache)
      Attributes: WebSite-instance_attributes
        configfile=/etc/httpd/conf/httpd.conf
        statusurl=http://localhost/server-status
      Operations:
        monitor: WebSite-monitor-interval-1min
          interval=1min
        start: WebSite-start-interval-0s
          interval=0s timeout=40s
        stop: WebSite-stop-interval-0s
          interval=0s timeout=60s

After you are satisfied with all the changes, you can commit
them all at once by pushing the ``drbd_cfg`` file into the live CIB.

.. code-block:: console

    [root@pcmk-1 ~]# pcs cluster cib-push drbd_cfg --config
    CIB updated

.. NOTE::

    All the updates above can be done in one shot as follows:

    .. code-block:: console

        [root@pcmk-1 ~]# pcs resource create WebData ocf:linbit:drbd \
            drbd_resource=wwwdata op monitor interval=29s role=Promoted \
            monitor interval=31s role=Unpromoted promotable meta \
            promoted-max=1 promoted-node-max=1 clone-max=2 clone-node-max=1 \
            notify=true

Let's see what the cluster did with the new configuration:

.. code-block:: console

    [root@pcmk-1 ~]# pcs resource status
      * ClusterIP	(ocf:heartbeat:IPaddr2):	 Started pcmk-2
      * WebSite	(ocf:heartbeat:apache):	 Started pcmk-2
      * Clone Set: WebData-clone [WebData] (promotable):
        * Promoted: [ pcmk-1 ]
        * Unpromoted: [ pcmk-2 ]
    [root@pcmk-1 ~]# pcs resource config
     Resource: ClusterIP (class=ocf provider=heartbeat type=IPaddr2)
      Attributes: ClusterIP-instance_attributes
        cidr_netmask=24
        ip=192.168.122.120
        nic=enp1s0
      Operations:
        monitor: ClusterIP-monitor-interval-30s
          interval=30s
        start: ClusterIP-start-interval-0s
          interval=0s timeout=20s
        stop: ClusterIP-stop-interval-0s
          interval=0s timeout=20s
     Resource: WebSite (class=ocf provider=heartbeat type=apache)
      Attributes: WebSite-instance_attributes
        configfile=/etc/httpd/conf/httpd.conf
        statusurl=http://localhost/server-status
      Operations:
        monitor: WebSite-monitor-interval-1min
          interval=1min
        start: WebSite-start-interval-0s
          interval=0s timeout=40s
        stop: WebSite-stop-interval-0s
          interval=0s timeout=60s
     Clone: WebData-clone
      Meta Attributes: WebData-clone-meta_attributes
        clone-max=2
        clone-node-max=1
        notify=true
        promotable=true
        promoted-max=1
        promoted-node-max=1
      Resource: WebData (class=ocf provider=linbit type=drbd)
       Attributes: WebData-instance_attributes
         drbd_resource=wwwdata
       Operations:
         demote: WebData-demote-interval-0s
           interval=0s timeout=90
         monitor: WebData-monitor-interval-29s
           interval=29s role=Promoted
         monitor: WebData-monitor-interval-31s
           interval=31s role=Unpromoted
         notify: WebData-notify-interval-0s
           interval=0s timeout=90
         promote: WebData-promote-interval-0s
           interval=0s timeout=90
         reload: WebData-reload-interval-0s
           interval=0s timeout=30
         start: WebData-start-interval-0s
           interval=0s timeout=240
         stop: WebData-stop-interval-0s
           interval=0s timeout=100

We can see that ``WebData-clone`` (our DRBD device) is running as ``Promoted``
(DRBD's primary role) on ``pcmk-1`` and ``Unpromoted`` (DRBD's secondary role)
on ``pcmk-2``.

.. IMPORTANT::

    The resource agent should load the DRBD module when needed if it's not already
    loaded. If that does not happen, configure your operating system to load the
    module at boot time. For |CFS_DISTRO| |CFS_DISTRO_VER|, you would run this on both
    nodes:

    .. code-block:: console

        # echo drbd >/etc/modules-load.d/drbd.conf

Configure the Cluster for the Filesystem
########################################

Now that we have a working DRBD device, we need to mount its filesystem.

In addition to defining the filesystem, we also need to
tell the cluster where it can be located (only on the DRBD Primary)
and when it is allowed to start (after the Primary was promoted).

We are going to take a shortcut when creating the resource this time.
Instead of explicitly saying we want the ``ocf:heartbeat:Filesystem`` script,
we are only going to ask for ``Filesystem``. We can do this because we know
there is only one resource script named ``Filesystem`` available to
Pacemaker, and that ``pcs`` is smart enough to fill in the
``ocf:heartbeat:`` portion for us correctly in the configuration. If there were
multiple ``Filesystem`` scripts from different OCF providers, we would need to
specify the exact one we wanted.

Once again, we will queue our changes to a file and then push the
new configuration to the cluster as the final step.

.. code-block:: console

    [root@pcmk-1 ~]# pcs cluster cib fs_cfg
    [root@pcmk-1 ~]# pcs -f fs_cfg resource create WebFS Filesystem \
        device="/dev/drbd1" directory="/var/www/html" fstype="xfs"
    Assumed agent name 'ocf:heartbeat:Filesystem' (deduced from 'Filesystem')
    [root@pcmk-1 ~]# pcs -f fs_cfg constraint colocation add \
        WebFS with Promoted WebData-clone
    [root@pcmk-1 ~]# pcs -f fs_cfg constraint order \
        promote WebData-clone then start WebFS
    Adding WebData-clone WebFS (kind: Mandatory) (Options: first-action=promote then-action=start)

We also need to tell the cluster that Apache needs to run on the same
machine as the filesystem and that it must be active before Apache can
start.

.. code-block:: console

    [root@pcmk-1 ~]# pcs -f fs_cfg constraint colocation add WebSite with WebFS
    [root@pcmk-1 ~]# pcs -f fs_cfg constraint order WebFS then WebSite
    Adding WebFS WebSite (kind: Mandatory) (Options: first-action=start then-action=start)

Review the updated configuration.

.. code-block:: console

    [root@pcmk-1 ~]# pcs -f fs_cfg constraint
    Location Constraints:
      resource 'WebSite' prefers node 'pcmk-1' with score 50
    Colocation Constraints:
      resource 'WebSite' with resource 'ClusterIP'
        score=INFINITY
      Started resource 'WebFS' with Promoted resource 'WebData-clone'
        score=INFINITY
      resource 'WebSite' with resource 'WebFS'
        score=INFINITY
    Ordering Constraints:
      start resource 'ClusterIP' then start resource 'WebSite'
      promote resource 'WebData-clone' then start resource 'WebFS'
      start resource 'WebFS' then start resource 'WebSite'

After reviewing the new configuration, upload it and watch the
cluster put it into effect.

.. code-block:: console

    [root@pcmk-1 ~]# pcs cluster cib-push fs_cfg --config
    CIB updated
    [root@pcmk-1 ~]# pcs resource status
      * ClusterIP	(ocf:heartbeat:IPaddr2):	 Started pcmk-2
      * WebSite	(ocf:heartbeat:apache):	 Started pcmk-2
      * Clone Set: WebData-clone [WebData] (promotable):
        * Promoted: [ pcmk-2 ]
        * Unpromoted: [ pcmk-1 ]
      * WebFS	(ocf:heartbeat:Filesystem):	 Started pcmk-2
    [root@pcmk-1 ~]# pcs resource config
     Resource: ClusterIP (class=ocf provider=heartbeat type=IPaddr2)
      Attributes: ClusterIP-instance_attributes
        cidr_netmask=24
        ip=192.168.122.120
        nic=enp1s0
      Operations:
        monitor: ClusterIP-monitor-interval-30s
          interval=30s
        start: ClusterIP-start-interval-0s
          interval=0s timeout=20s
        stop: ClusterIP-stop-interval-0s
          interval=0s timeout=20s
     Resource: WebSite (class=ocf provider=heartbeat type=apache)
      Attributes: WebSite-instance_attributes
        configfile=/etc/httpd/conf/httpd.conf
        statusurl=http://localhost/server-status
      Operations:
        monitor: WebSite-monitor-interval-1min
          interval=1min
        start: WebSite-start-interval-0s
          interval=0s timeout=40s
        stop: WebSite-stop-interval-0s
          interval=0s timeout=60s
     Resource: WebFS (class=ocf provider=heartbeat type=Filesystem)
      Attributes: WebFS-instance_attributes
        device=/dev/drbd1
        directory=/var/www/html
        fstype=xfs
      Operations:
        monitor: WebFS-monitor-interval-20s
          interval=20s timeout=40s
        start: WebFS-start-interval-0s
          interval=0s timeout=60s
        stop: WebFS-stop-interval-0s
          interval=0s timeout=60s
     Clone: WebData-clone
      Meta Attributes: WebData-clone-meta_attributes
        clone-max=2
        clone-node-max=1
        notify=true
        promotable=true
        promoted-max=1
        promoted-node-max=1
      Resource: WebData (class=ocf provider=linbit type=drbd)
       Attributes: WebData-instance_attributes
         drbd_resource=wwwdata
       Operations:
         demote: WebData-demote-interval-0s
           interval=0s timeout=90
         monitor: WebData-monitor-interval-29s
           interval=29s role=Promoted
         monitor: WebData-monitor-interval-31s
           interval=31s role=Unpromoted
         notify: WebData-notify-interval-0s
           interval=0s timeout=90
         promote: WebData-promote-interval-0s
           interval=0s timeout=90
         reload: WebData-reload-interval-0s
           interval=0s timeout=30
         start: WebData-start-interval-0s
           interval=0s timeout=240
         stop: WebData-stop-interval-0s
           interval=0s timeout=100

Test Cluster Failover
#####################

Previously, we used ``pcs cluster stop pcmk-2`` to stop all cluster
services on ``pcmk-2``, failing over the cluster resources, but there is another
way to safely simulate node failure.

We can put the node into *standby mode*. Nodes in this state continue to
run ``corosync`` and ``pacemaker`` but are not allowed to run resources. Any
resources found active there will be moved elsewhere. This feature can be
particularly useful when performing system administration tasks such as
updating packages used by cluster resources.

Put the active node into standby mode, and observe the cluster move all
the resources to the other node. The node's status will change to indicate that
it can no longer host resources, and eventually all the resources will move.

.. code-block:: console

    [root@pcmk-1 ~]# pcs node standby pcmk-2
    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync (Pacemaker is running)
      * Current DC: pcmk-1 (version 3.0.1-3.el10-6a90427) - partition with quorum
      * Last updated: Wed Feb 25 10:32:17 2026
      * Last change:  Wed Feb 25 10:32:13 2026 by root via root on pcmk-1
      * 2 nodes configured
      * 6 resource instances configured

    Node List:
      * Node pcmk-2: standby
      * Online: [ pcmk-1 ]

    Full List of Resources:
      * fence_dev	(stonith:some_fence_agent):	 Started pcmk-1
      * ClusterIP	(ocf:heartbeat:IPaddr2):	 Started pcmk-1
      * WebSite	(ocf:heartbeat:apache):	 Started pcmk-1
      * Clone Set: WebData-clone [WebData] (promotable):
        * Promoted: [ pcmk-1 ]
        * Stopped: [ pcmk-2 ]
      * WebFS	(ocf:heartbeat:Filesystem):	 Started pcmk-1

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled

Once we've done everything we needed to on ``pcmk-2`` (in this case nothing,
we just wanted to see the resources move), we can unstandby the node, making it
eligible to host resources again.

.. code-block:: console

    [root@pcmk-1 ~]# pcs node unstandby pcmk-2
    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync (Pacemaker is running)
      * Current DC: pcmk-1 (version 3.0.1-3.el10-6a90427) - partition with quorum
      * Last updated: Wed Feb 25 10:32:17 2026
      * Last change:  Wed Feb 25 10:32:13 2026 by root via root on pcmk-1
      * 2 nodes configured
      * 6 resource instances configured

    Node List:
      * Online: [ pcmk-1 pcmk-2 ]

    Full List of Resources:
      * fence_dev	(stonith:some_fence_agent):	 Started pcmk-1
      * ClusterIP	(ocf:heartbeat:IPaddr2):	 Started pcmk-1
      * WebSite	(ocf:heartbeat:apache):	 Started pcmk-1
      * Clone Set: WebData-clone [WebData] (promotable):
        * Promoted: [ pcmk-1 ]
        * Unpromoted: [ pcmk-2 ]
      * WebFS	(ocf:heartbeat:Filesystem):	 Started pcmk-1

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled

Notice that ``pcmk-2`` is back to the ``Online`` state, and that the cluster
resources stay where they are due to our resource stickiness settings
configured earlier.

.. [#] See http://www.drbd.org for details.

.. [#] Since version 2.6.33
