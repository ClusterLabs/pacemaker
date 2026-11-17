.. index::
   single: storage; active/active

Convert Storage to Active/Active
--------------------------------

.. NOTE::

   GFS2 is not available in a package repo for |CFS_DISTRO| |CFS_DISTRO_VER|.
   It can still be built from source, but doing so is scope of this document.
   The following instructions are still useful for older distributions or
   for installation from source.  They have been updated where possible.

The primary requirement for an active/active cluster is that the data
required for your services is available, simultaneously, on both
machines. Pacemaker makes no requirement on how this is achieved; you
could use a Storage Area Network (SAN) if you had one available, but
since DRBD supports multiple Primaries, we can continue to use it here.

.. index::
   single: GFS2
   single: DLM
   single: filesystem; GFS2

Install Cluster Filesystem Software
###################################

The only hitch is that we need to use a cluster-aware filesystem. The
one we used earlier with DRBD, xfs, is not one of those. Both OCFS2
and GFS2 are supported; here, we will use GFS2.

On both nodes, install Distributed Lock Manager (DLM) and the GFS2 command-
line utilities required by cluster filesystems:

.. code-block:: console

    # dnf config-manager --set-enabled resilientstorage
    # dnf install -y dlm gfs2-utils

Configure the Cluster for the DLM
#################################

The DLM control daemon needs to run on both nodes, so we'll start by creating a
resource for it (using the ``ocf:pacemaker:controld`` resource agent), and
clone it:

.. code-block:: console

    [root@pcmk-1 ~]# pcs cluster cib dlm_cfg
    [root@pcmk-1 ~]# pcs -f dlm_cfg resource create dlm \
        ocf:pacemaker:controld op monitor interval=60s
    [root@pcmk-1 ~]# pcs -f dlm_cfg resource clone dlm clone-max=2 clone-node-max=1
    [root@pcmk-1 ~]# pcs resource status
      * ClusterIP	(ocf:heartbeat:IPaddr2):	 Started pcmk-1
      * WebSite	(ocf:heartbeat:apache):	 Started pcmk-1
      * Clone Set: WebData-clone [WebData] (promotable):
        * Promoted: [ pcmk-1 ]
        * Unpromoted: [ pcmk-2 ]
      * WebFS	(ocf:heartbeat:Filesystem):	 Started pcmk-1

Activate our new configuration, and see how the cluster responds:

.. code-block:: console

    [root@pcmk-1 ~]# pcs cluster cib-push dlm_cfg --config
    CIB updated
    [root@pcmk-1 ~]# pcs resource status
      * ClusterIP	(ocf:heartbeat:IPaddr2):	 Started pcmk-1
      * WebSite	(ocf:heartbeat:apache):	 Started pcmk-1
      * Clone Set: WebData-clone [WebData] (promotable):
        * Promoted: [ pcmk-1 ]
        * Unpromoted: [ pcmk-2 ]
      * WebFS	(ocf:heartbeat:Filesystem):	 Started pcmk-1
      * Clone Set: dlm-clone [dlm]:
        * Started: [ pcmk-1 pcmk-2 ]
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
     Clone: dlm-clone
      Meta Attributes: dlm-clone-meta_attributes
        interleave=true
        ordered=true
      Resource: dlm (class=ocf provider=pacemaker type=controld)
       Operations:
         monitor: dlm-monitor-interval-60s
           interval=60s
         start: dlm-start-interval-0s
           interval=0s timeout=90
         stop: dlm-stop-interval-0s
           interval=0s timeout=100

Create and Populate GFS2 Filesystem
###################################

Before we do anything to the existing partition, we need to make sure it
is unmounted. We do this by telling the cluster to stop the ``WebFS`` resource.
This will ensure that other resources (in our case, ``WebSite``) using
``WebFS`` are not only stopped, but stopped in the correct order.

.. code-block:: console

    [root@pcmk-1 ~]# pcs resource disable WebFS
    [root@pcmk-1 ~]# pcs resource
      * ClusterIP	(ocf:heartbeat:IPaddr2):	 Started pcmk-1
      * WebSite	(ocf:heartbeat:apache):	 Stopped
      * Clone Set: WebData-clone [WebData] (promotable):
        * Promoted: [ pcmk-1 ]
        * Unpromoted: [ pcmk-2 ]
      * WebFS	(ocf:heartbeat:Filesystem):	 Stopped (disabled)
      * Clone Set: dlm-clone [dlm]:
        * Started: [ pcmk-1 pcmk-2 ]

You can see that both ``WebSite`` and ``WebFS`` have been stopped, and that
``pcmk-1`` is currently running the promoted instance for the DRBD device.

Now we can create a new GFS2 filesystem on the DRBD device.

.. WARNING::

    This will erase all previous content stored on the DRBD device. Ensure
    you have a copy of any important data.

.. IMPORTANT::

    Run the next command on whichever node has the DRBD Primary role.
    Otherwise, you will receive the message:

    .. code-block:: console

        /dev/drbd1: Read-only file system

.. code-block:: console

    [root@pcmk-1 ~]# mkfs.gfs2 -p lock_dlm -j 2 -t mycluster:web /dev/drbd1
    It appears to contain an existing filesystem (xfs)
    This will destroy any data on /dev/drbd1
    Are you sure you want to proceed? [y/n] y
    Discarding device contents (may take a while on large devices): Done
    Adding journals: Done 
    Building resource groups: Done 
    Creating quota file: Done
    Writing superblock and syncing: Done
    Device:                    /dev/drbd1
    Block size:                4096
    Device size:               0.50 GB (131059 blocks)
    Filesystem size:           0.50 GB (131055 blocks)
    Journals:                  2
    Journal size:              8MB
    Resource groups:           4
    Locking protocol:          "lock_dlm"
    Lock table:                "mycluster:web"
    UUID:                      19712677-7206-4660-a079-5d17341dd720

The ``mkfs.gfs2`` command required a number of additional parameters:

* ``-p lock_dlm`` specifies that we want to use DLM-based locking.

* ``-j 2`` indicates that the filesystem should reserve enough
  space for two journals (one for each node that will access the filesystem).

* ``-t mycluster:web`` specifies the lock table name. The format for this
  field is ``<CLUSTERNAME>:<FSNAME>``. For ``CLUSTERNAME``, we need to use the
  same value we specified originally with ``pcs cluster setup --name`` (which is
  also the value of ``cluster_name`` in ``/etc/corosync/corosync.conf``). If
  you are unsure what your cluster name is, you can look in
  ``/etc/corosync/corosync.conf`` or execute the command
  ``pcs cluster corosync | grep cluster_name``.

Now we can (re-)populate the new filesystem with data
(web pages). We'll create yet another variation on our home page.

.. code-block:: console

    [root@pcmk-1 ~]# mount /dev/drbd1 /mnt
    [root@pcmk-1 ~]# cat <<-END >/mnt/index.html
    <html>
    <body>My Test Site - GFS2</body>
    </html>
    END
    [root@pcmk-1 ~]# chcon -R --reference=/var/www/html /mnt
    [root@pcmk-1 ~]# umount /dev/drbd1
    [root@pcmk-1 ~]# drbdadm verify wwwdata

Reconfigure the Cluster for GFS2
################################

With the ``WebFS`` resource stopped, let's update the configuration.

.. code-block:: console

    [root@pcmk-1 ~]# pcs resource config WebFS
     Resource: WebFS (class=ocf provider=heartbeat type=Filesystem)
      Attributes: WebFS-instance_attributes
        device=/dev/drbd1
        directory=/var/www/html
        fstype=xfs
      Meta Attributes: WebFS-meta_attributes
        target-role=Stopped
      Operations:
        monitor: WebFS-monitor-interval-20s
          interval=20s timeout=40s
        start: WebFS-start-interval-0s
          interval=0s timeout=60s
        stop: WebFS-stop-interval-0s
          interval=0s timeout=60s

The fstype option needs to be updated to ``gfs2`` instead of ``xfs``.

.. code-block:: console

    [root@pcmk-1 ~]# pcs resource update WebFS fstype=gfs2
    [root@pcmk-1 ~]# pcs resource config WebFS
     Resource: WebFS (class=ocf provider=heartbeat type=Filesystem)
      Attributes: WebFS-instance_attributes
        device=/dev/drbd1
        directory=/var/www/html
        fstype=gfs2
      Meta Attributes: WebFS-meta_attributes
        target-role=Stopped
      Operations:
        monitor: WebFS-monitor-interval-20s
          interval=20s timeout=40s
        start: WebFS-start-interval-0s
          interval=0s timeout=60s
        stop: WebFS-stop-interval-0s
          interval=0s timeout=60s

GFS2 requires that DLM be running, so we also need to set up new colocation
and ordering constraints for it:

.. code-block:: console

    [root@pcmk-1 ~]# pcs constraint colocation add WebFS with dlm-clone
    [root@pcmk-1 ~]# pcs constraint order dlm-clone then WebFS
    Adding dlm-clone WebFS (kind: Mandatory) (Options: first-action=start then-action=start)
    [root@pcmk-1 ~]# pcs constraint
    Location Constraints:
      resource 'WebSite' prefers node 'pcmk-2' with score 50
    Colocation Constraints:
      resource 'WebSite' with resource 'ClusterIP'
        score=INFINITY
      resource 'WebFS' with Promoted resource 'WebData-clone'
        score=INFINITY
      resource 'WebSite' with resource 'WebFS'
        score=INFINITY
      resource 'WebFS' with resource 'dlm-clone'
        score=INFINITY
    Order Constraints:
      start resource 'ClusterIP' then start resource 'WebSite'
      promote resource 'WebData-clone' then start resource 'WebFS'
      start resource 'WebFS' then start resource 'WebSite'
      start resource 'dlm-clone' then start resource 'WebFS'

We also need to update the ``no-quorum-policy`` property to ``freeze``. By
default, the value of ``no-quorum-policy`` is set to ``stop`` indicating that
once quorum is lost, all the resources on the remaining partition will
immediately be stopped. Typically this default is the safest and most optimal
option, but unlike most resources, GFS2 requires quorum to function. When
quorum is lost both the applications using the GFS2 mounts and the GFS2 mount
itself cannot be correctly stopped. Any attempts to stop these resources
without quorum will fail, which will ultimately result in the entire cluster
being fenced every time quorum is lost.

To address this situation, set ``no-quorum-policy`` to ``freeze`` when GFS2 is
in use. This means that when quorum is lost, the remaining partition will do
nothing until quorum is regained.

.. code-block:: console

    [root@pcmk-1 ~]# pcs property set no-quorum-policy=freeze


.. index::
   pair: filesystem; clone

Clone the Filesystem Resource
#############################

Now that we have a cluster filesystem ready to go, we can configure the cluster
so both nodes mount the filesystem.

Clone the ``Filesystem`` resource in a new configuration.
Notice how ``pcs`` automatically updates the relevant constraints again.

.. code-block:: console

    [root@pcmk-1 ~]# pcs cluster cib active_cfg
    [root@pcmk-1 ~]# pcs -f active_cfg resource clone WebFS
    [root@pcmk-1 ~]# pcs -f active_cfg constraint
    Location Constraints:
      resource 'WebSite' prefers node 'pcmk-2' with score 50
    Colocation Constraints:
      resource 'WebSite' with resource 'ClusterIP'
        score=INFINITY
      resource 'WebFS-clone' with Promoted resource 'WebData-clone'
        score=INFINITY
      resource 'WebSite' with resource 'WebFS-clone'
        score=INFINITY
      resource 'WebFS-clone' with resource 'dlm-clone'
        score=INFINITY
    Order Constraints:
      start resource 'ClusterIP' then start resource 'WebSite'
      promote resource 'WebData-clone' then start resource 'WebFS-clone'
      start resource 'WebFS-clone' then start resource 'WebSite'
      start resource 'dlm-clone' then start resource 'WebFS-clone'

Tell the cluster that it is now allowed to promote both instances to be DRBD
Primary.

.. code-block:: console

    [root@pcmk-1 ~]# pcs -f active_cfg resource update WebData-clone promoted-max=2

Finally, load our configuration to the cluster, and re-enable the ``WebFS``
resource (which we disabled earlier).

.. code-block:: console

    [root@pcmk-1 ~]# pcs cluster cib-push active_cfg --config
    CIB updated
    [root@pcmk-1 ~]# pcs resource enable WebFS

After all the processes are started, the status should look similar to this.

.. code-block:: console

    [root@pcmk-1 ~]# pcs resource
      * ClusterIP	(ocf:heartbeat:IPaddr2):	 Started pcmk-1
      * WebSite	(ocf:heartbeat:apache):	 Started pcmk-1
      * Clone Set: WebData-clone [WebData] (promotable):
        * Promoted: [ pcmk-1 pcmk-2 ]
      * Clone Set: dlm-clone [dlm]:
        * Started: [ pcmk-1 pcmk-2 ]
      * Clone Set: WebFS-clone [WebFS]:
        * Started: [ pcmk-1 pcmk-2 ]

Test Failover
#############

Testing failover is left as an exercise for the reader.

With this configuration, the data is now active/active. The website
administrator could change HTML files on either node, and the live website will
show the changes even if it is running on the opposite node.

If the web server is configured to listen on all IP addresses, it is possible
to remove the constraints between the ``WebSite`` and ``ClusterIP`` resources,
and clone the ``WebSite`` resource. The web server would always be ready to
serve web pages, and only the IP address would need to be moved in a failover.
