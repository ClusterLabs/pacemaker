.. index::
   single: storage; active/active

Convert Storage to Active/Active
--------------------------------

The primary requirement for an Active/Active cluster is that the data
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

On both nodes, install the GFS2 command-line utilities required by
cluster filesystems:

.. code-block:: none

    # yum install -y gfs2-utils

Additionally, install Distributed Lock Manager (DLM) on both nodes.
To do so, download the RPM from the `CentOS composes artifacts tree <https://composes.centos.org/latest-CentOS-Stream-8/compose/ResilientStorage/x86_64/os/Packages/>`_,
onto your nodes and then run the following
command:

.. code-block:: none

    # rpm -i dlm-4.1.0-1.el8.x86_64.rpm

Configure the Cluster for the DLM
#################################

The DLM control daemon needs to run on both nodes, so we'll start by creating a
resource for it (using the **ocf:pacemaker:controld** resource script), and clone
it:

.. code-block:: none

    [root@pcmk-1 ~]# pcs cluster cib dlm_cfg
    [root@pcmk-1 ~]# pcs -f dlm_cfg resource create dlm \
        ocf:pacemaker:controld op monitor interval=60s
    [root@pcmk-1 ~]# pcs -f dlm_cfg resource clone dlm clone-max=2 clone-node-max=1
    [root@pcmk-1 ~]# pcs resource status
      * ClusterIP	(ocf::heartbeat:IPaddr2):	 Started pcmk-2
      * WebSite	(ocf::heartbeat:apache):	 Started pcmk-2
      * Clone Set: WebData-clone [WebData] (promotable):
        * Masters: [ pcmk-2 ]
        * Slaves: [ pcmk-1 ]
      * WebFS	(ocf::heartbeat:Filesystem):	 Started pcmk-2
    [root@pcmk-1 ~]# pcs resource config
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
      Meta Attrs: clone-max=2 clone-node-max=1 notify=true promotable=true promoted-max=1 promoted-node-max=1
      Resource: WebData (class=ocf provider=linbit type=drbd)
       Attributes: drbd_resource=wwwdata
       Operations: demote interval=0s timeout=90 (WebData-demote-interval-0s)
                   monitor interval=60s (WebData-monitor-interval-60s)
                   notify interval=0s timeout=90 (WebData-notify-interval-0s)
                   promote interval=0s timeout=90 (WebData-promote-interval-0s)
                   reload interval=0s timeout=30 (WebData-reload-interval-0s)
                   start interval=0s timeout=240 (WebData-start-interval-0s)
                   stop interval=0s timeout=100 (WebData-stop-interval-0s)
     Resource: WebFS (class=ocf provider=heartbeat type=Filesystem)
      Attributes: device=/dev/drbd1 directory=/var/www/html fstype=xfs
      Operations: monitor interval=20s timeout=40s (WebFS-monitor-interval-20s)
                  start interval=0s timeout=60s (WebFS-start-interval-0s)
                  stop interval=0s timeout=60s (WebFS-stop-interval-0s)

Activate our new configuration, and see how the cluster responds:

.. code-block:: none

    [root@pcmk-1 ~]# pcs cluster cib-push dlm_cfg --config
    CIB updated
    [root@pcmk-1 ~]# pcs status
    Cluster name: mycluster
    Cluster Summary:
      * Stack: corosync
      * Current DC: pcmk-2 (version 2.1.0-3.el8-7c3f660707) - partition with quorum
      * Last updated: Wed Jul 13 10:57:20 2021
      * Last change:  Wed Jul 13 10:57:15 2021 by root via cibadmin on pcmk-1
      * 2 nodes configured
      * 7 resource instances configured

    Node List:
      * Online: [ pcmk-1 pcmk-2 ]

    Full List of Resources:
      * ClusterIP	(ocf::heartbeat:IPaddr2):	 Started pcmk-1
      * WebSite	(ocf::heartbeat:apache):	 Started pcmk-1
      * Clone Set: WebData-clone [WebData] (promotable):
        * Masters: [ pcmk-1 ]
        * Slaves: [ pcmk-2 ]
      * WebFS	(ocf::heartbeat:Filesystem):	 Started pcmk-1
      * Clone Set: dlm-clone [dlm]:
        * Started: [ pcmk-1 pcmk-2 ]

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled

Create and Populate GFS2 Filesystem
###################################

Before we do anything to the existing partition, we need to make sure it
is unmounted. We do this by telling the cluster to stop the WebFS resource.
This will ensure that other resources (in our case, Apache) using WebFS
are not only stopped, but stopped in the correct order.

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource disable WebFS
    [root@pcmk-1 ~]# pcs resource
      * ClusterIP	(ocf::heartbeat:IPaddr2):	 Started pcmk-1
      * WebSite	(ocf::heartbeat:apache):	 Stopped
      * Clone Set: WebData-clone [WebData] (promotable):
        * Masters: [ pcmk-1 ]
        * Slaves: [ pcmk-2 ]
      * WebFS	(ocf::heartbeat:Filesystem):	 Stopped (disabled)
      * Clone Set: dlm-clone [dlm]:
        * Started: [ pcmk-1 pcmk-2 ]

You can see that both Apache and WebFS have been stopped, and that **pcmk-1**
is currently running the promoted instance for the DRBD device.

Now we can create a new GFS2 filesystem on the DRBD device.

.. WARNING::

    This will erase all previous content stored on the DRBD device. Ensure
    you have a copy of any important data.

.. IMPORTANT::

    Run the next command on whichever node has the DRBD Primary role.
    Otherwise, you will receive the message:

    .. code-block:: none

        /dev/drbd1: Read-only file system

.. code-block:: none

    [root@pcmk-2 ~]# mkfs.gfs2 -p lock_dlm -j 2 -t mycluster:web /dev/drbd1
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
  also the value of **cluster_name** in ``/etc/corosync/corosync.conf``). If
  you are unsure what your cluster name is, you can look in
  ``/etc/corosync/corosync.conf`` or execute the command
  ``pcs cluster corosync | grep cluster_name``.

Now we can (re-)populate the new filesystem with data
(web pages). We'll create yet another variation on our home page.

.. code-block:: none

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

With the WebFS resource stopped, let's update the configuration.

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource config WebFS
     Resource: WebFS (class=ocf provider=heartbeat type=Filesystem)
       Attributes: device=/dev/drbd1 directory=/var/www/html fstype=xfs
       Meta Attrs: target-role=Stopped
       Operations: monitor interval=20s timeout=40s (WebFS-monitor-interval-20s)
                   start interval=0s timeout=60s (WebFS-start-interval-0s)
                   stop interval=0s timeout=60s (WebFS-stop-interval-0s)

The fstype option needs to be updated to **gfs2** instead of **xfs**.

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource update WebFS fstype=gfs2
    [root@pcmk-1 ~]# pcs resource config WebFS
     Resource: WebFS (class=ocf provider=heartbeat type=Filesystem)
       Attributes: device=/dev/drbd1 directory=/var/www/html fstype=gfs2
       Meta Attrs: target-role=Stopped
       Operations: monitor interval=20s timeout=40s (WebFS-monitor-interval-20s)
                   start interval=0s timeout=60s (WebFS-start-interval-0s)
                   stop interval=0s timeout=60s (WebFS-stop-interval-0s)

GFS2 requires that DLM be running, so we also need to set up new colocation
and ordering constraints for it:

.. code-block:: none

    [root@pcmk-1 ~]# pcs constraint colocation add WebFS with dlm-clone INFINITY
    [root@pcmk-1 ~]# pcs constraint order dlm-clone then WebFS
    Adding dlm-clone WebFS (kind: Mandatory) (Options: first-action=start then-action=start)

We also need to update the **no-quorum-policy** property to **freeze**. By
default, the value of **no-quorum-policy** is set to **stop**, indicating that
once quorum is lost, all the resources on the remaining partition will
immediately be stopped. Typically this default is the safest and most optimal
option, but unlike most resources, GFS2 requires quorum to function. When
quorum is lost both the applications using the GFS2 mounts and the GFS2 mount
itself cannot be correctly stopped. Any attempts to stop these resources
without quorum will fail, which will ultimately result in the entire cluster
being fenced every time quorum is lost.

To address this situation, set **no-quorum-policy** to **freeze** when GFS2 is
in use. This means that when quorum is lost, the remaining partition will do
nothing until quorum is regained. 

.. code-block:: none

    [root@pcmk-1 ~]# pcs property set no-quorum-policy=freeze


.. index::
   pair: filesystem; clone

Clone the Filesystem Resource
#############################

Now that we have a cluster filesystem ready to go, we can configure the cluster
so both nodes mount the filesystem.

Clone the filesystem resource in a new configuration.
Notice how pcs automatically updates the relevant constraints again.

.. code-block:: none

    [root@pcmk-1 ~]# pcs cluster cib active_cfg
    [root@pcmk-1 ~]# pcs -f active_cfg resource clone WebFS
    [root@pcmk-1 ~]# pcs -f active_cfg constraint
    [root@pcmk-1 ~]# pcs -f active_cfg constraint
    Location Constraints:
      Resource: WebSite
        Enabled on:
          Node: pcmk-1 (score:50)
    Ordering Constraints:
      start ClusterIP then start WebSite (kind:Mandatory)
      promote WebData-clone then start WebFS-clone (kind:Mandatory)
      start WebFS-clone then start WebSite (kind:Mandatory)
    Colocation Constraints:
      WebSite with ClusterIP (score:INFINITY)
      WebFS-clone with WebData-clone (score:INFINITY) (with-rsc-role:Master)
      WebSite with WebFS-clone (score:INFINITY)
    Ticket Constraints:

Tell the cluster that it is now allowed to promote both instances to be DRBD
Primary.

.. code-block:: none

    [root@pcmk-1 ~]# pcs -f active_cfg resource update WebData-clone promoted-max=2

Finally, load our configuration to the cluster, and re-enable the WebFS resource
(which we disabled earlier).

.. code-block:: none

    [root@pcmk-1 ~]# pcs cluster cib-push active_cfg --config
    CIB updated
    [root@pcmk-1 ~]# pcs resource enable WebFS

After all the processes are started, the status should look similar to this.

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource
    [root@pcmk-1 ~]# pcs resource
      * ClusterIP	(ocf::heartbeat:IPaddr2):	 Started pcmk-1
      * WebSite	(ocf::heartbeat:apache):	 Started pcmk-1
      * Clone Set: WebData-clone [WebData] (promotable):
        * Masters: [ pcmk-1 pcmk-2 ]
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
to remove the constraints between the WebSite and ClusterIP resources, and
clone the WebSite resource. The web server would always be ready to serve web
pages, and only the IP address would need to be moved in a failover.
