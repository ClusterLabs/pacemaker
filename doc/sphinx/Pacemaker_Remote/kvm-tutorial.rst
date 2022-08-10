.. index::
   single: guest node; walk-through

Guest Node Walk-through
-----------------------

**What this tutorial is:** An in-depth walk-through of how to get Pacemaker to
manage a KVM guest instance and integrate that guest into the cluster as a
guest node.

**What this tutorial is not:** A realistic deployment scenario. The steps shown
here are meant to get users familiar with the concept of guest nodes as quickly
as possible.

Configure Cluster Nodes
#######################

This walk-through assumes you already have a Pacemaker cluster configured. For examples, we will use a cluster with two cluster nodes named pcmk-1 and pcmk-2. You can substitute whatever your node names are, for however many nodes you have. If you are not familiar with setting up basic Pacemaker clusters, follow the walk-through in the Clusters From Scratch document before attempting this one.

You will need to add the remote node's hostname (we're using **guest1** in
this tutorial) to the cluster nodes' ``/etc/hosts`` files if you haven't already.
This is required unless you have DNS set up in a way where guest1's address can be
discovered.

Execute the following on each cluster node, replacing the IP address with the
actual IP address of the remote node.

.. code-block:: none

    # cat << END >> /etc/hosts
    192.168.122.10    guest1
    END

Install Virtualization Software
_______________________________

On each node within your cluster, install virt-install, libvirt, and qemu-kvm.
Start and enable libvirtd.

  .. code-block:: none

    # yum install -y virt-install libvirt qemu-kvm
    # systemctl start libvirtd
    # systemctl enable libvirtd

Reboot the host.

.. NOTE::

    While KVM is used in this example, any virtualization platform with a Pacemaker
    resource agent can be used to create a guest node. The resource agent needs
    only to support usual commands (start, stop, etc.); Pacemaker implements the
    **remote-node** meta-attribute, independent of the agent.

Configure the KVM guest
#######################

Create Guest
____________

Create a KVM guest to use as a guest node. Be sure to configure the guest with a
hostname and a static IP address (as an example here, we will use guest1 and 192.168.122.10).
Here's an example way to create a guest:

* Download an .iso file from the `CentOS Mirrors List <http://isoredirect.centos.org/centos/8-stream/isos/x86_64/>`_ into a directory on your cluster node.

* Run the following command, using your own path for the **location** flag:

  .. code-block:: none

    # virt-install \
      --name vm-guest1 \
      --ram 1024 \
      --disk path=./vm-guest1.qcow2,size=1 \
      --vcpus 2 \
      --os-type linux \
      --os-variant centos-stream8\
      --network bridge=virbr0 \
      --graphics none \
      --console pty,target_type=serial \
      --location <path to your .iso file> \
      --extra-args 'console=ttyS0,115200n8 serial'

.. index::
   single: guest node; firewall

Configure Firewall on Guest
___________________________

On each guest, allow cluster-related services through the local firewall.

Verify Connectivity
___________________

At this point, you should be able to ping and ssh into guests from hosts, and
vice versa.

Configure pacemaker_remote on Guest Node
________________________________________

Install the pacemaker_remote daemon on the guest node. We'll also install the
``pacemaker`` package. It isn't required for a guest node to run, but it
provides the ``crm_attribute`` tool, which many resource agents use.

.. code-block:: none

    # yum install -y pacemaker-remote resource-agents pcs pacemaker

Integrate Guest into Cluster
############################

Now the fun part, integrating the virtual machine you've just created into the
cluster. It is incredibly simple.

Start the Cluster
_________________

On the host, start Pacemaker.

.. code-block:: none

    # pcs cluster start

Wait for the host to become the DC.

Integrate Guest Node into Cluster
_________________________________

We will use the following command, which creates the VirtualDomain resource,
creates and copies the key, and enables pacemaker_remote:

.. code-block:: none

    # pcs cluster node add-guest guest1

Once the **vm-guest1** resource is started you will see **guest1** appear in the
``pcs status`` output as a node.  The final ``pcs status`` output should look
something like this, and you can see that it created the VirtualDomain resource:

.. code-block:: none

    # pcs status
    Cluster name: mycluster
    
    Cluster Summary:
      * Stack: corosync
      * Current DC: pcmk-1 (version 2.0.5-8.el8-ba59be7122) - partition with quorum
      * Last updated: Wed Mar 17 08:37:37 2021
      * Last change:  Wed Mar 17 08:31:01 2021 by root via cibadmin on pcmk-1
      * 3 nodes configured
      * 2 resource instances configured
    
    Node List:
      * Online: [ pcmk-1 pcmk-2 ]
      * GuestOnline: [ guest1@pcmk-1 ]

    Full List of Resources:
      * vm-guest1	(ocf::heartbeat:VirtualDomain):	 pcmk-1

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled

How pcs Configures the Guest
____________________________

To see that it created the key and copied it to all cluster nodes and the
guest, run:

.. code-block:: none

    # ls -l /etc/pacemaker

To see that it enables pacemaker_remote, run:

.. code-block:: none

    # systemctl status pacemaker_remote
    
    ● pacemaker_remote.service - Pacemaker Remote executor daemon
       Loaded: loaded (/usr/lib/systemd/system/pacemaker_remote.service; enabled; vendor preset: disabled)
       Active: active (running) since Wed 2021-03-17 08:31:01 EDT; 1min 5s ago
         Docs: man:pacemaker-remoted
               https://clusterlabs.org/pacemaker/doc/
     Main PID: 90160 (pacemaker-remot)
        Tasks: 1
       Memory: 1.4M
       CGroup: /system.slice/pacemaker_remote.service
               └─90160 /usr/sbin/pacemaker-remoted
    
    Mar 17 08:31:01 guest1 systemd[1]: Started Pacemaker Remote executor daemon.
    Mar 17 08:31:01 guest1 pacemaker-remoted[90160]:  notice: Additional logging available in /var/log/pacemaker/pacemaker.log
    Mar 17 08:31:01 guest1 pacemaker-remoted[90160]:  notice: Starting Pacemaker remote executor
    Mar 17 08:31:01 guest1 pacemaker-remoted[90160]:  notice: Pacemaker remote executor successfully started and accepting connections
.. NOTE::

    Pacemaker will automatically monitor pacemaker_remote connections for failure,
    so it is not necessary to create a recurring monitor on the **VirtualDomain**
    resource.

Starting Resources on KVM Guest
###############################

The commands below demonstrate how resources can be executed on both the
guest node and the cluster node.

Create a few Dummy resources.  Dummy resources are real resource agents used
just for testing purposes.  They actually execute on the host they are assigned
to just like an apache server or database would, except their execution just
means a file was created.  When the resource is stopped, that the file it
created is removed.

.. code-block:: none

    # for i in {1..5}; do pcs resource create FAKE${i} ocf:heartbeat:Dummy; done

Now check your ``pcs status`` output. In the resource section, you should see
something like the following, where some of the resources started on the
cluster node, and some started on the guest node.

.. code-block:: none

    Full List of Resources:
      * vm-guest1	(ocf::heartbeat:VirtualDomain):	 Started pcmk-1
      * FAKE1	(ocf::heartbeat:Dummy):	 Started guest1
      * FAKE2	(ocf::heartbeat:Dummy):	 Started guest1
      * FAKE3	(ocf::heartbeat:Dummy):	 Started pcmk-1
      * FAKE4	(ocf::heartbeat:Dummy):	 Started guest1
      * FAKE5	(ocf::heartbeat:Dummy):	 Started pcmk-1

The guest node, **guest1**, reacts just like any other node in the cluster. For
example, pick out a resource that is running on your cluster node. For my
purposes, I am picking FAKE3 from the output above. We can force FAKE3 to run
on **guest1** in the exact same way we would any other node.

.. code-block:: none

    # pcs constraint location FAKE3 prefers guest1

Now, looking at the bottom of the `pcs status` output you'll see FAKE3 is on
**guest1**.

.. code-block:: none

    Full List of Resources:
      * vm-guest1	(ocf::heartbeat:VirtualDomain):	 Started pcmk-1
      * FAKE1	(ocf::heartbeat:Dummy):	 Started guest1
      * FAKE2	(ocf::heartbeat:Dummy):	 Started guest1
      * FAKE3	(ocf::heartbeat:Dummy):	 Started guest1
      * FAKE4	(ocf::heartbeat:Dummy):	 Started pcmk-1
      * FAKE5	(ocf::heartbeat:Dummy):	 Started pcmk-1

Testing Recovery and Fencing
############################

Pacemaker's scheduler is smart enough to know fencing guest nodes
associated with a virtual machine means shutting off/rebooting the virtual
machine.  No special configuration is necessary to make this happen.  If you
are interested in testing this functionality out, trying stopping the guest's
pacemaker_remote daemon.  This would be equivalent of abruptly terminating a
cluster node's corosync membership without properly shutting it down.

ssh into the guest and run this command.

.. code-block:: none

    # kill -9 $(pidof pacemaker-remoted)

Within a few seconds, your ``pcs status`` output will show a monitor failure,
and the **guest1** node will not be shown while it is being recovered.

.. code-block:: none

    # pcs status
    Cluster name: mycluster
    
    Cluster Summary:
      * Stack: corosync
      * Current DC: pcmk-1 (version 2.0.5-8.el8-ba59be7122) - partition with quorum
      * Last updated: Wed Mar 17 08:37:37 2021
      * Last change:  Wed Mar 17 08:31:01 2021 by root via cibadmin on pcmk-1
      * 3 nodes configured
      * 7 resource instances configured
    
    Node List:
      * Online: [ pcmk-1 pcmk-2 ]
      * GuestOnline: [ guest1@pcmk-1 ]

    Full List of Resources:
      * vm-guest1	(ocf::heartbeat:VirtualDomain):	 pcmk-1
      * FAKE1	(ocf::heartbeat:Dummy):	 Stopped
      * FAKE2	(ocf::heartbeat:Dummy):	 Stopped
      * FAKE3	(ocf::heartbeat:Dummy):	 Stopped
      * FAKE4	(ocf::heartbeat:Dummy):	 Started pcmk-1
      * FAKE5	(ocf::heartbeat:Dummy):	 Started pcmk-1

    Failed Actions:
    * guest1_monitor_30000 on pcmk-1 'unknown error' (1): call=8, status=Error, exitreason='none',
        last-rc-change='Wed Mar 17 08:32:01 2021', queued=0ms, exec=0ms

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled


.. NOTE::

    A guest node involves two resources: the one you explicitly configured creates the guest,
    and Pacemaker creates an implicit resource for the pacemaker_remote connection, which
    will be named the same as the value of the **remote-node** attribute of the explicit resource.
    When we killed pacemaker_remote, it is the implicit resource that failed, which is why
    the failed action starts with **guest1** and not **vm-guest1**.

Once recovery of the guest is complete, you'll see it automatically get
re-integrated into the cluster.  The final ``pcs status`` output should look
something like this.

.. code-block:: none

    # pcs status
    Cluster name: mycluster
    
    Cluster Summary:
      * Stack: corosync
      * Current DC: pcmk-1 (version 2.0.5-8.el8-ba59be7122) - partition with quorum
      * Last updated: Wed Mar 17 08:37:37 2021
      * Last change:  Wed Mar 17 08:31:01 2021 by root via cibadmin on pcmk-1
      * 3 nodes configured
      * 7 resource instances configured
    
    Node List:
      * Online: [ pcmk-1 pcmk-2 ]
      * GuestOnline: [ guest1@pcmk-1 ]

    Full List of Resources:
      * vm-guest1	(ocf::heartbeat:VirtualDomain):	 pcmk-1
      * FAKE1	(ocf::heartbeat:Dummy):	 Stopped
      * FAKE2	(ocf::heartbeat:Dummy):	 Stopped
      * FAKE3	(ocf::heartbeat:Dummy):	 Stopped
      * FAKE4	(ocf::heartbeat:Dummy):	 Started pcmk-1
      * FAKE5	(ocf::heartbeat:Dummy):	 Started pcmk-1

    Failed Actions:
    * guest1_monitor_30000 on pcmk-1 'unknown error' (1): call=8, status=Error, exitreason='none',
        last-rc-change='Fri Jan 12 18:08:29 2018', queued=0ms, exec=0ms

    Daemon Status:
      corosync: active/disabled
      pacemaker: active/disabled
      pcsd: active/enabled

Normally, once you've investigated and addressed a failed action, you can clear the
failure. However Pacemaker does not yet support cleanup for the implicitly
created connection resource while the explicit resource is active. If you want
to clear the failed action from the status output, stop the guest resource before
clearing it. For example:

.. code-block:: none

    # pcs resource disable vm-guest1 --wait
    # pcs resource cleanup guest1
    # pcs resource enable vm-guest1

Accessing Cluster Tools from Guest Node
#######################################

Besides allowing the cluster to manage resources on a guest node,
pacemaker_remote has one other trick. The pacemaker_remote daemon allows
nearly all the pacemaker tools (``crm_resource``, ``crm_mon``, ``crm_attribute``,
etc.) to work on guest nodes natively.

Try it: Run ``crm_mon`` on the guest after pacemaker has
integrated the guest node into the cluster. These tools just work. This
means resource agents such as promotable resources (which need access to tools
like ``crm_attribute``) work seamlessly on the guest nodes.

Higher-level command shells such as ``pcs`` may have partial support
on guest nodes, but it is recommended to run them from a cluster node.

Guest nodes will show up in ``crm_mon`` output as normal.  For example, this is the
``crm_mon`` output after **guest1** is integrated into the cluster:

.. code-block:: none

    Cluster name: mycluster
    
    Cluster Summary:
      * Stack: corosync
      * Current DC: pcmk-1 (version 2.0.5-8.el8-ba59be7122) - partition with quorum
      * Last updated: Wed Mar 17 08:37:37 2021
      * Last change:  Wed Mar 17 08:31:01 2021 by root via cibadmin on pcmk-1
      * 2 nodes configured
      * 2 resource instances configured
    
    Node List:
      * Online: [ pcmk-1 ]
      * GuestOnline: [ guest1@pcmk-1 ]

    Full List of Resources:
      * vm-guest1	(ocf::heartbeat:VirtualDomain):	 Started pcmk-1

Now, you could place a resource, such as a webserver, on **guest1**:

.. code-block:: none

    # pcs resource create webserver apache params configfile=/etc/httpd/conf/httpd.conf op monitor interval=30s
    # pcs constraint location webserver prefers guest1

Now, the crm_mon output would show:

.. code-block:: none

    Cluster name: mycluster
    
    Cluster Summary:
      * Stack: corosync
      * Current DC: pcmk-1 (version 2.0.5-8.el8-ba59be7122) - partition with quorum
      * Last updated: Wed Mar 17 08:38:37 2021
      * Last change:  Wed Mar 17 08:35:01 2021 by root via cibadmin on pcmk-1
      * 2 nodes configured
      * 3 resource instances configured
    
    Node List:
      * Online: [ pcmk-1 ]
      * GuestOnline: [ guest1@pcmk-1 ]

    Full List of Resources:
      * vm-guest1	(ocf::heartbeat:VirtualDomain): Started pcmk-1
      * webserver	(ocf::heartbeat::apache):       Started guest1

It is worth noting that after **guest1** is integrated into the cluster, nearly all the
Pacemaker command-line tools immediately become available to the guest node.
This means things like ``crm_mon``, ``crm_resource``, and ``crm_attribute`` will work
natively on the guest node, as long as the connection between the guest node
and a cluster node exists. This is particularly important for any promotable
clone resources executing on the guest node that need access to
``crm_attribute`` to set promotion scores.

Mile-High View of Configuration Steps
#####################################

The command used in `Integrate Guest Node into Cluster`_ does multiple things.
If you'd like to each part manually, you can do so as follows. You'll see that the
end result is the same:

* Later, we are going to put the same authentication key with the path
  ``/etc/pacemaker/authkey`` on every cluster node and on every virtual machine.
  This secures remote communication.

  Run this command on your cluster node if you want to make a somewhat random key:

  .. code-block:: none

     # dd if=/dev/urandom of=/etc/pacemaker/authkey bs=4096 count=1


* To create the VirtualDomain resource agent for the management of the virtual
  machine, Pacemaker requires the virtual machine's xml config file to be dumped
  to a file -- which we can name as we'd like -- on disk. We named our virtual
  machine guest1; for this example, we'll dump to the file /etc/pacemaker/guest1.xml

  .. code-block:: none

    # virsh dumpxml guest1 > /etc/pacemaker/guest1.xml

* Install pacemaker_remote on the virtual machine, and if a local firewall is used,
  allow the node to accept connections on TCP port 3121.

  .. code-block:: none

    # yum install pacemaker-remote resource-agents
    # firewall-cmd --add-port 3121/tcp --permanent

  .. NOTE::

      If you just want to see this work, you may want to simply disable the local
      firewall and put SELinux in permissive mode while testing. This creates
      security risks and should not be done on a production machine exposed to the
      Internet, but can be appropriate for a protected test machine.

* On a cluster node, create a Pacemaker VirtualDomain resource to launch the virtual machine.

  .. code-block:: none

    [root@pcmk-1 ~]# pcs resource create vm-guest1 VirtualDomain hypervisor="qemu:///system" config="vm-guest1.xml" meta
    Assumed agent name 'ocf:heartbeat:VirtualDomain' (deduced from 'VirtualDomain')

* Now use the following command to convert the VirtualDomain resource into a guest node
  which we'll name guest1. By doing so, the /etc/pacemaker/authkey will get copied to
  the guest node and the pacemaker_remote daemon will get started and enabled on the
  guest node as well.

  .. code-block:: none

    [root@pcmk-1 ~]# pcs cluster node add-guest guest1 vm-guest1
    No addresses specified for host 'guest1', using 'guest1'
    Sending 'pacemaker authkey' to 'guest1'
    guest1: successful distribution of the file 'pacemaker authkey'
    Requesting 'pacemaker_remote enable', 'pacemaker_remote start' on 'guest1'
    guest1: successful run of 'pacemaker_remote enable'
    guest1: successful run of 'pacemaker_remote start'

*  This will create CIB XML similar to the following:

  .. code-block:: xml

     <primitive class="ocf" id="vm-guest1" provider="heartbeat" type="VirtualDomain">
       <meta_attributes id="vm-guest1-meta_attributes">
         <nvpair id="vm-guest1-meta_attributes-remote-addr" name="remote-addr" value="guest1"/>
         <nvpair id="vm-guest1-meta_attributes-remote-node" name="remote-node" value="guest1"/>
       </meta_attributes>
       <instance_attributes id="vm-guest1-instance_attributes">
         <nvpair id="vm-guest1-instance_attributes-config" name="config" value="vm-guest1.xml"/>
         <nvpair id="vm-guest1-instance_attributes-hypervisor" name="hypervisor" value="qemu:///system"/>
       </instance_attributes>
       <operations>
         <op id="vm-guest1-migrate_from-interval-0s" interval="0s" name="migrate_from" timeout="60s"/>
         <op id="vm-guest1-migrate_to-interval-0s" interval="0s" name="migrate_to" timeout="120s"/>
         <op id="vm-guest1-monitor-interval-10s" interval="10s" name="monitor" timeout="30s"/>
         <op id="vm-guest1-start-interval-0s" interval="0s" name="start" timeout="90s"/>
         <op id="vm-guest1-stop-interval-0s" interval="0s" name="stop" timeout="90s"/>
       </operations>
     </primitive>

  .. code-block:: xml

    [root@pcmk-1 ~]# pcs resource status
      * vm-guest1 (ocf::heartbeat:VirtualDomain): Stopped

    [root@pcmk-1 ~]# pcs resource config
     Resource: vm-guest1 (class=ocf provider=heartbeat type=VirtualDomain)
      Attributes: config=vm-guest1.xml hypervisor=qemu:///system
      Meta Attrs: remote-addr=guest1 remote-node=guest1
      Operations: migrate_from interval=0s timeout=60s (vm-guest1-migrate_from-interval-0s)
                  migrate_to interval=0s timeout=120s (vm-guest1-migrate_to-interval-0s)
                  monitor interval=10s timeout=30s (vm-guest1-monitor-interval-10s)
                  start interval=0s timeout=90s (vm-guest1-start-interval-0s)
                  stop interval=0s timeout=90s (vm-guest1-stop-interval-0s)

The cluster will attempt to contact the virtual machine's pacemaker_remote service at the
hostname **guest1** after it launches.

.. NOTE::

    The ID of the resource creating the virtual machine (**vm-guest1** in the above
    example) 'must' be different from the virtual machine's uname (**guest1** in the
    above example). Pacemaker will create an implicit internal resource for the
    pacemaker_remote connection to the guest, named with the value of **remote-node**,
    so that value cannot be used as the name of any other resource.

Troubleshooting a Remote Connection
###################################

Note: This section should not be done when the guest is connected to the cluster.

Should connectivity issues occur, it can be worth verifying that the cluster nodes
can contact the remote node on port 3121. Here's a trick you can use.
Connect using ssh from each of the cluster nodes. The connection will get
destroyed, but how it is destroyed tells you whether it worked or not.

If running the ssh command on one of the cluster nodes results in this
output before disconnecting, the connection works:

.. code-block:: none

    # ssh -p 3121 guest1
    ssh_exchange_identification: read: Connection reset by peer

If you see one of these, the connection is not working:

.. code-block:: none

    # ssh -p 3121 guest1
    ssh: connect to host guest1 port 3121: No route to host

.. code-block:: none

    # ssh -p 3121 guest1
    ssh: connect to host guest1 port 3121: Connection refused

If you see this, then the connection is working, but port 3121 is attached
to SSH, which it should not be.

.. code-block:: none

    # ssh -p 3121 guest1
    kex_exchange_identification: banner line contains invalid characters

Once you can successfully connect to the guest from the host, you may
shutdown the guest. Pacemaker will be managing the virtual machine from
this point forward.
