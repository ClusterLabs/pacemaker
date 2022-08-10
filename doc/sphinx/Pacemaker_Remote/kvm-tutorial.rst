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

On each guest, allow cluster-related services through the local firewall. If
you're using ``firewalld``, run the following commands.

.. code-block:: none

    [root@guest1 ~]# firewall-cmd --permanent --add-service=high-availability
    success
    [root@guest1 ~]# firewall-cmd --reload
    success

.. NOTE::

    If you are using some other firewall solution besides firewalld,
    simply open the following ports, which can be used by various
    clustering components: TCP ports 2224, 3121, and 21064.

    If you run into any problems during testing, you might want to disable
    the firewall and SELinux entirely until you have everything working.
    This may create significant security issues and should not be performed on
    machines that will be exposed to the outside world, but may be appropriate
    during development and testing on a protected host.

    To disable security measures:

    .. code-block:: none

        [root@guest1 ~]# setenforce 0
        [root@guest1 ~]# sed -i.bak "s/SELINUX=enforcing/SELINUX=permissive/g" \
            /etc/selinux/config
        [root@guest1 ~]# systemctl mask firewalld.service
        [root@guest1 ~]# systemctl stop firewalld.service

Configure ``/etc/hosts``
________________________

You will need to add the remote node's hostname (we're using **guest1** in
this tutorial) to the cluster nodes' ``/etc/hosts`` files if you haven't already.
This is required unless you have DNS set up in a way where guest1's address can be
discovered.

For each guest, execute the following on each cluster node and on the guests,
replacing the IP address with the actual IP address of the guest node.

.. code-block:: none

    # cat << END >> /etc/hosts
    192.168.122.10  guest1
    END

Also add entries for each cluster node to the ``/etc/hosts`` file on each guest.
For example:

.. code-block:: none

   # cat << END >> /etc/hosts
   192.168.122.101  pcmk-1
   192.168.122.102  pcmk-2
   END

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

On the host, start Pacemaker if it's not already running.

.. code-block:: none

    # pcs cluster start

Create a ``VirtualDomain`` Resource for the Guest VM
____________________________________________________

For this simple walk-through, we have created the VM and made its disk
available only on node ``pcmk-1``, so that's the only node where the VM is
capable of running. In a more realistic scenario, you'll probably want to have
multiple nodes that are capable of running the VM.

Next we'll assign an attribute to node 1 that denotes its eligibility to host
``vm-guest1``. If other nodes are capable of hosting your guest VM, then add the
attribute to each of those nodes as well.

.. code-block:: none

    [root@pcmk-1 ~]# pcs node attribute pcmk-1 can-host-vm-guest1=1

Then we'll create a ``VirtualDomain`` resource so that Pacemaker can manage
``vm-guest1``. Be sure to replace the XML file path below with your own if it
differs. We'll also create a rule to prevent Pacemaker from trying to start the
resource or probe its status on any node that isn't capable of running the VM.
We'll save the CIB to a file, make both of these edits, and push them
simultaneously.

.. code-block:: none

    [root@pcmk-1 ~]# pcs cluster cib vm_cfg
    [root@pcmk-1 ~]# pcs -f vm_cfg resource create vm-guest1 VirtualDomain \
        hypervisor="qemu:///system" config="/etc/libvirt/qemu/vm-guest1.xml"
    Assumed agent name 'ocf:heartbeat:VirtualDomain' (deduced from 'VirtualDomain')
    [root@pcmk-1 ~]# pcs -f vm_cfg constraint location vm-guest1 rule \
        resource-discovery=never score=-INFINITY can-host-vm-guest1 ne 1
    [root@pcmk-1 ~]# pcs cluster cib-push --config vm_cfg --wait

.. NOTE::

    If all nodes in your cluster are capable of hosting the VM that you've
    created, then you can skip the ``pcs node attribute`` and ``pcs constraint
    location`` commands.

.. NOTE::

    The ID of the resource managing the virtual machine (``vm-guest1`` in the
    above example) **must** be different from the virtual machine's node name
    (``guest1`` in the above example). Pacemaker will create an implicit
    internal resource for the Pacemaker Remote connection to the guest. This
    implicit resource will be named with the value of the ``VirtualDomain``
    resource's ``remote-node`` meta attribute, which will be set by ``pcs`` to
    the guest node's node name. Therefore, that value cannot be used as the name
    of any other resource.

Now we can confirm that the ``VirtualDomain`` resource is running on ``pcmk-1``.

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource status
      * vm-guest1	(ocf:heartbeat:VirtualDomain):	 Started pcmk-1

Prepare ``pcsd``
________________

Now we need to prepare ``pcsd`` on the guest so that we can use ``pcs`` commands
to communicate with it.

Start and enable the ``pcsd`` daemon on the guest.

.. code-block:: none

    [root@guest1 ~]# systemctl start pcsd
    [root@guest1 ~]# systemctl enable pcsd
    Created symlink /etc/systemd/system/multi-user.target.wants/pcsd.service → /usr/lib/systemd/system/pcsd.service.

Next, set a password for the ``hacluster`` user on the guest.

.. code-block:: none

    [root@guest1 ~]# echo MyPassword | passwd --stdin hacluster
    Changing password for user hacluster.
    passwd: all authentication tokens updated successfully.

Now authenticate the existing cluster nodes to ``pcsd`` on the guest. The below
command only needs to be run from one cluster node.

.. code-block:: none

    [root@pcmk-1 ~]# pcs host auth guest1 -u hacluster
    Password: 
    guest1: Authorized

Integrate Guest Node into Cluster
_________________________________

We're finally ready to integrate the VM into the cluster as a guest node. Run
the following command, which will create a guest node from the ``VirtualDomain``
resource and take care of all the remaining steps. Note that the format is ``pcs
cluster node add-guest <guest_name> <vm_resource_name>``.

.. code-block:: none

    [root@pcmk-1 ~]# pcs cluster node add-guest guest1 vm-guest1
    No addresses specified for host 'guest1', using 'guest1'
    Sending 'pacemaker authkey' to 'guest1'
    guest1: successful distribution of the file 'pacemaker authkey'
    Requesting 'pacemaker_remote enable', 'pacemaker_remote start' on 'guest1'
    guest1: successful run of 'pacemaker_remote enable'
    guest1: successful run of 'pacemaker_remote start'

You should soon see ``guest1`` appear in the ``pcs status`` output as a node.
The output should look something like this:

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

The resulting configuration should look something like the following:

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource config
     Resource: vm-guest1 (class=ocf provider=heartbeat type=VirtualDomain)
      Attributes: config=/etc/libvirt/qemu/vm-guest1.xml hypervisor=qemu:///system
      Meta Attrs: remote-addr=guest1 remote-node=guest1
      Operations: migrate_from interval=0s timeout=60s (vm-guest1-migrate_from-interval-0s)
                  migrate_to interval=0s timeout=120s (vm-guest1-migrate_to-interval-0s)
                  monitor interval=10s timeout=30s (vm-guest1-monitor-interval-10s)
                  start interval=0s timeout=90s (vm-guest1-start-interval-0s)
                  stop interval=0s timeout=90s (vm-guest1-stop-interval-0s)

How pcs Configures the Guest
____________________________

Let's take a closer look at what the ``pcs cluster node add-guest`` command is
doing. There is no need to run any of the commands in this section.

First, ``pcs`` copies the Pacemaker authkey file to the VM that will become the
guest. If an authkey is not already present on the cluster nodes, this command
creates one and distributes it to the existing nodes and to the guest.

If you want to do this manually, you can run a command like the following to
generate an authkey in ``/etc/pacemaker/authkey``, and then distribute the key
to the rest of the nodes and to the new guest.

.. code-block:: none

    [root@pcmk-1 ~]# dd if=/dev/urandom of=/etc/pacemaker/authkey bs=4096 count=1

Then ``pcs`` starts and enables the ``pacemaker_remote`` service on the guest.
If you want to do this manually, run the following commands.

.. code-block:: none

    [root@guest1 ~]# systemctl start pacemaker_remote
    [root@guest1 ~]# systemctl enable pacemaker_remote

Finally, ``pcs`` creates a guest node from the ``VirtualDomain`` resource by
adding ``remote-addr`` and ``remote-node`` meta attributes to the resource. If
you want to do this manually, you can run the following command if you're using
``pcs``. Alternativately, run an equivalent command if you're using another
cluster shell, or edit the CIB manually.

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource update vm-guest1 meta remote-addr='guest1' \
        remote-node='guest1' --force

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
