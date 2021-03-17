.. index::
   single: guest node; example

Guest Node Quick Example
------------------------

If you already know how to use Pacemaker, you'll likely be able to grasp this
new concept of guest nodes by reading through this quick example without
having to sort through all the detailed walk-through steps. Here are the key
configuration ingredients that make this possible using libvirt and KVM virtual
guests. These steps strip everything down to the very basics.


Mile-High View of Configuration Steps
#####################################

* On a node within your cluster, install virt-install, libvirt, and qemu-kvm.
  Start and enable libvirtd.

  .. code-block:: none

    # yum install virt-install libvirt qemu-kvmkvm
    # systemctl start libvirt
    # systemctl enable libvirt

* Later, we are going to put the same authentication key with the path
  ``/etc/pacemaker/authkey`` on every cluster node and on every virtual machine.
  This secures remote communication.

  Run this command on your cluster node if you want to make a somewhat random key:

  .. code-block:: none

     # dd if=/dev/urandom of=/etc/pacemaker/authkey bs=4096 count=1

* Add the following two lines of code to /etc/libvirt/qemu.conf
  to set the permissions that'll allow us to create a virtual machine from your
  node console in the following step.

    # user = "root"
    # group = "root"

* For this example, we'll create just one virtual machine to use as a guest node,
  using the following command.

  .. code-block:: none

    # virt-install \
      --name k1 \
      --ram 1024 \
      --disk path=./centos7.qcow2,size=1 \
      --vcpus 1 \
      --os-type linux \
      --os-variant centos7.0 \
      --network bridge=virbr0 \
      --graphics none \
      --console pty,target_type=serial \
      --location 'http://mirror.i3d.net/pub/centos/7/os/x86_64/' \
      --extra-args 'console=ttyS0,115200n8 serial' // TODO: Kickstart

* Give the virtual machine a static network address and unique hostname when you
  configure it.

* To create the VirtualDomain resource agent for the management of the virtual
  machine, Pacemaker requires the virtual machine's xml config file to be dumped
  to a file -- which we can name as we'd like -- on disk. We named our virutal
  machine guest1; for this example, we'll dump to the file /etc/pacemaker/guest1.xml

  .. code-block:: none

    # virsh dumpxml guest1 > /etc/pacemaker/guest1.xml

* Install pacemaker_remote on the virtual machine, enabling it to start at
  boot, and if a local firewall is used, allow the node to accept connections
  on TCP port 3121.

  .. code-block:: none

    # yum install pacemaker-remote resource-agents
    # systemctl enable pacemaker_remote
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

Using a Guest Node
==================

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
      * Online: [ node1 ]
      * GuestOnline: [ guest1@node1 ]

    Full List of Resources:
      * vm-guest1	(ocf::heartbeat:VirtualDomain):	 Started node1

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
      * Online: [ node1 ]
      * GuestOnline: [ guest1@node1 ]

    Full List of Resources:
      * vm-guest1	(ocf::heartbeat:VirtualDomain): Started node1
      * webserver	(ocf::heartbeat::apache):       Started guest1

It is worth noting that after **guest1** is integrated into the cluster, nearly all the
Pacemaker command-line tools immediately become available to the guest node.
This means things like ``crm_mon``, ``crm_resource``, and ``crm_attribute`` will work
natively on the guest node, as long as the connection between the guest node
and a cluster node exists. This is particularly important for any promotable
clone resources executing on the guest node that need access to ``crm_master`` to
set transient attributes.
