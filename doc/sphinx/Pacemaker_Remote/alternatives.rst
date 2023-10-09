Alternative Configurations
--------------------------

These alternative configurations may be appropriate in limited cases, such as a
test cluster, but are not the best method in most situations. They are
presented here for completeness and as an example of Pacemaker's flexibility
to suit your needs.

.. index::
   single: virtual machine; as cluster node

Virtual Machines as Cluster Nodes
#################################

The preferred use of virtual machines in a Pacemaker cluster is as a
cluster resource, whether opaque or as a guest node. However, it is
possible to run the full cluster stack on a virtual node instead.

This is commonly used to set up test environments; a single physical host
(that does not participate in the cluster) runs two or more virtual machines,
all running the full cluster stack. This can be used to simulate a
larger cluster for testing purposes.

In a production environment, fencing becomes more complicated, especially
if the underlying hosts run any services besides the clustered VMs.
If the VMs are not guaranteed a minimum amount of host resources,
CPU and I/O contention can cause timing issues for cluster components.

Another situation where this approach is sometimes used is when
the cluster owner leases the VMs from a provider and does not have
direct access to the underlying host. The main concerns in this case
are proper fencing (usually via a custom resource agent that communicates
with the provider's APIs) and maintaining a static IP address between reboots,
as well as resource contention issues.

.. index::
   single: virtual machine; as remote node

Virtual Machines as Remote Nodes
################################

Virtual machines may be configured following the process for remote nodes 
rather than guest nodes (i.e., using an **ocf:pacemaker:remote** resource
rather than letting the cluster manage the VM directly).

This is mainly useful in testing, to use a single physical host to simulate a
larger cluster involving remote nodes. Pacemaker's Cluster Test Suite (CTS)
uses this approach to test remote node functionality.

.. index::
   single: container; as guest node
   single: container; LXC
   single: container; Docker
   single: container; bundle
   single: LXC
   single: Docker
   single: bundle

Containers as Guest Nodes
#########################

`Containers <https://en.wikipedia.org/wiki/Operating-system-level_virtualization>`_
and in particular Linux containers (LXC) and Docker, have become a popular
method of isolating services in a resource-efficient manner.

The preferred means of integrating containers into Pacemaker is as a
cluster resource, whether opaque or using Pacemaker's ``bundle`` resource type.

However, it is possible to run ``pacemaker_remote`` inside a container,
following the process for guest nodes. This is not recommended but can
be useful, for example, in testing scenarios, to simulate a large number of
guest nodes.

The configuration process is very similar to that described for guest nodes
using virtual machines. Key differences:

* The underlying host must install the libvirt driver for the desired container
  technology -- for example, the ``libvirt-daemon-lxc`` package to get the
  `libvirt-lxc <http://libvirt.org/drvlxc.html>`_ driver for LXC containers.

* Libvirt XML definitions must be generated for the containers. You can create
  XML definitions manually, following the appropriate libvirt driver documentation.

* To share the authentication key, either share the host's ``/etc/pacemaker``
  directory with the container, or copy the key into the container's
  filesystem.

* The **VirtualDomain** resource for a container will need
  **force_stop="true"** and an appropriate hypervisor option,
  for example **hypervisor="lxc:///"** for LXC containers.
