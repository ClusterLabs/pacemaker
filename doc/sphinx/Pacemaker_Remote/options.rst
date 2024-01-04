.. index::
    single: configuration

Configuration Explained
-----------------------

The walk-through examples use some of these options, but don't explain exactly
what they mean or do.  This section is meant to be the go-to resource for all
the options available for configuring Pacemaker Remote.

.. index::
   pair: configuration; guest node
   single: guest node; meta-attribute

Resource Meta-Attributes for Guest Nodes
########################################

When configuring a virtual machine as a guest node, the virtual machine is
created using one of the usual resource agents for that purpose (for example,
**ocf:heartbeat:VirtualDomain** or **ocf:heartbeat:Xen**), with additional
meta-attributes.

No restrictions are enforced on what agents may be used to create a guest node,
but obviously the agent must create a distinct environment capable of running
the pacemaker_remote daemon and cluster resources. An additional requirement is
that fencing the host running the guest node resource must be sufficient for
ensuring the guest node is stopped. This means, for example, that not all
hypervisors supported by **VirtualDomain** may be used to create guest nodes;
if the guest can survive the hypervisor being fenced, it may not be used as a
guest node.

Below are the meta-attributes available to enable a resource as a guest node
and define its connection parameters.

.. table:: **Meta-attributes for configuring VM resources as guest nodes**

  +------------------------+-----------------+-----------------------------------------------------------+
  | Option                 | Default         | Description                                               |
  +========================+=================+===========================================================+
  | remote-node            | none            | The node name of the guest node this resource defines.    |
  |                        |                 | This both enables the resource as a guest node and        |
  |                        |                 | defines the unique name used to identify the guest node.  |
  |                        |                 | If no other parameters are set, this value will also be   |
  |                        |                 | assumed as the hostname to use when connecting to         |
  |                        |                 | pacemaker_remote on the VM.  This value **must not**      |
  |                        |                 | overlap with any resource or node IDs.                    |
  +------------------------+-----------------+-----------------------------------------------------------+
  | remote-port            | 3121            | The port on the virtual machine that the cluster will     |
  |                        |                 | use to connect to pacemaker_remote.                       |
  +------------------------+-----------------+-----------------------------------------------------------+
  | remote-addr            | 'value of'      | The IP address or hostname to use when connecting to      |
  |                        | ``remote-node`` | pacemaker_remote on the VM.                               |
  +------------------------+-----------------+-----------------------------------------------------------+
  | remote-connect-timeout | 60s             | How long before a pending guest connection will time out. |
  +------------------------+-----------------+-----------------------------------------------------------+
  | remote-allow-migrate   | TRUE            | The ``allow-migrate`` meta-attribute value for the        |
  |                        |                 | implicit remote connection resource                       |
  |                        |                 | (``ocf:pacemaker:remote``).                               |
  +------------------------+-----------------+-----------------------------------------------------------+

.. index::
   pair: configuration; remote node

Connection Resources for Remote Nodes
#####################################

A remote node is defined by a connection resource. That connection resource
has instance attributes that define where the remote node is located on the
network and how to communicate with it.

Descriptions of these instance attributes can be retrieved using the following
``pcs`` command:

.. code-block:: none

    [root@pcmk-1 ~]# pcs resource describe remote
    Assumed agent name 'ocf:pacemaker:remote' (deduced from 'remote')
    ocf:pacemaker:remote - Pacemaker Remote connection

    Resource options:
      server (unique group: address): Server location to connect to (IP address
                                      or resolvable host name)
      port (unique group: address): TCP port at which to contact Pacemaker
                                    Remote executor
      reconnect_interval: If this is a positive time interval, the cluster will
                          attempt to reconnect to a remote node after an active
                          connection has been lost at this interval. Otherwise,
                          the cluster will attempt to reconnect immediately
                          (after any fencing needed).

When defining a remote node's connection resource, it is common and recommended
to name the connection resource the same as the remote node's hostname. By
default, if no ``server`` option is provided, the cluster will attempt to contact
the remote node using the resource name as the hostname.

Environment Variables for Daemon Start-up
#########################################

Authentication and encryption of the connection between cluster nodes
and nodes running pacemaker_remote is achieved using
with `TLS-PSK <https://en.wikipedia.org/wiki/TLS-PSK>`_ encryption/authentication
over TCP (port 3121 by default). This means that both the cluster node and
remote node must share the same private key. By default, this
key is placed at ``/etc/pacemaker/authkey`` on each node.

You can change the default port and/or key location for Pacemaker and
``pacemaker_remoted`` via environment variables. How these variables are set
varies by OS, but usually they are set in the ``/etc/sysconfig/pacemaker`` or
``/etc/default/pacemaker`` file.

.. code-block:: none

    #==#==# Pacemaker Remote
    # Use the contents of this file as the authorization key to use with Pacemaker
    # Remote connections. This file must be readable by Pacemaker daemons (that is,
    # it must allow read permissions to either the hacluster user or the haclient
    # group), and its contents must be identical on all nodes. The default is
    # "/etc/pacemaker/authkey".
    # PCMK_authkey_location=/etc/pacemaker/authkey
    
    # If the Pacemaker Remote service is run on the local node, it will listen
    # for connections on this address. The value may be a resolvable hostname or an
    # IPv4 or IPv6 numeric address. When resolving names or using the default
    # wildcard address (i.e. listen on all available addresses), IPv6 will be
    # preferred if available. When listening on an IPv6 address, IPv4 clients will
    # be supported (via IPv4-mapped IPv6 addresses).
    # PCMK_remote_address="192.0.2.1"

    # Use this TCP port number when connecting to a Pacemaker Remote node. This
    # value must be the same on all nodes. The default is "3121".
    # PCMK_remote_port=3121

    # Use these GnuTLS cipher priorities for TLS connections. See:
    #
    #   https://gnutls.org/manual/html_node/Priority-Strings.html
    #
    # Pacemaker will append ":+ANON-DH" for remote CIB access (when enabled) and
    # ":+DHE-PSK:+PSK" for Pacemaker Remote connections, as they are required for
    # the respective functionality.
    # PCMK_tls_priorities="NORMAL"

    # Set bounds on the bit length of the prime number generated for Diffie-Hellman
    # parameters needed by TLS connections. The default is not to set any bounds.
    #
    # If these values are specified, the server (Pacemaker Remote daemon, or CIB
    # manager configured to accept remote clients) will use these values to provide
    # a floor and/or ceiling for the value recommended by the GnuTLS library. The
    # library will only accept a limited number of specific values, which vary by
    # library version, so setting these is recommended only when required for
    # compatibility with specific client versions.
    #
    # If PCMK_dh_min_bits is specified, the client (connecting cluster node or
    # remote CIB command) will require that the server use a prime of at least this
    # size. This is only recommended when the value must be lowered in order for
    # the client's GnuTLS library to accept a connection to an older server.
    # The client side does not use PCMK_dh_max_bits.
    # 
    # PCMK_dh_min_bits=1024
    # PCMK_dh_max_bits=2048

Removing Remote Nodes and Guest Nodes
#####################################

If the resource creating a guest node, or the **ocf:pacemaker:remote** resource
creating a connection to a remote node, is removed from the configuration, the
affected node will continue to show up in output as an offline node.

If you want to get rid of that output, run (replacing ``$NODE_NAME``
appropriately):

.. code-block:: none

    # crm_node --force --remove $NODE_NAME

.. WARNING::

    Be absolutely sure that there are no references to the node's resource in the
    configuration before running the above command.
