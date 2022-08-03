.. index:: fencing

Configure Fencing
-----------------

What is Fencing?
################

Fencing protects your data from being corrupted, and your application from
becoming unavailable, due to unintended concurrent access by rogue nodes.

Just because a node is unresponsive doesn't mean it has stopped
accessing your data. The only way to be 100% sure that your data is
safe, is to use fencing to ensure that the node is truly
offline before allowing the data to be accessed from another node.

Fencing also has a role to play in the event that a clustered service
cannot be stopped. In this case, the cluster uses fencing to force the
whole node offline, thereby making it safe to start the service
elsewhere.

Fencing is also known as STONITH, an acronym for "Shoot The Other Node In The
Head", since the most popular form of fencing is cutting a host's power.

In order to guarantee the safety of your data [#]_, fencing is enabled by default.

.. NOTE::

    It is possible to tell the cluster not to use fencing, by setting the
    ``stonith-enabled`` cluster property to false:

    .. code-block:: console

        [root@pcmk-1 ~]# pcs property set stonith-enabled=false
        [root@pcmk-1 ~]# pcs cluster verify --full

    However, this is completely inappropriate for a production cluster. It tells
    the cluster to simply pretend that failed nodes are safely powered off. Some
    vendors will refuse to support clusters that have fencing disabled. Even
    disabling it for a test cluster means you won't be able to test real failure
    scenarios.


.. index::
   single: fencing; device

Choose a Fence Device
#####################

The two broad categories of fence device are power fencing, which cuts off
power to the target, and fabric fencing, which cuts off the target's access to
some critical resource, such as a shared disk or access to the local network.

Power fencing devices include:

* Intelligent power switches
* IPMI
* Hardware watchdog device (alone, or in combination with shared storage used
  as a "poison pill" mechanism)

Fabric fencing devices include:

* Shared storage that can be cut off for a target host by another host (for
  example, an external storage device that supports SCSI-3 persistent
  reservations)
* Intelligent network switches

Using IPMI as a power fencing device may seem like a good choice. However,
if the IPMI shares power and/or network access with the host (such as most
onboard IPMI controllers), a power or network failure will cause both the
host and its fencing device to fail. The cluster will be unable to recover,
and must stop all resources to avoid a possible split-brain situation.

Likewise, any device that relies on the machine being active (such as
SSH-based "devices" sometimes used during testing) is inappropriate,
because fencing will be required when the node is completely unresponsive.
(Fence agents like ``fence_ilo_ssh``, which connects via SSH to an HP iLO but
not to the cluster node, are fine.)

Configure the Cluster for Fencing
#################################

#. Install the fence agent(s). To see what packages are available, run
   ``dnf search fence-``. Be sure to install the package(s) on all cluster nodes.

#. Configure the fence device itself to be able to fence your nodes and accept
   fencing requests. This includes any necessary configuration on the device and
   on the nodes, and any firewall or SELinux changes needed. Test the
   communication between the device and your nodes.

#. Find the name of the correct fence agent: ``pcs stonith list``

#. Find the parameters associated with the device:
   ``pcs stonith describe <AGENT_NAME>``

#. Create a local copy of the CIB: ``pcs cluster cib stonith_cfg``

#. Create the fencing resource: ``pcs -f stonith_cfg stonith create <STONITH_ID> <STONITH_DEVICE_TYPE> [STONITH_DEVICE_OPTIONS]``

   Any flags that do not take arguments, such as ``--ssl``, should be passed as ``ssl=1``.

#. Ensure fencing is enabled in the cluster:
   ``pcs -f stonith_cfg property set stonith-enabled=true``

#. If the device does not know how to fence nodes based on their cluster node
   name, you may also need to set the special ``pcmk_host_map`` parameter. See
   ``man pacemaker-fenced`` for details.

#. If the device does not support the ``list`` command, you may also need to
   set the special ``pcmk_host_list`` and/or ``pcmk_host_check`` parameters.
   See ``man pacemaker-fenced`` for details.

#. If the device does not expect the victim to be specified with the ``port``
   parameter, you may also need to set the special ``pcmk_host_argument``
   parameter. See ``man pacemaker-fenced`` for details.

#. Commit the new configuration: ``pcs cluster cib-push stonith_cfg``

#. Once the fence device resource is running, test it (you might want to stop
   the cluster on that machine first):
   ``pcs stonith fence <NODENAME>``

Example
#######

For this example, assume we have a chassis containing four nodes
and a separately powered IPMI device active on ``10.0.0.1``. Following the steps
above would go something like this:

Step 1: Install the ``fence-agents-ipmilan`` package on both nodes.

Step 2: Configure the IP address, authentication credentials, etc. in the IPMI device itself.

Step 3: Choose the ``fence_ipmilan`` STONITH agent.

Step 4: Obtain the agent's possible parameters:

.. code-block:: console

    [root@pcmk-1 ~]# pcs stonith describe fence_ipmilan
    fence_ipmilan - Fence agent for IPMI

    fence_ipmilan is an I/O Fencing agentwhich can be used with machines controlled by IPMI.This agent calls support software ipmitool (http://ipmitool.sf.net/). WARNING! This fence agent might report success before the node is powered off. You should use -m/method onoff if your fence device works correctly with that option.

    Stonith options:
      auth: IPMI Lan Auth type.
      cipher: Ciphersuite to use (same as ipmitool -C parameter)
      hexadecimal_kg: Hexadecimal-encoded Kg key for IPMIv2 authentication
      ip: IP address or hostname of fencing device
      ipport: TCP/UDP port to use for connection with device
      lanplus: Use Lanplus to improve security of connection
      method: Method to fence
      password: Login password or passphrase
      password_script: Script to run to retrieve password
      plug: IP address or hostname of fencing device (together with --port-as-ip)
      privlvl: Privilege level on IPMI device
      target: Bridge IPMI requests to the remote target address
      username: Login name
      quiet: Disable logging to stderr. Does not affect --verbose or --debug-file or logging to syslog.
      verbose: Verbose mode. Multiple -v flags can be stacked on the command line (e.g., -vvv) to increase verbosity.
      verbose_level: Level of debugging detail in output. Defaults to the number of --verbose flags specified on the command line, or to 1 if verbose=1 in a stonith device configuration (i.e., on stdin).
      debug_file: Write debug information to given file
      delay: Wait X seconds before fencing is started
      disable_timeout: Disable timeout (true/false) (default: true when run from Pacemaker 2.0+)
      ipmitool_path: Path to ipmitool binary
      login_timeout: Wait X seconds for cmd prompt after login
      port_as_ip: Make "port/plug" to be an alias to IP address
      power_timeout: Test X seconds for status change after ON/OFF
      power_wait: Wait X seconds after issuing ON/OFF
      shell_timeout: Wait X seconds for cmd prompt after issuing command
      stonith_status_sleep: Sleep X seconds between status calls during a STONITH action
      ipmitool_timeout: Timeout (sec) for IPMI operation
      retry_on: Count of attempts to retry power on
      use_sudo: Use sudo (without password) when calling 3rd party software
      sudo_path: Path to sudo binary
      pcmk_host_map: A mapping of host names to ports numbers for devices that do not support host names. Eg. node1:1;node2:2,3 would tell the cluster to use port 1 for node1 and ports 2 and 3 for node2
      pcmk_host_list: A list of machines controlled by this device (Optional unless pcmk_host_check=static-list).
      pcmk_host_check: How to determine which machines are controlled by the device. Allowed values: dynamic-list (query the device via the 'list' command), static-list (check the pcmk_host_list attribute), status
                       (query the device via the 'status' command), none (assume every device can fence every machine)
      pcmk_delay_max: Enable a delay of no more than the time specified before executing fencing actions. Pacemaker derives the overall delay by taking the value of pcmk_delay_base and adding a random delay value
                      such that the sum is kept below this maximum. This prevents double fencing when using slow devices such as sbd. Use this to enable a random delay for fencing actions. The overall delay is
                      derived from this random delay value adding a static delay so that the sum is kept below the maximum delay.
      pcmk_delay_base: Enable a base delay for fencing actions and specify base delay value. This enables a static delay for fencing actions, which can help avoid "death matches" where two nodes try to fence each
                       other at the same time. If pcmk_delay_max is also used, a random delay will be added such that the total delay is kept below that value. This can be set to a single time value to apply to any
                       node targeted by this device (useful if a separate device is configured for each target), or to a node map (for example, "node1:1s;node2:5") to set a different value per target.
      pcmk_action_limit: The maximum number of actions can be performed in parallel on this device Cluster property concurrent-fencing=true needs to be configured first. Then use this to specify the maximum number
                         of actions can be performed in parallel on this device. -1 is unlimited.

    Default operations:
      monitor: interval=60s


Step 5: ``pcs cluster cib stonith_cfg``

Step 6: Here are example parameters for creating our fence device resource:

.. code-block:: console

    [root@pcmk-1 ~]# pcs -f stonith_cfg stonith create ipmi-fencing fence_ipmilan \
          pcmk_host_list="pcmk-1 pcmk-2" ipaddr=10.0.0.1 login=testuser \
          passwd=acd123 op monitor interval=60s
    [root@pcmk-1 ~]# pcs -f stonith_cfg stonith
      * ipmi-fencing	(stonith:fence_ipmilan):	Stopped

Steps 7-10: Enable fencing in the cluster:

.. code-block:: console

    [root@pcmk-1 ~]# pcs -f stonith_cfg property set stonith-enabled=true
    [root@pcmk-1 ~]# pcs -f stonith_cfg property
    Cluster Properties:
     cluster-infrastructure: corosync
     cluster-name: mycluster
     dc-version: 2.0.5-4.el8-ba59be7122
     have-watchdog: false
     stonith-enabled: true

Step 11: ``pcs cluster cib-push stonith_cfg --config``

Step 12: Test:

.. code-block:: console

    [root@pcmk-1 ~]# pcs cluster stop pcmk-2
    [root@pcmk-1 ~]# pcs stonith fence pcmk-2

After a successful test, login to any rebooted nodes, and start the cluster
(with ``pcs cluster start``).

.. [#] If the data is corrupt, there is little point in continuing to
       make it available.
