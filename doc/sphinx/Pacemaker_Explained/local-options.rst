Host-Local Configuration
------------------------

.. index::
   pair: XML element; configuration

.. note:: Directory and file paths below may differ on your system depending on
          your Pacemaker build settings. Check your Pacemaker configuration
          file to find the correct paths.

Pacemaker supports several host-local configuration options. These options can
be configured on each node in the main Pacemaker configuration file
(|PCMK_CONFIG_FILE|) in the format ``<NAME>="<VALUE>"``. They work by setting
environment variables when Pacemaker daemons start up.

.. list-table:: **Local Options**
   :class: longtable
   :widths: 2 2 2 5
   :header-rows: 1

   * - Name
     - Type
     - Default
     - Description
   * - .. _pcmk_logfacility:
       
       .. index::
          pair: node option; PCMK_logfacility
       
       PCMK_logfacility
     - :ref:`enumeration <enumeration>`
     - daemon
     - Enable logging via the system log or journal, using the specified log
       facility. Messages sent here are of value to all Pacemaker
       administrators. This can be disabled using ``none``, but that is not
       recommended. Allowed values:

       * ``none``
       * ``daemon``
       * ``user``
       * ``local0``
       * ``local1``
       * ``local2``
       * ``local3``
       * ``local4``
       * ``local5``
       * ``local6``
       * ``local7``

   * - .. _pcmk_logpriority:

       .. index::
          pair:: node option; PCMK_logpriority

       PCMK_logpriority
     - :ref:`enumeration <enumeration>`
     - notice
     - Unless system logging is disabled using ``PCMK_logfacility=none``,
       messages of the specified log severity and higher will be sent to the
       system log. The default is appropriate for most installations. Allowed
       values:

       * ``emerg``
       * ``alert``
       * ``crit``
       * ``error``
       * ``warning``
       * ``notice``
       * ``info``
       * ``debug``

   * - .. _pcmk_logfile:

       .. index::
          pair:: node option; PCMK_logfile

       PCMK_logfile
     - :ref:`text <text>`
     - |PCMK_LOG_FILE|
     - Unless set to ``none``, more detailed log messages will be sent to the
       specified file (in addition to the system log, if enabled). These
       messages may have extended information, and will include messages of info
       severity. This log is of more use to developers and advanced system
       administrators, and when reporting problems. Note: The default is
       |PCMK_CONTAINER_LOG_FILE| (inside the container) for bundled container
       nodes; this would typically be mapped to a different path on the host
       running the container.

   * - .. _pcmk_logfile_mode:

       .. index::
          pair:: node option; PCMK_logfile_mode

       PCMK_logfile_mode
     - :ref:`text <text>`
     - 0660
     - Pacemaker will set the permissions on the detail log to this value (see
       ``chmod(1)``).

   * - .. _pcmk_debug:

       .. index::
          pair:: node option; PCMK_debug

       PCMK_debug
     - :ref:`enumeration <enumeration>`
     - no
     - Whether to send debug severity messages to the detail log. This may be
       set for all subsystems (``yes`` or ``no``) or for specific (comma-
       separated) subsystems. Allowed subsystems are:

       * ``pacemakerd``
       * ``pacemaker-attrd``
       * ``pacemaker-based``
       * ``pacemaker-controld``
       * ``pacemaker-execd``
       * ``pacemaker-fenced``
       * ``pacemaker-schedulerd``

       Example: ``PCMK_debug="pacemakerd,pacemaker-execd"``

   * - .. _pcmk_stderr:

       .. index::
          pair:: node option; PCMK_stderr

       PCMK_stderr
     - :ref:`boolean <boolean>`
     - no
     - *Advanced Use Only:* Whether to send daemon log messages to stderr. This
       would be useful only during troubleshooting, when starting Pacemaker
       manually on the command line.

       Setting this option in the configuration file is pointless, since the
       file is not read when starting Pacemaker manually. However, it can be set
       directly as an environment variable on the command line.

   * - .. _pcmk_trace_functions:

       .. index::
          pair:: node option; PCMK_trace_functions

       PCMK_trace_functions
     - :ref:`text <text>`
     -
     - *Advanced Use Only:* Send debug and trace severity messages from these
       (comma-separated) source code functions to the detail log.

       Example:
       ``PCMK_trace_functions="func1,func2"``

   * - .. _pcmk_trace_files:

       .. index::
          pair:: node option; PCMK_trace_files

       PCMK_trace_files
     - :ref:`text <text>`
     -
     - *Advanced Use Only:* Send debug and trace severity messages from all
       functions in these (comma-separated) source file names to the detail log.

       Example: ``PCMK_trace_files="file1.c,file2.c"``

   * - .. _pcmk_trace_formats:

       .. index::
          pair:: node option; PCMK_trace_formats

       PCMK_trace_formats
     - :ref:`text <text>`
     -
     - *Advanced Use Only:* Send trace severity messages that are generated by
       these (comma-separated) format strings in the source code to the detail
       log.

       Example: ``PCMK_trace_formats="Error: %s (%d)"``

   * - .. _pcmk_trace_tags:

       .. index::
          pair:: node option; PCMK_trace_tags

       PCMK_trace_tags
     - :ref:`text <text>`
     -
     - *Advanced Use Only:* Send debug and trace severity messages related to
       these (comma-separated) resource IDs to the detail log.

       Example: ``PCMK_trace_tags="client-ip,dbfs"``

   * - .. _pcmk_blackbox:

       .. index::
          pair:: node option; PCMK_blackbox

       PCMK_blackbox
     - :ref:`enumeration <enumeration>`
     - no
     - *Advanced Use Only:* Enable blackbox logging globally (``yes`` or ``no``)
       or by subsystem. A blackbox contains a rolling buffer of all logs (of all
       severities). Blackboxes are stored under |CRM_BLACKBOX_DIR| by default,
       by default, and their contents can be viewed using the ``qb-blackbox(8)``
       command.

       The blackbox recorder can be enabled at start using this variable, or at
       runtime by sending a Pacemaker subsystem daemon process a ``SIGUSR1`` or
       ``SIGTRAP`` signal, and disabled by sending ``SIGUSR2`` (see
       ``kill(1)``). The blackbox will be written after a crash, assertion
       failure, or ``SIGTRAP`` signal.

       See :ref:`PCMK_debug <pcmk_debug>` for allowed subsystems.

       Example:
       ``PCMK_blackbox="pacemakerd,pacemaker-execd"``

   * - .. _pcmk_trace_blackbox:

       .. index::
          pair:: node option; PCMK_trace_blackbox

       PCMK_trace_blackbox
     - :ref:`enumeration <enumeration>`
     -
     - *Advanced Use Only:* Write a blackbox whenever the message at the
       specified function and line is logged. Multiple entries may be comma-
       separated.

       Example: ``PCMK_trace_blackbox="remote.c:144,remote.c:149"``

   * - .. _pcmk_node_start_state:

       .. index::
          pair:: node option; PCMK_node_start_state

       PCMK_node_start_state
     - :ref:`enumeration <enumeration>`
     - default
     - By default, the local host will join the cluster in an online or standby
       state when Pacemaker first starts depending on whether it was previously
       put into standby mode. If this variable is set to ``standby`` or
       ``online``, it will force the local host to join in the specified state.

   * - .. _pcmk_node_action_limit:

       .. index::
          pair:: node option; PCMK_node_action_limit

       PCMK_node_action_limit
     - :ref:`nonnegative integer <nonnegative_integer>`
     -
     - Specify the maximum number of jobs that can be scheduled on this node. If
       set, this overrides the ``node-action-limit`` cluster property for this
       node.

   * - .. _pcmk_shutdown_delay:

       .. index::
          pair:: node option; PCMK_shutdown_delay

       PCMK_shutdown_delay
     - :ref:`timeout <timeout>`
     -
     - Specify a delay before shutting down ``pacemakerd`` after shutting down
       all other Pacemaker daemons.

   * - .. _pcmk_fail_fast:

       .. index::
          pair:: node option; PCMK_fail_fast

       PCMK_fail_fast
     - :ref:`boolean <boolean>`
     - no
     - By default, if a Pacemaker subsystem crashes, the main ``pacemakerd``
       process will attempt to restart it. If this variable is set to ``yes``,
       ``pacemakerd`` will panic the local host instead.

   * - .. _pcmk_panic_action:

       .. index::
          pair:: node option; PCMK_panic_action

       PCMK_panic_action
     - :ref:`enumeration <enumeration>`
     - reboot
     - Pacemaker will panic the local host under certain conditions. By default,
       this means rebooting the host. This variable can change that behavior: if
       ``crash``, trigger a kernel crash (useful if you want a kernel dump to
       investigate); if ``sync-reboot`` or ``sync-crash``, synchronize
       filesystems before rebooting the host or triggering a kernel crash. The
       sync values are more likely to preserve log messages, but with the risk
       that the host may be left active if the synchronization hangs.

   * - .. _pcmk_authkey_location:

       .. index::
          pair:: node option; PCMK_authkey_location

       PCMK_authkey_location
     - :ref:`text <text>`
     - |PCMK_AUTHKEY_FILE|
     - Use the contents of this file as the authorization key to use with
       Pacemaker Remote connections. This file must be readable by Pacemaker
       daemons (that is, it must allow read permissions to either the
       |CRM_DAEMON_USER| user or the |CRM_DAEMON_GROUP| group), and its contents
       must be identical on all nodes.

   * - .. _pcmk_remote_address:

       .. index::
          pair:: node option; PCMK_remote_address

       PCMK_remote_address
     - :ref:`text <text>`
     -
     - By default, if the Pacemaker Remote service is run on the local node, it
       will listen for connections on all IP addresses. This may be set to one
       address to listen on instead, as a resolvable hostname or as a numeric
       IPv4 or IPv6 address. When resolving names or listening on all addresses,
       IPv6 will be preferred if available. When listening on an IPv6 address,
       IPv4 clients will be supported via IPv4-mapped IPv6 addresses.

       Example: ``PCMK_remote_address="192.0.2.1"``

   * - .. _pcmk_remote_port:

       .. index::
          pair:: node option; PCMK_remote_port

       PCMK_remote_port
     - :ref:`port <port>`
     - 3121
     - Use this TCP port number for Pacemaker Remote node connections. This
       value must be the same on all nodes.

   * - .. _pcmk_remote_pid1:

       .. index::
          pair:: node option; PCMK_remote_pid1

       PCMK_remote_pid1
     - :ref:`enumeration <enumeration>`
     - default
     - *Advanced Use Only:* When a bundle resource's ``run-command`` option is
       left to default, Pacemaker Remote runs as PID 1 in the bundle's
       containers. When it does so, it loads environment variables from the
       container's |PCMK_INIT_ENV_FILE| and performs the PID 1 responsibility of
       reaping dead subprocesses.

       This option controls whether those actions are performed when Pacemaker
       Remote is not running as PID 1. It is intended primarily for developer
       testing but can be useful when ``run-command`` is set to a separate,
       custom PID 1 process that launches Pacemaker Remote.

       * ``full``: Pacemaker Remote loads environment variables from
         |PCMK_INIT_ENV_FILE| and reaps dead subprocesses.
       * ``vars``: Pacemaker Remote loads environment variables from
         |PCMK_INIT_ENV_FILE| but does not reap dead subprocesses.
       * ``default``: Pacemaker Remote performs neither action.

       If Pacemaker Remote is running as PID 1, this option is ignored, and the
       behavior is the same as for ``full``.

   * - .. _pcmk_tls_priorities:

       .. index::
          pair:: node option; PCMK_tls_priorities

       PCMK_tls_priorities
     - :ref:`text <text>`
     - |PCMK_GNUTLS_PRIORITIES|
     - *Advanced Use Only:* These GnuTLS cipher priorities will be used for TLS
       connections (whether for Pacemaker Remote connections or remote CIB
       access, when enabled). See:

         https://gnutls.org/manual/html_node/Priority-Strings.html

       Pacemaker will append ``":+ANON-DH"`` for remote CIB access and
       ``":+DHE-PSK:+PSK"`` for Pacemaker Remote connections, as they are
       required for the respective functionality.

       Example:
       ``PCMK_tls_priorities="SECURE128:+SECURE192"``

   * - .. _pcmk_dh_min_bits:

       .. index::
          pair:: node option; PCMK_dh_min_bits

       PCMK_dh_min_bits
     - :ref:`nonnegative integer <nonnegative_integer>`
     - 0 (no minimum)
     - *Advanced Use Only:* Set a lower bound on the bit length of the prime
       number generated for Diffie-Hellman parameters needed by TLS connections.
       The default is no minimum.

       The server (Pacemaker Remote daemon, or CIB manager configured to accept
       remote clients) will use this value to provide a floor for the value
       recommended by the GnuTLS library. The library will only accept a limited
       number of specific values, which vary by library version, so setting
       these is recommended only when required for compatibility with specific
       client versions.

       Clients (connecting cluster nodes or remote CIB commands) will require
       that the server use a prime of at least this size. This is recommended
       only when the value must be lowered in order for the client's GnuTLS
       library to accept a connection to an older server.

   * - .. _pcmk_dh_max_bits:

       .. index::
          pair:: node option; PCMK_dh_max_bits

       PCMK_dh_max_bits
     - :ref:`nonnegative integer <nonnegative_integer>`
     - 0 (no maximum)
     - *Advanced Use Only:* Set an upper bound on the bit length of the prime
       number generated for Diffie-Hellman parameters needed by TLS connections.
       The default is no maximum.

       The server (Pacemaker Remote daemon, or CIB manager configured to accept
       remote clients) will use this value to provide a ceiling for the value
       recommended by the GnuTLS library. The library will only accept a limited
       number of specific values, which vary by library version, so setting
       these is recommended only when required for compatibility with specific
       client versions.

       Clients do not use ``PCMK_dh_max_bits``.

   * - .. _pcmk_ipc_type:

       .. index::
          pair:: node option; PCMK_ipc_type

       PCMK_ipc_type
     - :ref:`enumeration <enumeration>`
     - shared-mem
     - *Advanced Use Only:* Force use of a particular IPC method. Allowed values:

       * ``shared-mem``
       * ``socket``
       * ``posix``
       * ``sysv``

   * - .. _pcmk_ipc_buffer:

       .. index::
          pair:: node option; PCMK_ipc_buffer

       PCMK_ipc_buffer
     - :ref:`nonnegative integer <nonnegative_integer>`
     - 131072
     - *Advanced Use Only:* Specify an IPC buffer size in bytes. This can be
       useful when connecting to large clusters that result in messages
       exceeding the default size (which will also result in log messages
       referencing this variable).

   * - .. _pcmk_cluster_type:

       .. index::
          pair:: node option; PCMK_cluster_type

       PCMK_cluster_type
     - :ref:`enumeration <enumeration>`
     - corosync
     - *Advanced Use Only:* Specify the cluster layer to be used. If unset,
       Pacemaker will detect and use a supported cluster layer, if available.
       Currently, ``"corosync"`` is the only supported cluster layer. If
       multiple layers are supported in the future, this will allow overriding
       Pacemaker's automatic detection to select a specific one.

   * - .. _pcmk_schema_directory:

       .. index::
          pair:: node option; PCMK_schema_directory

       PCMK_schema_directory
     - :ref:`text <text>`
     - |CRM_SCHEMA_DIRECTORY|
     - *Advanced Use Only:* Specify an alternate location for RNG schemas and
       XSL transforms.

   * - .. _pcmk_valgrind_enabled:

       .. index::
          pair:: node option; PCMK_valgrind_enabled

       PCMK_valgrind_enabled
     - :ref:`enumeration <enumeration>`
     - no
     - *Advanced Use Only:* Whether subsystem daemons should be run under
       ``valgrind``. Allowed values are the same as for ``PCMK_debug``.

   * - .. _pcmk_callgrind_enabled:

       .. index::
          pair:: node option; PCMK_callgrind_enabled

       PCMK_callgrind_enabled
     - :ref:`enumeration <enumeration>`
     - no
     - *Advanced Use Only:* Whether subsystem daemons should be run under
       ``valgrind`` with the ``callgrind`` tool enabled. Allowed values are the
       same as for ``PCMK_debug``.

   * - .. _valgrind_opts:

       .. index::
          pair:: node option; VALGRIND_OPTS

       VALGRIND_OPTS
     - :ref:`text <text>`
     -
     - *Advanced Use Only:* Pass these options to valgrind, when enabled (see
       ``valgrind(1)``). ``"--vgdb=no"`` should usually be specified because
       ``pacemaker-execd`` can lower privileges when executing commands, which
       would otherwise leave a bunch of unremovable files in ``/tmp``.
