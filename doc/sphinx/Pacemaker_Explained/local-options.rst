Host-Local Configuration
------------------------

.. index::
   pair: XML element; configuration

.. note:: Directory and file paths below may differ on your system depending on
          your Pacemaker build settings. Check your Pacemaker configuration
          file to find the correct paths.

Configuration Value Types
#########################

Throughout this document, configuration values will be designated as having one
of the following types:

.. list-table:: **Configuration Value Types**
   :class: longtable
   :widths: 25 75
   :header-rows: 1

   * - Type
     - Description
   * - .. _boolean:

       .. index::
          pair: type; boolean

       boolean
     - Case-insensitive text value where ``1``, ``yes``, ``y``, ``on``,
       and ``true`` evaluate as true and ``0``, ``no``, ``n``, ``off``,
       ``false``, and unset evaluate as false
   * - .. _date_time:

       .. index::
          pair: type; date/time

       date/time
     - Textual timestamp like ``Sat Dec 21 11:47:45 2013``
   * - .. _duration:

       .. index::
          pair: type; duration

       duration
     - A nonnegative time duration, specified either like a
       :ref:`timeout <timeout>` or an
       `ISO 8601 duration <https://en.wikipedia.org/wiki/ISO_8601#Durations>`_.
       A duration may be up to approximately 49 days but is intended for much
       smaller time periods.
   * - .. _enumeration:

       .. index::
          pair: type; enumeration

       enumeration
     - Text that must be one of a set of defined values (which will be listed
       in the description)
   * - .. _epoch_time:

       .. index::
          pair: type; epoch_time

       epoch_time
     - Time as the integer number of seconds since the Unix epoch,
       ``1970-01-01 00:00:00 +0000 (UTC)``.
   * - .. _id:

       .. index::
          pair: type; id

       id
     - A text string starting with a letter or underbar, followed by any
       combination of letters, numbers, dashes, dots, and/or underbars; when
       used for a property named ``id``, the string must be unique across all
       ``id`` properties in the CIB
   * - .. _integer:

       .. index::
          pair: type; integer

       integer
     - 32-bit signed integer value (-2,147,483,648 to 2,147,483,647)
   * - .. _iso8601:

       .. index::
          pair: type; iso8601

       ISO 8601
     - An `ISO 8601 <https://en.wikipedia.org/wiki/ISO_8601>`_ date/time.
   * - .. _nonnegative_integer:

       .. index::
          pair: type; nonnegative integer

       nonnegative integer
     - 32-bit nonnegative integer value (0 to 2,147,483,647)
   * - .. _percentage:

       .. index::
          pair: type; percentage

       percentage
     - Floating-point number followed by an optional percent sign ('%')
   * - .. _port:

       .. index::
          pair: type; port

       port
     - Integer TCP port number (0 to 65535)
   * - .. _range:

       .. index::
          pair: type; range

       range
     - A range may be a single nonnegative integer or a dash-separated range of
       nonnegative integers. Either the first or last value may be omitted to
       leave the range open-ended. Examples: ``0``, ``3-``, ``-5``, ``4-6``.
   * - .. _score:

       .. index::
          pair: type; score

       score
     - A Pacemaker score can be an integer between -1,000,000 and 1,000,000, or
       a string alias: ``INFINITY`` or ``+INFINITY`` is equivalent to
       1,000,000, ``-INFINITY`` is equivalent to -1,000,000, and ``red``,
       ``yellow``, and ``green`` are equivalent to integers as described in
       :ref:`node-health`.
   * - .. _text:

       .. index::
          pair: type; text

       text
     - A text string
   * - .. _timeout:

       .. index::
          pair: type; timeout

       timeout
     - A time duration, specified as a bare number (in which case it is
       considered to be in seconds) or a number with a unit (``ms`` or ``msec``
       for milliseconds, ``us`` or ``usec`` for microseconds, ``s`` or ``sec``
       for seconds, ``m`` or ``min`` for minutes, ``h`` or ``hr`` for hours)
       optionally with whitespace before and/or after the number.
   * - .. _version:

       .. index::
          pair: type; version

       version
     - Version number (any combination of alphanumeric characters, dots, and
       dashes, starting with a number).


Scores
______

Scores are integral to how Pacemaker works. Practically everything from moving
a resource to deciding which resource to stop in a degraded cluster is achieved
by manipulating scores in some way.

Scores are calculated per resource and node. Any node with a negative score for
a resource can't run that resource. The cluster places a resource on the node
with the highest score for it.

Score addition and subtraction follow these rules:

* Any value (including ``INFINITY``) - ``INFINITY`` = ``-INFINITY``
* ``INFINITY`` + any value other than ``-INFINITY`` = ``INFINITY``

.. note::

   What if you want to use a score higher than 1,000,000? Typically this possibility
   arises when someone wants to base the score on some external metric that might
   go above 1,000,000.

   The short answer is you can't.

   The long answer is it is sometimes possible work around this limitation
   creatively. You may be able to set the score to some computed value based on
   the external metric rather than use the metric directly. For nodes, you can
   store the metric as a node attribute, and query the attribute when computing
   the score (possibly as part of a custom resource agent).


Local Options
#############

Most Pacemaker configuration is in the cluster-wide CIB, but some host-local
configuration options either are needed at startup (before the CIB is read) or
provide per-host overrides of cluster-wide options.

These options are configured as environment variables set when Pacemaker is
started, in the format ``<NAME>="<VALUE>"``. These are typically set in a file
whose location varies by OS (most commonly ``/etc/sysconfig/pacemaker`` or
``/etc/default/pacemaker``; this documentation was generated on a system using
|PCMK_CONFIG_FILE|).

.. list-table:: **Local Options**
   :class: longtable
   :widths: 25 15 10 50
   :header-rows: 1

   * - Name
     - Type
     - Default
     - Description

   * - .. _cib_pam_service:

       .. index::
          pair: node option; CIB_pam_service

       CIB_pam_service
     - :ref:`text <text>`
     - login
     - PAM service to use for remote CIB client authentication (passed to
       ``pam_start``).

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
          pair: node option; PCMK_logpriority

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
          pair: node option; PCMK_logfile

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
          pair: node option; PCMK_logfile_mode

       PCMK_logfile_mode
     - :ref:`text <text>`
     - 0660
     - Pacemaker will set the permissions on the detail log to this value (see
       ``chmod(1)``).

   * - .. _pcmk_debug:

       .. index::
          pair: node option; PCMK_debug

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
          pair: node option; PCMK_stderr

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
          pair: node option; PCMK_trace_functions

       PCMK_trace_functions
     - :ref:`text <text>`
     -
     - *Advanced Use Only:* Send debug and trace severity messages from these
       (comma-separated) source code functions to the detail log.

       Example:
       ``PCMK_trace_functions="func1,func2"``

   * - .. _pcmk_trace_files:

       .. index::
          pair: node option; PCMK_trace_files

       PCMK_trace_files
     - :ref:`text <text>`
     -
     - *Advanced Use Only:* Send debug and trace severity messages from all
       functions in these (comma-separated) source file names to the detail log.

       Example: ``PCMK_trace_files="file1.c,file2.c"``

   * - .. _pcmk_trace_formats:

       .. index::
          pair: node option; PCMK_trace_formats

       PCMK_trace_formats
     - :ref:`text <text>`
     -
     - *Advanced Use Only:* Send trace severity messages that are generated by
       these (comma-separated) format strings in the source code to the detail
       log.

       Example: ``PCMK_trace_formats="Error: %s (%d)"``

   * - .. _pcmk_trace_tags:

       .. index::
          pair: node option; PCMK_trace_tags

       PCMK_trace_tags
     - :ref:`text <text>`
     -
     - *Advanced Use Only:* Send debug and trace severity messages related to
       these (comma-separated) resource IDs to the detail log.

       Example: ``PCMK_trace_tags="client-ip,dbfs"``

   * - .. _pcmk_blackbox:

       .. index::
          pair: node option; PCMK_blackbox

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
          pair: node option; PCMK_trace_blackbox

       PCMK_trace_blackbox
     - :ref:`enumeration <enumeration>`
     -
     - *Advanced Use Only:* Write a blackbox whenever the message at the
       specified function and line is logged. Multiple entries may be comma-
       separated.

       Example: ``PCMK_trace_blackbox="remote.c:144,remote.c:149"``

   * - .. _pcmk_node_start_state:

       .. index::
          pair: node option; PCMK_node_start_state

       PCMK_node_start_state
     - :ref:`enumeration <enumeration>`
     - default
     - By default, the local host will join the cluster in an online or standby
       state when Pacemaker first starts depending on whether it was previously
       put into standby mode. If this variable is set to ``standby`` or
       ``online``, it will force the local host to join in the specified state.

   * - .. _pcmk_node_action_limit:

       .. index::
          pair: node option; PCMK_node_action_limit

       PCMK_node_action_limit
     - :ref:`nonnegative integer <nonnegative_integer>`
     -
     - If set, this overrides the :ref:`node-action-limit <node_action_limit>`
       cluster option on this node to specify the maximum number of jobs that
       can be scheduled on this node (or 0 to use twice the number of CPU
       cores).

   * - .. _pcmk_fail_fast:

       .. index::
          pair: node option; PCMK_fail_fast

       PCMK_fail_fast
     - :ref:`boolean <boolean>`
     - no
     - By default, if a Pacemaker subsystem crashes, the main ``pacemakerd``
       process will attempt to restart it. If this variable is set to ``yes``,
       ``pacemakerd`` will panic the local host instead.

   * - .. _pcmk_panic_action:

       .. index::
          pair: node option; PCMK_panic_action

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

   * - .. _pcmk_remote_address:

       .. index::
          pair: node option; PCMK_remote_address

       PCMK_remote_address
     - :ref:`text <text>`
     -
     - By default, if the :ref:`Pacemaker Remote <pacemaker_remote>` service is
       run on the local node, it will listen for connections on all IP
       addresses. This may be set to one address to listen on instead, as a
       resolvable hostname or as a numeric IPv4 or IPv6 address. When resolving
       names or listening on all addresses, IPv6 will be preferred if
       available. When listening on an IPv6 address, IPv4 clients will be
       supported via IPv4-mapped IPv6 addresses.

       Example: ``PCMK_remote_address="192.0.2.1"``

   * - .. _pcmk_remote_port:

       .. index::
          pair: node option; PCMK_remote_port

       PCMK_remote_port
     - :ref:`port <port>`
     - 3121
     - Use this TCP port number for :ref:`Pacemaker Remote <pacemaker_remote>`
       node connections. This value must be the same on all nodes.

   * - .. _pcmk_ca_file:

       .. index::
          pair: node option; PCMK_ca_file

       PCMK_ca_file
     - :ref:`text <text>`
     -
     - The location of a file containing trusted Certificate Authorities, used to
       verify client or server certificates. This file must be in PEM format and
       must be readable by Pacemaker daemons (that is, it must allow read permissions
       to either the |CRM_DAEMON_USER| user or the |CRM_DAEMON_GROUP| group).
       If set, along with :ref:`PCMK_key_file <PCMK_key_file>` and
       :ref:`PCMK_cert_file <PCMK_cert_file>`, X509 authentication will be enabled
       for :ref:`Pacemaker Remote <pacemaker_remote>` and remote CIB connections.

       Example: ``PCMK_ca_file="/etc/pacemaker/ca.cert.pem"``

   * - .. _pcmk_cert_file:

       .. index::
          pair: node option; PCMK_cert_file

       PCMK_cert_file
     - :ref:`text <text>`
     -
     - The location of a file containing the signed certificate for the server
       side of the connection. This file must be in PEM format and must be
       readable by Pacemaker daemons (that is, it must allow read permissions
       to either the |CRM_DAEMON_USER| user or the |CRM_DAEMON_GROUP| group).
       If set, along with :ref:`PCMK_ca_file <PCMK_ca_file>` and
       :ref:`PCMK_key_file <PCMK_key_file>`, X509 authentication will be enabled
       for :ref:`Pacemaker Remote <pacemaker_remote>` and remote CIB connections.

       Example: ``PCMK_cert_file="/etc/pacemaker/server.cert.pem"``

   * - .. _pcmk_crl_file:

       .. index::
          pair: node option; PCMK_crl_file

       PCMK_crl_file
     - :ref:`text <text>`
     -
     - The location of a Certificate Revocation List file, in PEM format. This
       setting is optional for X509 authentication.

       Example: ``PCMK_cr1_file="/etc/pacemaker/crl.pem"``

   * - .. _pcmk_key_file:

       .. index::
          pair: node option; PCMK_key_file

       PCMK_key_file
     - :ref:`text <text>`
     -
     - The location of a file containing the private key for the matching
       :ref:`PCMK_cert_file <PCMK_cert_file>`, in PEM format. This file must
       be readble by Pacemaker daemons (that is, it must allow read permissions
       to either the |CRM_DAEMON_USER| user or the |CRM_DAEMON_GROUP| group).
       If set, along with :ref:`PCMK_ca_file <PCMK_ca_file>` and
       :ref:`PCMK_cert_file <PCMK_cert_file>`, X509 authentication will be
       enabled for :ref:`Pacemaker Remote <pacemaker_remote>` and remote CIB
       connections.

       Example: ``PCMK_key_file="/etc/pacemaker/server.key.pem"``

   * - .. _pcmk_authkey_location:

       .. index::
          pair: node option; PCMK_authkey_location

       PCMK_authkey_location
     - :ref:`text <text>`
     - |PCMK_AUTHKEY_FILE|
     - As an alternative to using X509 authentication for :ref:`Pacemaker Remote
       <pacemaker_remote>` connections, use the contents of this file as the
       authorization key. This file must be readable by Pacemaker daemons (that
       is, it must allow read permissions to either the |CRM_DAEMON_USER| user
       or the |CRM_DAEMON_GROUP| group), and its contents must be identical on
       all nodes.

   * - .. _pcmk_cib_authkey_location:

       .. index::
          pair: node option; PCMK_cib_authkey_location

       PCMK_cib_authkey_location
     - :ref:`text <text>`
     - |PCMK_CIB_AUTHKEY_FILE|
     - As an alternative to using X509 authentication for remote CIB operations,
       use the contents of this file as the authorization key. This file must be
       readable by Pacemaker daemons (that is, it must allow read permissions
       to either the |CRM_DAEMON_USER| user or the |CRM_DAEMON_GROUP| group), and
       its contents must be identical on both the cluster nodes and the remote
       administration system.

   * - .. _pcmk_remote_pid1:

       .. index::
          pair: node option; PCMK_remote_pid1

       PCMK_remote_pid1
     - :ref:`enumeration <enumeration>`
     - default
     - *Advanced Use Only:* When a bundle resource's ``run-command`` option is
       left to default, :ref:`Pacemaker Remote <pacemaker_remote>` runs as PID
       1 in the bundle's containers. When it does so, it loads environment
       variables from the container's |PCMK_INIT_ENV_FILE| and performs the PID
       1 responsibility of reaping dead subprocesses.

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
          pair: node option; PCMK_tls_priorities

       PCMK_tls_priorities
     - :ref:`text <text>`
     - |PCMK__GNUTLS_PRIORITIES|
     - *Advanced Use Only:* These `GnuTLS cipher priorities
       <https://gnutls.org/manual/html_node/Priority-Strings.html>`_ will be
       used for TLS connections (whether for :ref:`Pacemaker Remote
       <pacemaker_remote>` connections or remote CIB access, when enabled).

       Pacemaker will append ``":+ANON-DH"`` for remote CIB access and
       ``":+DHE-PSK:+PSK"`` for Pacemaker Remote connections, as they are
       required for the respective functionality.

       Example:
       ``PCMK_tls_priorities="SECURE128:+SECURE192"``

   * - .. _pcmk_dh_max_bits:

       .. index::
          pair: node option; PCMK_dh_max_bits

       PCMK_dh_max_bits
     - :ref:`nonnegative integer <nonnegative_integer>`
     - 0 (no maximum)
     - *Advanced Use Only:* Set an upper bound on the bit length of the prime
       number generated for Diffie-Hellman parameters needed by TLS connections.
       The default is no maximum.

       The server (:ref:`Pacemaker Remote <pacemaker_remote>` daemon, or CIB
       manager configured to accept remote clients) will use this value to
       provide a ceiling for the value recommended by the GnuTLS library. The
       library will only accept a limited number of specific values, which vary
       by library version, so setting these is recommended only when required
       for compatibility with specific client versions.

       Clients do not use ``PCMK_dh_max_bits``.

   * - .. _pcmk_ipc_type:

       .. index::
          pair: node option; PCMK_ipc_type

       PCMK_ipc_type
     - :ref:`enumeration <enumeration>`
     - shared-mem
     - *Advanced Use Only:* Force use of a particular IPC method. Allowed values:

       * ``shared-mem``
       * ``socket``
       * ``posix``
       * ``sysv``

   * - .. _pcmk_cluster_type:

       .. index::
          pair: node option; PCMK_cluster_type

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
          pair: node option; PCMK_schema_directory

       PCMK_schema_directory
     - :ref:`text <text>`
     - |PCMK_SCHEMA_DIR|
     - *Advanced Use Only:* Specify an alternate location for RNG schemas and
       XSL transforms.

   * - .. _pcmk_remote_schema_directory:

       .. index::
          pair: node option; PCMK_remote_schema_directory

       PCMK_remote_schema_directory
     - :ref:`text <text>`
     - |PCMK__REMOTE_SCHEMA_DIR|
     - *Advanced Use Only:* Specify an alternate location on
       :ref:`Pacemaker Remote <pacemaker_remote>` nodes for storing newer RNG
       schemas and XSL transforms fetched from the cluster.

   * - .. _pcmk_valgrind_enabled:

       .. index::
          pair: node option; PCMK_valgrind_enabled

       PCMK_valgrind_enabled
     - :ref:`enumeration <enumeration>`
     - no
     - *Advanced Use Only:* Whether subsystem daemons should be run under
       ``valgrind``. Allowed values are the same as for ``PCMK_debug``.

   * - .. _pcmk_callgrind_enabled:

       .. index::
          pair: node option; PCMK_callgrind_enabled

       PCMK_callgrind_enabled
     - :ref:`enumeration <enumeration>`
     - no
     - *Advanced Use Only:* Whether subsystem daemons should be run under
       ``valgrind`` with the ``callgrind`` tool enabled. Allowed values are the
       same as for ``PCMK_debug``.

   * - .. _sbd_sync_resource_startup:

       .. index::
          pair: node option; SBD_SYNC_RESOURCE_STARTUP

       SBD_SYNC_RESOURCE_STARTUP
     - :ref:`boolean <boolean>`
     -
     - If true, ``pacemakerd`` waits for a ping from ``sbd`` during startup
       before starting other Pacemaker daemons, and during shutdown after
       stopping other Pacemaker daemons but before exiting. Default value is set
       based on the ``--with-sbd-sync-default`` configure script option.

   * - .. _sbd_watchdog_timeout:

       .. index::
          pair: node option; SBD_WATCHDOG_TIMEOUT

       SBD_WATCHDOG_TIMEOUT
     - :ref:`duration <duration>`
     -
     - If the ``fencing-watchdog-timeout`` cluster property is set to a negative
       or invalid value, use double this value as the default if positive, or
       use 0 as the default otherwise. This value must be greater than the value
       of ``fencing-watchdog-timeout`` if both are set.

   * - .. _valgrind_opts:

       .. index::
          pair: node option; VALGRIND_OPTS

       VALGRIND_OPTS
     - :ref:`text <text>`
     -
     - *Advanced Use Only:* Pass these options to valgrind, when enabled (see
       ``valgrind(1)``). ``"--vgdb=no"`` should usually be specified because
       ``pacemaker-execd`` can lower privileges when executing commands, which
       would otherwise leave a bunch of unremovable files in ``/tmp``.
