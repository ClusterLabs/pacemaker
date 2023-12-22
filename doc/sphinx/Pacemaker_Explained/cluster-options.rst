Cluster-Wide Configuration
--------------------------

.. index::
   pair: XML element; cib
   pair: XML element; configuration

Configuration Layout
####################

The cluster is defined by the Cluster Information Base (CIB), which uses XML
notation. The simplest CIB, an empty one, looks like this:

.. topic:: An empty configuration

   .. code-block:: xml

      <cib crm_feature_set="3.6.0" validate-with="pacemaker-3.5" epoch="1" num_updates="0" admin_epoch="0">
        <configuration>
          <crm_config/>
          <nodes/>
          <resources/>
          <constraints/>
        </configuration>
        <status/>
      </cib>

The empty configuration above contains the major sections that make up a CIB:

* ``cib``: The entire CIB is enclosed with a ``cib`` element. Certain
  fundamental settings are defined as attributes of this element.

  * ``configuration``: This section -- the primary focus of this document --
    contains traditional configuration information such as what resources the
    cluster serves and the relationships among them.

    * ``crm_config``: cluster-wide configuration options

    * ``nodes``: the machines that host the cluster

    * ``resources``: the services run by the cluster

    * ``constraints``: indications of how resources should be placed

  * ``status``: This section contains the history of each resource on each
    node. Based on this data, the cluster can construct the complete current
    state of the cluster. The authoritative source for this section is the
    local executor (pacemaker-execd process) on each cluster node, and the
    cluster will occasionally repopulate the entire section. For this reason,
    it is never written to disk, and administrators are advised against
    modifying it in any way.

In this document, configuration settings will be described as properties or
options based on how they are defined in the CIB:

* Properties are XML attributes of an XML element.

* Options are name-value pairs expressed as ``nvpair`` child elements of an XML
  element.

Normally, you will use command-line tools that abstract the XML, so the
distinction will be unimportant; both properties and options are cluster
settings you can tweak.


CIB Properties
##############

Certain settings are defined by CIB properties (that is, attributes of the
``cib`` tag) rather than with the rest of the cluster configuration in the
``configuration`` section.

The reason is simply a matter of parsing. These options are used by the
configuration database which is, by design, mostly ignorant of the content it
holds. So the decision was made to place them in an easy-to-find location.

.. list-table:: **CIB Properties**
   :class: longtable
   :widths: 2 2 2 5
   :header-rows: 1

   * - Name
     - Type
     - Default
     - Description
   * - .. _admin_epoch:
       
       .. index::
          pair: admin_epoch; cib
       
       admin_epoch
     - :ref:`nonnegative integer <nonnegative_integer>`
     - 0
     - When a node joins the cluster, the cluster asks the node with the
       highest (``admin_epoch``, ``epoch``, ``num_updates``) tuple to replace
       the configuration on all the nodes -- which makes setting them correctly
       very important. ``admin_epoch`` is never modified by the cluster; you
       can use this to make the configurations on any inactive nodes obsolete.
   * - .. _epoch:
       
       .. index::
          pair: epoch; cib
       
       epoch
     - :ref:`nonnegative integer <nonnegative_integer>`
     - 0
     - The cluster increments this every time the CIB's configuration section
       is updated.
   * - .. _num_updates:
       
       .. index::
          pair: num_updates; cib
       
       num_updates
     - :ref:`nonnegative integer <nonnegative_integer>`
     - 0
     - The cluster increments this every time the CIB's configuration or status
       sections are updated, and resets it to 0 when epoch changes.
   * - .. _validate_with:
       
       .. index::
          pair: validate-with; cib
       
       validate-with
     - :ref:`enumeration <enumeration>`
     -
     - Determines the type of XML validation that will be done on the
       configuration. Allowed values are ``none`` (in which case the cluster
       will not require that updates conform to expected syntax) and the base
       names of schema files installed on the local machine (for example,
       "pacemaker-3.9")
   * - .. _remote_tls_port:
       
       .. index::
          pair: remote-tls-port; cib
       
       remote-tls-port
     - :ref:`port <port>`
     -
     - If set, the CIB manager will listen for anonymously encrypted remote
       connections on this port, to allow CIB administration from hosts not in
       the cluster. No key is used, so this should be used only on a protected
       network where man-in-the-middle attacks can be avoided.
   * - .. _remote_clear_port:
       
       .. index::
          pair: remote-clear-port; cib
       
       remote-clear-port
     - :ref:`port <port>`
     -
     - If set to a TCP port number, the CIB manager will listen for remote
       connections on this port, to allow for CIB administration from hosts not
       in the cluster. No encryption is used, so this should be used only on a
       protected network.
   * - .. _cib_last_written:
       
       .. index::
          pair: cib-last-written; cib
       
       cib-last-written
     - :ref:`date/time <date_time>`
     -
     - Indicates when the configuration was last written to disk. Maintained by
       the cluster; for informational purposes only.
   * - .. _have_quorum:
       
       .. index::
          pair: have-quorum; cib
       
       have-quorum
     - :ref:`boolean <boolean>`
     -
     - Indicates whether the cluster has quorum. If false, the cluster's
       response is determined by ``no-quorum-policy`` (see below). Maintained
       by the cluster.
   * - .. _dc_uuid:
       
       .. index::
          pair: dc-uuid; cib
       
       dc-uuid
     - :ref:`text <text>`
     -
     - Node ID of the cluster's current designated controller (DC). Used and
       maintained by the cluster.


.. _cluster_options:

Cluster Options
###############

Cluster options, as you might expect, control how the cluster behaves when
confronted with various situations.

They are grouped into sets within the ``crm_config`` section. In advanced
configurations, there may be more than one set. (This will be described later
in the chapter on :ref:`rules` where we will show how to have the cluster use
different sets of options during working hours than during weekends.) For now,
we will describe the simple case where each option is present at most once.

You can obtain an up-to-date list of cluster options, including their default
values, by running the ``man pacemaker-schedulerd`` and
``man pacemaker-controld`` commands.

.. list-table:: **Cluster Options**
   :class: longtable
   :widths: 2 2 2 5
   :header-rows: 1

   * - Name
     - Type
     - Default
     - Description
   * - .. _cluster_name:
       
       .. index::
          pair: cluster option; cluster-name
       
       cluster-name
     - :ref:`text <text>`
     -
     - An (optional) name for the cluster as a whole. This is mostly for users'
       convenience for use as desired in administration, but can be used in the
       Pacemaker configuration in :ref:`rules` (as the ``#cluster-name``
       :ref:`node attribute <node-attribute-expressions-special>`). It may also
       be used by higher-level tools when displaying cluster information, and
       by certain resource agents (for example, the ``ocf:heartbeat:GFS2``
       agent stores the cluster name in filesystem meta-data).
   * - .. _dc_version:
       
       .. index::
          pair: cluster option; dc-version
       
       dc-version
     - :ref:`version <version>`
     - *detected*
     - Version of Pacemaker on the cluster's designated controller (DC).
       Maintained by the cluster, and intended for diagnostic purposes.
   * - .. _cluster_infrastructure:
       
       .. index::
          pair: cluster option; cluster-infrastructure
       
       cluster-infrastructure
     - :ref:`text <text>`
     - *detected*
     - The messaging layer with which Pacemaker is currently running.
       Maintained by the cluster, and intended for informational and diagnostic
       purposes.
   * - .. _no_quorum_policy:
       
       .. index::
          pair: cluster option; no-quorum-policy
       
       no-quorum-policy
     - :ref:`enumeration <enumeration>`
     - stop
     - What to do when the cluster does not have quorum. Allowed values:
       
       * ``ignore:`` continue all resource management
       * ``freeze:`` continue resource management, but don't recover resources
         from nodes not in the affected partition
       * ``stop:`` stop all resources in the affected cluster partition
       * ``demote:`` demote promotable resources and stop all other resources
         in the affected cluster partition *(since 2.0.5)*
       * ``suicide:`` fence all nodes in the affected cluster partition
   * - .. _batch_limit:
       
       .. index::
          pair: cluster option; batch-limit
       
       batch-limit
     - :ref:`integer <integer>`
     - 0
     - The maximum number of actions that the cluster may execute in parallel
       across all nodes. The ideal value will depend on the speed and load
       of your network and cluster nodes. If zero, the cluster will impose a
       dynamically calculated limit only when any node has high load. If -1,
       the cluster will not impose any limit.
   * - .. _migration_limit:
       
       .. index::
          pair: cluster option; migration-limit
       
       migration-limit
     - :ref:`integer <integer>`
     - -1
     - The number of :ref:`live migration <live-migration>` actions that the
       cluster is allowed to execute in parallel on a node. A value of -1 means
       unlimited.
   * - .. _load_threshold:
       
       .. index::
          pair: cluster option; load-threshold
       
       load-threshold
     - :ref:`percentage <percentage>`
     - 80%
     - Maximum amount of system load that should be used by cluster nodes. The
       cluster will slow down its recovery process when the amount of system
       resources used (currently CPU) approaches this limit.
   * - .. _symmetric_cluster:
       
       .. index::
          pair: cluster option; symmetric-cluster
       
       symmetric-cluster
     - :ref:`boolean <boolean>`
     - true
     - If true, resources can run on any node by default. If false, a resource
       is allowed to run on a node only if a
       :ref:`location constraint <location-constraint>` enables it.
   * - .. _stop_all_resources:
       
       .. index::
          pair: cluster option; stop-all-resources
       
       stop-all-resources
     - :ref:`boolean <boolean>`
     - false
     - Whether all resources should be disallowed from running (can be useful
       during maintenance or troubleshooting)
   * - .. _stop_orphan_resources:
       
       .. index::
          pair: cluster option; stop-orphan-resources
       
       stop-orphan-resources
     - :ref:`boolean <boolean>`
     - true
     - Whether resources that have been deleted from the configuration should
       be stopped. This value takes precedence over
       :ref:`is-managed <is_managed>` (that is, even unmanaged resources will
       be stopped when orphaned if this value is ``true``).
   * - .. _stop_orphan_actions:
       
       .. index::
          pair: cluster option; stop-orphan-actions
       
       stop-orphan-actions
     - :ref:`boolean <boolean>`
     - true
     - Whether recurring :ref:`operations <operation>` that have been deleted
       from the configuration should be cancelled
   * - .. _start_failure_is_fatal:
      
       .. index::
          pair: cluster option; start-failure-is-fatal
      
       start-failure-is-fatal
     - :ref:`boolean <boolean>`
     - true
     - Whether a failure to start a resource on a particular node prevents
       further start attempts on that node. If ``false``, the cluster will
       decide whether the node is still eligible based on the resource's
       current failure count and ``migration-threshold``.
   * - .. _enable_startup_probes:
      
       .. index::
          pair: cluster option; enable-startup-probes
      
       enable-startup-probes
     - :ref:`boolean <boolean>`
     - true
     - Whether the cluster should check the pre-existing state of resources
       when the cluster starts
   * - .. _maintenance_mode:
      
       .. index::
          pair: cluster option; maintenance-mode
      
       maintenance-mode
     - :ref:`boolean <boolean>`
     - false
     - If true, the cluster will not start or stop any resource in the cluster,
       and any recurring operations (expect those specifying ``role`` as
       ``Stopped``) will be paused. If true, this overrides the
       :ref:`maintenance <node_maintenance>` node attribute,
       :ref:`is-managed <is_managed>` and :ref:`maintenance <rsc_maintenance>`
       resource meta-attributes, and :ref:`enabled <op_enabled>` operation
       meta-attribute.
   * - .. _stonith_enabled:
      
       .. index::
          pair: cluster option; stonith-enabled
      
       stonith-enabled
     - :ref:`boolean <boolean>`
     - true
     - Whether the cluster is allowed to fence nodes (for example, failed nodes
       and nodes with resources that can't be stopped).
       
       If true, at least one fence device must be configured before resources
       are allowed to run.
       
       If false, unresponsive nodes are immediately assumed to be running no
       resources, and resource recovery on online nodes starts without any
       further protection (which can mean *data loss* if the unresponsive node
       still accesses shared storage, for example). See also the
       :ref:`requires <requires>` resource meta-attribute.
   * - .. _stonith_action:
      
       .. index::
          pair: cluster option; stonith-action
      
       stonith-action
     - :ref:`enumeration <enumeration>`
     - reboot
     - Action the cluster should send to the fence agent when a node must be
       fenced. Allowed values are ``reboot``, ``off``, and (for legacy agents
       only) ``poweroff``.
   * - .. _stonith_timeout:
      
       .. index::
          pair: cluster option; stonith-timeout
      
       stonith-timeout
     - :ref:`duration <duration>`
     - 60s
     - How long to wait for ``on``, ``off``, and ``reboot`` fence actions to
       complete by default.
   * - .. _stonith_max_attempts:
      
       .. index::
          pair: cluster option; stonith-max-attempts
      
       stonith-max-attempts
     - :ref:`score <score>`
     - 10
     - How many times fencing can fail for a target before the cluster will no
       longer immediately re-attempt it. Any value below 1 will be ignored, and
       the default will be used instead.
   * - .. _have_watchdog:

       .. index::
          pair: cluster option; have-watchdog

       have-watchdog
     - :ref:`boolean <boolean>`
     - *detected*
     - Whether watchdog integration is enabled. This is set automatically by the
       cluster according to whether SBD is detected to be in use.
       User-configured values are ignored. The value `true` is meaningful if
       diskless SBD is used and
       :ref:`stonith-watchdog-timeout <stonith_watchdog_timeout>` is nonzero. In
       that case, if fencing is required, watchdog-based self-fencing will be
       performed via SBD without requiring a fencing resource explicitly
       configured.
   * - .. _stonith_watchdog_timeout:
      
       .. index::
          pair: cluster option; stonith-watchdog-timeout
      
       stonith-watchdog-timeout
     - :ref:`timeout <timeout>`
     - 0
     - If nonzero, and the cluster detects ``have-watchdog`` as ``true``, then
       watchdog-based self-fencing will be performed via SBD when fencing is
       required, without requiring a fencing resource explicitly configured.
       
       If this is set to a positive value, unseen nodes are assumed to
       self-fence within this much time.
       
       **Warning:** It must be ensured that this value is larger than the
       ``SBD_WATCHDOG_TIMEOUT`` environment variable on all nodes. Pacemaker
       verifies the settings individually on all nodes and prevents startup or
       shuts down if configured wrongly on the fly. It is strongly recommended
       that ``SBD_WATCHDOG_TIMEOUT`` be set to the same value on all nodes.
       
       If this is set to a negative value, and ``SBD_WATCHDOG_TIMEOUT`` is set,
       twice that value will be used.
       
       **Warning:** In this case, it is essential (and currently not verified
       by pacemaker) that ``SBD_WATCHDOG_TIMEOUT`` is set to the same value on
       all nodes.
   * - .. _concurrent-fencing:
      
       .. index::
          pair: cluster option; concurrent-fencing
      
       concurrent-fencing
     - :ref:`boolean <boolean>`
     - false
     - Whether the cluster is allowed to initiate multiple fence actions
       concurrently. Fence actions initiated externally, such as via the
       ``stonith_admin`` tool or an application such as DLM, or by the fencer
       itself such as recurring device monitors and ``status`` and ``list``
       commands, are not limited by this option.
   * - .. _fence_reaction:
      
       .. index::
          pair: cluster option; fence-reaction
      
       fence-reaction
     - :ref:`enumeration <enumeration>`
     - stop
     - How should a cluster node react if notified of its own fencing? A
       cluster node may receive notification of its own fencing if fencing is
       misconfigured, or if fabric fencing is in use that doesn't cut cluster
       communication. Allowed values are ``stop`` to attempt to immediately
       stop Pacemaker and stay stopped, or ``panic`` to attempt to immediately
       reboot the local node, falling back to stop on failure. The default is
       likely to be changed to ``panic`` in a future release. *(since 2.0.3)*
   * - .. _priority_fencing_delay:
      
       .. index::
          pair: cluster option; priority-fencing-delay
      
       priority-fencing-delay
     - :ref:`duration <duration>`
     - 0
     - Apply this delay to any fencing targeting the lost nodes with the
       highest total resource priority in case we don't have the majority of
       the nodes in our cluster partition, so that the more significant nodes
       potentially win any fencing match (especially meaningful in a
       split-brain of a 2-node cluster). A promoted resource instance takes the
       resource's priority plus 1 if the resource's priority is not 0. Any
       static or random delays introduced by ``pcmk_delay_base`` and
       ``pcmk_delay_max`` configured for the corresponding fencing resources
       will be added to this delay. This delay should be significantly greater
       than (safely twice) the maximum delay from those parameters. *(since
       2.0.4)*
   * - .. _node_pending_timeout:
      
       .. index::
          pair: cluster option; node-pending-timeout
      
       node-pending-timeout
     - :ref:`duration <duration>`
     - 0
     - Fence nodes that do not join the controller process group within this
       much time after joining the cluster, to allow the cluster to continue
       managing resources. A value of 0 means never fence pending nodes. Setting the value to 2h means fence nodes after 2 hours. 
       *(since 2.1.7)*
   * - .. _cluster_delay:
      
       .. index::
          pair: cluster option; cluster-delay
      
       cluster-delay
     - :ref:`duration <duration>`
     - 60s
     - If the DC requires an action to be executed on another node, it will
       consider the action failed if it does not get a response from the other
       node within this time (beyond the action's own timeout). The ideal value
       will depend on the speed and load of your network and cluster nodes.
   * - .. _dc_deadtime:
      
       .. index::
          pair: cluster option; dc-deadtime
      
       dc-deadtime
     - :ref:`duration <duration>`
     - 20s
     - How long to wait for a response from other nodes when electing a DC. The
       ideal value will depend on the speed and load of your network and
       cluster nodes.
   * - .. _cluster_ipc_limit:
      
       .. index::
          pair: cluster option; cluster-ipc-limit
      
       cluster-ipc-limit
     - :ref:`nonnegative integer <nonnegative_integer>`
     - 500
     - The maximum IPC message backlog before one cluster daemon will
       disconnect another. This is of use in large clusters, for which a good
       value is the number of resources in the cluster multiplied by the number
       of nodes. The default of 500 is also the minimum. Raise this if you see
       "Evicting client" log messages for cluster daemon process IDs.
   * - .. _pe_error_series_max:
      
       .. index::
          pair: cluster option; pe-error-series-max
      
       pe-error-series-max
     - :ref:`integer <integer>`
     - -1
     - The number of scheduler inputs resulting in errors to save. These inputs
       can be helpful during troubleshooting and when reporting issues. A
       negative value means save all inputs, and 0 means save none.
   * - .. _pe_warn_series_max:
      
       .. index::
          pair: cluster option; pe-warn-series-max
      
       pe-warn-series-max
     - :ref:`integer <integer>`
     - 5000
     - The number of scheduler inputs resulting in warnings to save. These
       inputs can be helpful during troubleshooting and when reporting issues.
       A negative value means save all inputs, and 0 means save none.
   * - .. _pe_input_series_max:
      
       .. index::
          pair: cluster option; pe-input-series-max
      
       pe-input-series-max
     - :ref:`integer <integer>`
     - 4000
     - The number of "normal" scheduler inputs to save. These inputs can be
       helpful during troubleshooting and when reporting issues. A negative
       value means save all inputs, and 0 means save none.
   * - .. _enable_acl:
      
       .. index::
          pair: cluster option; enable-acl
      
       enable-acl
     - :ref:`boolean <boolean>`
     - false
     - Whether :ref:`access control lists <acl>` should be used to authorize
       CIB modifications
   * - .. _placement_strategy:
      
       .. index::
          pair: cluster option; placement-strategy
      
       placement-strategy
     - :ref:`enumeration <enumeration>`
     - default
     - How the cluster should assign resources to nodes (see
       :ref:`utilization`). Allowed values are ``default``, ``utilization``,
       ``balanced``, and ``minimal``.
   * - .. _node_health_strategy:
      
       .. index::
          pair: cluster option; node-health-strategy
      
       node-health-strategy
     - :ref:`enumeration <enumeration>`
     - none
     - How the cluster should react to :ref:`node health <node-health>`
       attributes. Allowed values are ``none``, ``migrate-on-red``,
       ``only-green``, ``progressive``, and ``custom``.
   * - .. _node_health_base:
      
       .. index::
          pair: cluster option; node-health-base
      
       node-health-base
     - :ref:`score <score>`
     - 0
     - The base health score assigned to a node. Only used when
       ``node-health-strategy`` is ``progressive``.
   * - .. _node_health_green:
      
       .. index::
          pair: cluster option; node-health-green
      
       node-health-green
     - :ref:`score <score>`
     - 0
     - The score to use for a node health attribute whose value is ``green``.
       Only used when ``node-health-strategy`` is ``progressive`` or
       ``custom``.
   * - .. _node_health_yellow:
      
       .. index::
          pair: cluster option; node-health-yellow
      
       node-health-yellow
     - :ref:`score <score>`
     - 0
     - The score to use for a node health attribute whose value is ``yellow``.
       Only used when ``node-health-strategy`` is ``progressive`` or
       ``custom``.
   * - .. _node_health_red:
      
       .. index::
          pair: cluster option; node-health-red
      
       node-health-red
     - :ref:`score <score>`
     - -INFINITY
     - The score to use for a node health attribute whose value is ``red``.
       Only used when ``node-health-strategy`` is ``progressive`` or
       ``custom``.
   * - .. _cluster_recheck_interval:
      
       .. index::
          pair: cluster option; cluster-recheck-interval
      
       cluster-recheck-interval
     - :ref:`duration <duration>`
     - 15min
     - Pacemaker is primarily event-driven, and looks ahead to know when to
       recheck the cluster for failure timeouts and most time-based rules
       *(since 2.0.3)*. However, it will also recheck the cluster after this
       amount of inactivity. This has two goals: rules with ``date_spec`` are
       only guaranteed to be checked this often, and it also serves as a
       fail-safe for some kinds of scheduler bugs. A value of 0 disables this
       polling.
   * - .. _shutdown_lock:
      
       .. index::
          pair: cluster option; shutdown-lock
      
       shutdown-lock
     - :ref:`boolean <boolean>`
     - false
     - The default of false allows active resources to be recovered elsewhere
       when their node is cleanly shut down, which is what the vast majority of
       users will want. However, some users prefer to make resources highly
       available only for failures, with no recovery for clean shutdowns. If
       this option is true, resources active on a node when it is cleanly shut
       down are kept "locked" to that node (not allowed to run elsewhere) until
       they start again on that node after it rejoins (or for at most
       ``shutdown-lock-limit``, if set). Stonith resources and Pacemaker Remote
       connections are never locked. Clone and bundle instances and the
       promoted role of promotable clones are currently never locked, though
       support could be added in a future release. Locks may be manually
       cleared using the ``--refresh`` option of ``crm_resource`` (both the
       resource and node must be specified; this works with remote nodes if
       their connection resource's ``target-role`` is set to ``Stopped``, but
       not if Pacemaker Remote is stopped on the remote node without disabling
       the connection resource). *(since 2.0.4)*
   * - .. _shutdown_lock_limit:
      
       .. index::
          pair: cluster option; shutdown-lock-limit
      
       shutdown-lock-limit
     - :ref:`duration <duration>`
     - 0
     - If ``shutdown-lock`` is true, and this is set to a nonzero time
       duration, locked resources will be allowed to start after this much time
       has passed since the node shutdown was initiated, even if the node has
       not rejoined. (This works with remote nodes only if their connection
       resource's ``target-role`` is set to ``Stopped``.) *(since 2.0.4)*
   * - .. _remove_after_stop:
      
       .. index::
          pair: cluster option; remove-after-stop
      
       remove-after-stop
     - :ref:`boolean <boolean>`
     - false
     - *Deprecated* Whether the cluster should remove resources from
       Pacemaker's executor after they are stopped. Values other than the
       default are, at best, poorly tested and potentially dangerous.  This
       option is deprecated and will be removed in a future release.
   * - .. _startup_fencing:
      
       .. index::
          pair: cluster option; startup-fencing
      
       startup-fencing
     - :ref:`boolean <boolean>`
     - true
     - *Advanced Use Only:* Whether the cluster should fence unseen nodes at
       start-up. Setting this to false is unsafe, because the unseen nodes
       could be active and running resources but unreachable. ``dc-deadtime``
       acts as a grace period before this fencing, since a DC must be elected
       to schedule fencing.
   * - .. _election_timeout:
      
       .. index::
          pair: cluster option; election-timeout
      
       election-timeout
     - :ref:`duration <duration>`
     - 2min
     - *Advanced Use Only:* If a winner is not declared within this much time
       of starting an election, the node that initiated the election will
       declare itself the winner.
   * - .. _shutdown_escalation:
      
       .. index::
          pair: cluster option; shutdown-escalation
      
       shutdown-escalation
     - :ref:`duration <duration>`
     - 20min
     - *Advanced Use Only:* The controller will exit immediately if a shutdown
       does not complete within this much time.
   * - .. _join_integration_timeout:
      
       .. index::
          pair: cluster option; join-integration-timeout
      
       join-integration-timeout
     - :ref:`duration <duration>`
     - 3min
     - *Advanced Use Only:* If you need to adjust this value, it probably
       indicates the presence of a bug.
   * - .. _join_finalization_timeout:
      
       .. index::
          pair: cluster option; join-finalization-timeout
      
       join-finalization-timeout
     - :ref:`duration <duration>`
     - 30min
     - *Advanced Use Only:* If you need to adjust this value, it probably
       indicates the presence of a bug.
   * - .. _transition_delay:
      
       .. index::
          pair: cluster option; transition-delay
      
       transition-delay
     - :ref:`duration <duration>`
     - 0s
     - *Advanced Use Only:* Delay cluster recovery for the configured interval
       to allow for additional or related events to occur. This can be useful
       if your configuration is sensitive to the order in which ping updates
       arrive. Enabling this option will slow down cluster recovery under all
       conditions.
