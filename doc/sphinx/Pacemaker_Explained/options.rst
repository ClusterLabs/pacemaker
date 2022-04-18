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

.. table:: **CIB Properties**
   :class: longtable
   :widths: 1 3

   +------------------+-----------------------------------------------------------+
   | Attribute        | Description                                               |
   +==================+===========================================================+
   | admin_epoch      | .. index::                                                |
   |                  |    pair: admin_epoch; cib                                 |
   |                  |                                                           |
   |                  | When a node joins the cluster, the cluster performs a     |
   |                  | check to see which node has the best configuration. It    |
   |                  | asks the node with the highest (``admin_epoch``,          |
   |                  | ``epoch``, ``num_updates``) tuple to replace the          |
   |                  | configuration on all the nodes -- which makes setting     |
   |                  | them, and setting them correctly, very important.         |
   |                  | ``admin_epoch`` is never modified by the cluster; you can |
   |                  | use this to make the configurations on any inactive nodes |
   |                  | obsolete.                                                 |
   |                  |                                                           |
   |                  | **Warning:** Never set this value to zero. In such cases, |
   |                  | the cluster cannot tell the difference between your       |
   |                  | configuration and the "empty" one used when nothing is    |
   |                  | found on disk.                                            |
   +------------------+-----------------------------------------------------------+
   | epoch            | .. index::                                                |
   |                  |    pair: epoch; cib                                       |
   |                  |                                                           |
   |                  | The cluster increments this every time the configuration  |
   |                  | is updated (usually by the administrator).                |
   +------------------+-----------------------------------------------------------+
   | num_updates      | .. index::                                                |
   |                  |    pair: num_updates; cib                                 |
   |                  |                                                           |
   |                  | The cluster increments this every time the configuration  |
   |                  | or status is updated (usually by the cluster) and resets  |
   |                  | it to 0 when epoch changes.                               |
   +------------------+-----------------------------------------------------------+
   | validate-with    | .. index::                                                |
   |                  |    pair: validate-with; cib                               |
   |                  |                                                           |
   |                  | Determines the type of XML validation that will be done   |
   |                  | on the configuration.  If set to ``none``, the cluster    |
   |                  | will not verify that updates conform to the DTD (nor      |
   |                  | reject ones that don't).                                  |
   +------------------+-----------------------------------------------------------+
   | cib-last-written | .. index::                                                |
   |                  |    pair: cib-last-written; cib                            |
   |                  |                                                           |
   |                  | Indicates when the configuration was last written to      |
   |                  | disk. Maintained by the cluster; for informational        |
   |                  | purposes only.                                            |
   +------------------+-----------------------------------------------------------+
   | have-quorum      | .. index::                                                |
   |                  |    pair: have-quorum; cib                                 |
   |                  |                                                           |
   |                  | Indicates if the cluster has quorum. If false, this may   |
   |                  | mean that the cluster cannot start resources or fence     |
   |                  | other nodes (see ``no-quorum-policy`` below). Maintained  |
   |                  | by the cluster.                                           |
   +------------------+-----------------------------------------------------------+
   | dc-uuid          | .. index::                                                |
   |                  |    pair: dc-uuid; cib                                     |
   |                  |                                                           |
   |                  | Indicates which cluster node is the current leader. Used  |
   |                  | by the cluster when placing resources and determining the |
   |                  | order of some events. Maintained by the cluster.          |
   +------------------+-----------------------------------------------------------+

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

.. table:: **Cluster Options**
   :class: longtable
   :widths: 2 1 4

   +---------------------------+---------+----------------------------------------------------+
   | Option                    | Default | Description                                        |
   +===========================+=========+====================================================+
   | cluster-name              |         | .. index::                                         |
   |                           |         |    pair: cluster option; cluster-name              |
   |                           |         |                                                    |
   |                           |         | An (optional) name for the cluster as a whole.     |
   |                           |         | This is mostly for users' convenience for use      |
   |                           |         | as desired in administration, but this can be      |
   |                           |         | used in the Pacemaker configuration in             |
   |                           |         | :ref:`rules` (as the ``#cluster-name``             |
   |                           |         | :ref:`node attribute                               |
   |                           |         | <node-attribute-expressions-special>`. It may      |
   |                           |         | also be used by higher-level tools when            |
   |                           |         | displaying cluster information, and by             |
   |                           |         | certain resource agents (for example, the          |
   |                           |         | ``ocf:heartbeat:GFS2`` agent stores the            |
   |                           |         | cluster name in filesystem meta-data).             |
   +---------------------------+---------+----------------------------------------------------+
   | dc-version                |         | .. index::                                         |
   |                           |         |    pair: cluster option; dc-version                |
   |                           |         |                                                    |
   |                           |         | Version of Pacemaker on the cluster's DC.          |
   |                           |         | Determined automatically by the cluster. Often     |
   |                           |         | includes the hash which identifies the exact       |
   |                           |         | Git changeset it was built from. Used for          |
   |                           |         | diagnostic purposes.                               |
   +---------------------------+---------+----------------------------------------------------+
   | cluster-infrastructure    |         | .. index::                                         |
   |                           |         |    pair: cluster option; cluster-infrastructure    |
   |                           |         |                                                    |
   |                           |         | The messaging stack on which Pacemaker is          |
   |                           |         | currently running. Determined automatically by     |
   |                           |         | the cluster. Used for informational and            |
   |                           |         | diagnostic purposes.                               |
   +---------------------------+---------+----------------------------------------------------+
   | no-quorum-policy          | stop    | .. index::                                         |
   |                           |         |    pair: cluster option; no-quorum-policy          |
   |                           |         |                                                    |
   |                           |         | What to do when the cluster does not have          |
   |                           |         | quorum. Allowed values:                            |
   |                           |         |                                                    |
   |                           |         | * ``ignore:`` continue all resource management     |
   |                           |         | * ``freeze:`` continue resource management, but    |
   |                           |         |   don't recover resources from nodes not in the    |
   |                           |         |   affected partition                               |
   |                           |         | * ``stop:`` stop all resources in the affected     |
   |                           |         |   cluster partition                                |
   |                           |         | * ``demote:`` demote promotable resources and      |
   |                           |         |   stop all other resources in the affected         |
   |                           |         |   cluster partition *(since 2.0.5)*                |
   |                           |         | * ``suicide:`` fence all nodes in the affected     |
   |                           |         |   cluster partition                                |
   +---------------------------+---------+----------------------------------------------------+
   | batch-limit               | 0       | .. index::                                         |
   |                           |         |    pair: cluster option; batch-limit               |
   |                           |         |                                                    |
   |                           |         | The maximum number of actions that the cluster     |
   |                           |         | may execute in parallel across all nodes. The      |
   |                           |         | "correct" value will depend on the speed and       |
   |                           |         | load of your network and cluster nodes. If zero,   |
   |                           |         | the cluster will impose a dynamically calculated   |
   |                           |         | limit only when any node has high load. If -1, the |
   |                           |         | cluster will not impose any limit.                 |
   +---------------------------+---------+----------------------------------------------------+
   | migration-limit           | -1      | .. index::                                         |
   |                           |         |    pair: cluster option; migration-limit           |
   |                           |         |                                                    |
   |                           |         | The number of                                      |
   |                           |         | :ref:`live migration <live-migration>` actions     |
   |                           |         | that the cluster is allowed to execute in          |
   |                           |         | parallel on a node. A value of -1 means            |
   |                           |         | unlimited.                                         |
   +---------------------------+---------+----------------------------------------------------+
   | symmetric-cluster         | true    | .. index::                                         |
   |                           |         |    pair: cluster option; symmetric-cluster         |
   |                           |         |                                                    |
   |                           |         | Whether resources can run on any node by default   |
   |                           |         | (if false, a resource is allowed to run on a       |
   |                           |         | node only if a                                     |
   |                           |         | :ref:`location constraint <location-constraint>`   |
   |                           |         | enables it)                                        |
   +---------------------------+---------+----------------------------------------------------+
   | stop-all-resources        | false   | .. index::                                         |
   |                           |         |    pair: cluster option; stop-all-resources        |
   |                           |         |                                                    |
   |                           |         | Whether all resources should be disallowed from    |
   |                           |         | running (can be useful during maintenance)         |
   +---------------------------+---------+----------------------------------------------------+
   | stop-orphan-resources     | true    | .. index::                                         |
   |                           |         |    pair: cluster option; stop-orphan-resources     |
   |                           |         |                                                    |
   |                           |         | Whether resources that have been deleted from      |
   |                           |         | the configuration should be stopped. This value    |
   |                           |         | takes precedence over ``is-managed`` (that is,     |
   |                           |         | even unmanaged resources will be stopped when      |
   |                           |         | orphaned if this value is ``true``                 |
   +---------------------------+---------+----------------------------------------------------+
   | stop-orphan-actions       | true    | .. index::                                         |
   |                           |         |    pair: cluster option; stop-orphan-actions       |
   |                           |         |                                                    |
   |                           |         | Whether recurring :ref:`operations <operation>`    |
   |                           |         | that have been deleted from the configuration      |
   |                           |         | should be cancelled                                |
   +---------------------------+---------+----------------------------------------------------+
   | start-failure-is-fatal    | true    | .. index::                                         |
   |                           |         |    pair: cluster option; start-failure-is-fatal    |
   |                           |         |                                                    |
   |                           |         | Whether a failure to start a resource on a         |
   |                           |         | particular node prevents further start attempts    |
   |                           |         | on that node? If ``false``, the cluster will       |
   |                           |         | decide whether the node is still eligible based    |
   |                           |         | on the resource's current failure count and        |
   |                           |         | :ref:`migration-threshold <failure-handling>`.     |
   +---------------------------+---------+----------------------------------------------------+
   | enable-startup-probes     | true    | .. index::                                         |
   |                           |         |    pair: cluster option; enable-startup-probes     |
   |                           |         |                                                    |
   |                           |         | Whether the cluster should check the               |
   |                           |         | pre-existing state of resources when the cluster   |
   |                           |         | starts                                             |
   +---------------------------+---------+----------------------------------------------------+
   | maintenance-mode          | false   | .. index::                                         |
   |                           |         |    pair: cluster option; maintenance-mode          |
   |                           |         |                                                    |
   |                           |         | Whether the cluster should refrain from            |
   |                           |         | monitoring, starting and stopping resources        |
   +---------------------------+---------+----------------------------------------------------+
   | stonith-enabled           | true    | .. index::                                         |
   |                           |         |    pair: cluster option; stonith-enabled           |
   |                           |         |                                                    |
   |                           |         | Whether the cluster is allowed to fence nodes      |
   |                           |         | (for example, failed nodes and nodes with          |
   |                           |         | resources that can't be stopped.                   |
   |                           |         |                                                    |
   |                           |         | If true, at least one fence device must be         |
   |                           |         | configured before resources are allowed to run.    |
   |                           |         |                                                    |
   |                           |         | If false, unresponsive nodes are immediately       |
   |                           |         | assumed to be running no resources, and resource   |
   |                           |         | recovery on online nodes starts without any        |
   |                           |         | further protection (which can mean *data loss*     |
   |                           |         | if the unresponsive node still accesses shared     |
   |                           |         | storage, for example). See also the                |
   |                           |         | :ref:`requires <requires>` resource                |
   |                           |         | meta-attribute.                                    |
   +---------------------------+---------+----------------------------------------------------+
   | stonith-action            | reboot  | .. index::                                         |
   |                           |         |    pair: cluster option; stonith-action            |
   |                           |         |                                                    |
   |                           |         | Action the cluster should send to the fence agent  |
   |                           |         | when a node must be fenced. Allowed values are     |
   |                           |         | ``reboot``, ``off``, and (for legacy agents only)  |
   |                           |         | ``poweroff``.                                      |
   +---------------------------+---------+----------------------------------------------------+
   | stonith-timeout           | 60s     | .. index::                                         |
   |                           |         |    pair: cluster option; stonith-timeout           |
   |                           |         |                                                    |
   |                           |         | How long to wait for ``on``, ``off``, and          |
   |                           |         | ``reboot`` fence actions to complete by default.   |
   +---------------------------+---------+----------------------------------------------------+
   | stonith-max-attempts      | 10      | .. index::                                         |
   |                           |         |    pair: cluster option; stonith-max-attempts      |
   |                           |         |                                                    |
   |                           |         | How many times fencing can fail for a target       |
   |                           |         | before the cluster will no longer immediately      |
   |                           |         | re-attempt it.                                     |
   +---------------------------+---------+----------------------------------------------------+
   | stonith-watchdog-timeout  | 0       | .. index::                                         |
   |                           |         |    pair: cluster option; stonith-watchdog-timeout  |
   |                           |         |                                                    |
   |                           |         | If nonzero, and the cluster detects                |
   |                           |         | ``have-watchdog`` as ``true``, then watchdog-based |
   |                           |         | self-fencing will be performed via SBD when        |
   |                           |         | fencing is required, without requiring a fencing   |
   |                           |         | resource explicitly configured.                    |
   |                           |         |                                                    |
   |                           |         | If this is set to a positive value, unseen nodes   |
   |                           |         | are assumed to self-fence within this much time.   |
   |                           |         |                                                    |
   |                           |         | **Warning:** It must be ensured that this value is |
   |                           |         | larger than the ``SBD_WATCHDOG_TIMEOUT``           |
   |                           |         | environment variable on all nodes. Pacemaker       |
   |                           |         | verifies the settings individually on all nodes    |
   |                           |         | and prevents startup or shuts down if configured   |
   |                           |         | wrongly on the fly. It is strongly recommended     |
   |                           |         | that ``SBD_WATCHDOG_TIMEOUT`` be set to the same   |
   |                           |         | value on all nodes.                                |
   |                           |         |                                                    |
   |                           |         | If this is set to a negative value, and            |
   |                           |         | ``SBD_WATCHDOG_TIMEOUT`` is set, twice that value  |
   |                           |         | will be used.                                      |
   |                           |         |                                                    |
   |                           |         | **Warning:** In this case, it is essential (and    |
   |                           |         | currently not verified by pacemaker) that          |
   |                           |         | ``SBD_WATCHDOG_TIMEOUT`` is set to the same        |
   |                           |         | value on all nodes.                                |
   +---------------------------+---------+----------------------------------------------------+
   | concurrent-fencing        | false   | .. index::                                         |
   |                           |         |    pair: cluster option; concurrent-fencing        |
   |                           |         |                                                    |
   |                           |         | Whether the cluster is allowed to initiate         |
   |                           |         | multiple fence actions concurrently. Fence actions |
   |                           |         | initiated externally, such as via the              |
   |                           |         | ``stonith_admin`` tool or an application such as   |
   |                           |         | DLM, or by the fencer itself such as recurring     |
   |                           |         | device monitors and ``status`` and ``list``        |
   |                           |         | commands, are not limited by this option.          |
   +---------------------------+---------+----------------------------------------------------+
   | fence-reaction            | stop    | .. index::                                         |
   |                           |         |    pair: cluster option; fence-reaction            |
   |                           |         |                                                    |
   |                           |         | How should a cluster node react if notified of its |
   |                           |         | own fencing? A cluster node may receive            |
   |                           |         | notification of its own fencing if fencing is      |
   |                           |         | misconfigured, or if fabric fencing is in use that |
   |                           |         | doesn't cut cluster communication. Allowed values  |
   |                           |         | are ``stop`` to attempt to immediately stop        |
   |                           |         | pacemaker and stay stopped, or ``panic`` to        |
   |                           |         | attempt to immediately reboot the local node,      |
   |                           |         | falling back to stop on failure. The default is    |
   |                           |         | likely to be changed to ``panic`` in a future      |
   |                           |         | release. *(since 2.0.3)*                           |
   +---------------------------+---------+----------------------------------------------------+
   | priority-fencing-delay    | 0       | .. index::                                         |
   |                           |         |    pair: cluster option; priority-fencing-delay    |
   |                           |         |                                                    |
   |                           |         | Apply this delay to any fencing targeting the lost |
   |                           |         | nodes with the highest total resource priority in  |
   |                           |         | case we don't have the majority of the nodes in    |
   |                           |         | our cluster partition, so that the more            |
   |                           |         | significant nodes potentially win any fencing      |
   |                           |         | match (especially meaningful in a split-brain of a |
   |                           |         | 2-node cluster). A promoted resource instance      |
   |                           |         | takes the resource's priority plus 1 if the        |
   |                           |         | resource's priority is not 0. Any static or random |
   |                           |         | delays introduced by ``pcmk_delay_base`` and       |
   |                           |         | ``pcmk_delay_max`` configured for the              |
   |                           |         | corresponding fencing resources will be added to   |
   |                           |         | this delay. This delay should be significantly     |
   |                           |         | greater than (safely twice) the maximum delay from |
   |                           |         | those parameters. *(since 2.0.4)*                  |
   +---------------------------+---------+----------------------------------------------------+
   | cluster-delay             | 60s     | .. index::                                         |
   |                           |         |    pair: cluster option; cluster-delay             |
   |                           |         |                                                    |
   |                           |         | Estimated maximum round-trip delay over the        |
   |                           |         | network (excluding action execution). If the DC    |
   |                           |         | requires an action to be executed on another node, |
   |                           |         | it will consider the action failed if it does not  |
   |                           |         | get a response from the other node in this time    |
   |                           |         | (after considering the action's own timeout). The  |
   |                           |         | "correct" value will depend on the speed and load  |
   |                           |         | of your network and cluster nodes.                 |
   +---------------------------+---------+----------------------------------------------------+
   | dc-deadtime               | 20s     | .. index::                                         |
   |                           |         |    pair: cluster option; dc-deadtime               |
   |                           |         |                                                    |
   |                           |         | How long to wait for a response from other nodes   |
   |                           |         | during startup. The "correct" value will depend on |
   |                           |         | the speed/load of your network and the type of     |
   |                           |         | switches used.                                     |
   +---------------------------+---------+----------------------------------------------------+
   | cluster-ipc-limit         | 500     | .. index::                                         |
   |                           |         |    pair: cluster option; cluster-ipc-limit         |
   |                           |         |                                                    |
   |                           |         | The maximum IPC message backlog before one cluster |
   |                           |         | daemon will disconnect another. This is of use in  |
   |                           |         | large clusters, for which a good value is the      |
   |                           |         | number of resources in the cluster multiplied by   |
   |                           |         | the number of nodes. The default of 500 is also    |
   |                           |         | the minimum. Raise this if you see                 |
   |                           |         | "Evicting client" messages for cluster daemon PIDs |
   |                           |         | in the logs.                                       |
   +---------------------------+---------+----------------------------------------------------+
   | pe-error-series-max       | -1      | .. index::                                         |
   |                           |         |    pair: cluster option; pe-error-series-max       |
   |                           |         |                                                    |
   |                           |         | The number of scheduler inputs resulting in errors |
   |                           |         | to save. Used when reporting problems. A value of  |
   |                           |         | -1 means unlimited (report all), and 0 means none. |
   +---------------------------+---------+----------------------------------------------------+
   | pe-warn-series-max        | 5000    | .. index::                                         |
   |                           |         |    pair: cluster option; pe-warn-series-max        |
   |                           |         |                                                    |
   |                           |         | The number of scheduler inputs resulting in        |
   |                           |         | warnings to save. Used when reporting problems. A  |
   |                           |         | value of -1 means unlimited (report all), and 0    |
   |                           |         | means none.                                        |
   +---------------------------+---------+----------------------------------------------------+
   | pe-input-series-max       | 4000    | .. index::                                         |
   |                           |         |    pair: cluster option; pe-input-series-max       |
   |                           |         |                                                    |
   |                           |         | The number of "normal" scheduler inputs to save.   |
   |                           |         | Used when reporting problems. A value of -1 means  |
   |                           |         | unlimited (report all), and 0 means none.          |
   +---------------------------+---------+----------------------------------------------------+
   | enable-acl                | false   | .. index::                                         |
   |                           |         |    pair: cluster option; enable-acl                |
   |                           |         |                                                    |
   |                           |         | Whether :ref:`acl` should be used to authorize     |
   |                           |         | modifications to the CIB                           |
   +---------------------------+---------+----------------------------------------------------+
   | placement-strategy        | default | .. index::                                         |
   |                           |         |    pair: cluster option; placement-strategy        |
   |                           |         |                                                    |
   |                           |         | How the cluster should allocate resources to nodes |
   |                           |         | (see :ref:`utilization`). Allowed values are       |
   |                           |         | ``default``, ``utilization``, ``balanced``, and    |
   |                           |         | ``minimal``.                                       |
   +---------------------------+---------+----------------------------------------------------+
   | node-health-strategy      | none    | .. index::                                         |
   |                           |         |    pair: cluster option; node-health-strategy      |
   |                           |         |                                                    |
   |                           |         | How the cluster should react to node health        |
   |                           |         | attributes (see :ref:`node-health`). Allowed values|
   |                           |         | are ``none``, ``migrate-on-red``, ``only-green``,  |
   |                           |         | ``progressive``, and ``custom``.                   |
   +---------------------------+---------+----------------------------------------------------+
   | node-health-base          | 0       | .. index::                                         |
   |                           |         |    pair: cluster option; node-health-base          |
   |                           |         |                                                    |
   |                           |         | The base health score assigned to a node. Only     |
   |                           |         | used when ``node-health-strategy`` is              |
   |                           |         | ``progressive``.                                   |
   +---------------------------+---------+----------------------------------------------------+
   | node-health-green         | 0       | .. index::                                         |
   |                           |         |    pair: cluster option; node-health-green         |
   |                           |         |                                                    |
   |                           |         | The score to use for a node health attribute whose |
   |                           |         | value is ``green``. Only used when                 |
   |                           |         | ``node-health-strategy`` is ``progressive`` or     |
   |                           |         | ``custom``.                                        |
   +---------------------------+---------+----------------------------------------------------+
   | node-health-yellow        | 0       | .. index::                                         |
   |                           |         |    pair: cluster option; node-health-yellow        |
   |                           |         |                                                    |
   |                           |         | The score to use for a node health attribute whose |
   |                           |         | value is ``yellow``. Only used when                |
   |                           |         | ``node-health-strategy`` is ``progressive`` or     |
   |                           |         | ``custom``.                                        |
   +---------------------------+---------+----------------------------------------------------+
   | node-health-red           | 0       | .. index::                                         |
   |                           |         |    pair: cluster option; node-health-red           |
   |                           |         |                                                    |
   |                           |         | The score to use for a node health attribute whose |
   |                           |         | value is ``red``. Only used when                   |
   |                           |         | ``node-health-strategy`` is ``progressive`` or     |
   |                           |         | ``custom``.                                        |
   +---------------------------+---------+----------------------------------------------------+
   | cluster-recheck-interval  | 15min   | .. index::                                         |
   |                           |         |    pair: cluster option; cluster-recheck-interval  |
   |                           |         |                                                    |
   |                           |         | Pacemaker is primarily event-driven, and looks     |
   |                           |         | ahead to know when to recheck the cluster for      |
   |                           |         | failure timeouts and most time-based rules         |
   |                           |         | *(since 2.0.3)*. However, it will also recheck the |
   |                           |         | cluster after this amount of inactivity. This has  |
   |                           |         | two goals: rules with ``date_spec`` are only       |
   |                           |         | guaranteed to be checked this often, and it also   |
   |                           |         | serves as a fail-safe for some kinds of scheduler  |
   |                           |         | bugs. A value of 0 disables this polling; positive |
   |                           |         | values are a time interval.                        |
   +---------------------------+---------+----------------------------------------------------+
   | shutdown-lock             | false   | .. index::                                         |
   |                           |         |    pair: cluster option; shutdown-lock             |
   |                           |         |                                                    |
   |                           |         | The default of false allows active resources to be |
   |                           |         | recovered elsewhere when their node is cleanly     |
   |                           |         | shut down, which is what the vast majority of      |
   |                           |         | users will want. However, some users prefer to     |
   |                           |         | make resources highly available only for failures, |
   |                           |         | with no recovery for clean shutdowns. If this      |
   |                           |         | option is true, resources active on a node when it |
   |                           |         | is cleanly shut down are kept "locked" to that     |
   |                           |         | node (not allowed to run elsewhere) until they     |
   |                           |         | start again on that node after it rejoins (or for  |
   |                           |         | at most ``shutdown-lock-limit``, if set). Stonith  |
   |                           |         | resources and Pacemaker Remote connections are     |
   |                           |         | never locked. Clone and bundle instances and the   |
   |                           |         | promoted role of promotable clones are currently   |
   |                           |         | never locked, though support could be added in a   |
   |                           |         | future release. Locks may be manually cleared      |
   |                           |         | using the ``--refresh`` option of ``crm_resource`` |
   |                           |         | (both the resource and node must be specified;     |
   |                           |         | this works with remote nodes if their connection   |
   |                           |         | resource's ``target-role`` is set to ``Stopped``,  |
   |                           |         | but not if Pacemaker Remote is stopped on the      |
   |                           |         | remote node without disabling the connection       |
   |                           |         | resource).  *(since 2.0.4)*                        |
   +---------------------------+---------+----------------------------------------------------+
   | shutdown-lock-limit       | 0       | .. index::                                         |
   |                           |         |    pair: cluster option; shutdown-lock-limit       |
   |                           |         |                                                    |
   |                           |         | If ``shutdown-lock`` is true, and this is set to a |
   |                           |         | nonzero time duration, locked resources will be    |
   |                           |         | allowed to start after this much time has passed   |
   |                           |         | since the node shutdown was initiated, even if the |
   |                           |         | node has not rejoined. (This works with remote     |
   |                           |         | nodes only if their connection resource's          |
   |                           |         | ``target-role`` is set to ``Stopped``.)            |
   |                           |         | *(since 2.0.4)*                                    |
   +---------------------------+---------+----------------------------------------------------+
   | remove-after-stop         | false   | .. index::                                         |
   |                           |         |    pair: cluster option; remove-after-stop         |
   |                           |         |                                                    |
   |                           |         | *Deprecated* Should the cluster remove             |
   |                           |         | resources from Pacemaker's executor after they are |
   |                           |         | stopped? Values other than the default are, at     |
   |                           |         | best, poorly tested and potentially dangerous.     |
   |                           |         | This option is deprecated and will be removed in a |
   |                           |         | future release.                                    |
   +---------------------------+---------+----------------------------------------------------+
   | startup-fencing           | true    | .. index::                                         |
   |                           |         |    pair: cluster option; startup-fencing           |
   |                           |         |                                                    |
   |                           |         | *Advanced Use Only:* Should the cluster fence      |
   |                           |         | unseen nodes at start-up? Setting this to false is |
   |                           |         | unsafe, because the unseen nodes could be active   |
   |                           |         | and running resources but unreachable.             |
   +---------------------------+---------+----------------------------------------------------+
   | election-timeout          | 2min    | .. index::                                         |
   |                           |         |    pair: cluster option; election-timeout          |
   |                           |         |                                                    |
   |                           |         | *Advanced Use Only:* If you need to adjust this    |
   |                           |         | value, it probably indicates the presence of a bug.|
   +---------------------------+---------+----------------------------------------------------+
   | shutdown-escalation       | 20min   | .. index::                                         |
   |                           |         |    pair: cluster option; shutdown-escalation       |
   |                           |         |                                                    |
   |                           |         | *Advanced Use Only:* If you need to adjust this    |
   |                           |         | value, it probably indicates the presence of a bug.|
   +---------------------------+---------+----------------------------------------------------+
   | join-integration-timeout  | 3min    | .. index::                                         |
   |                           |         |    pair: cluster option; join-integration-timeout  |
   |                           |         |                                                    |
   |                           |         | *Advanced Use Only:* If you need to adjust this    |
   |                           |         | value, it probably indicates the presence of a bug.|
   +---------------------------+---------+----------------------------------------------------+
   | join-finalization-timeout | 30min   | .. index::                                         |
   |                           |         |    pair: cluster option; join-finalization-timeout |
   |                           |         |                                                    |
   |                           |         | *Advanced Use Only:* If you need to adjust this    |
   |                           |         | value, it probably indicates the presence of a bug.|
   +---------------------------+---------+----------------------------------------------------+
   | transition-delay          | 0s      | .. index::                                         |
   |                           |         |    pair: cluster option; transition-delay          |
   |                           |         |                                                    |
   |                           |         | *Advanced Use Only:* Delay cluster recovery for    |
   |                           |         | the configured interval to allow for additional or |
   |                           |         | related events to occur. This can be useful if     |
   |                           |         | your configuration is sensitive to the order in    |
   |                           |         | which ping updates arrive. Enabling this option    |
   |                           |         | will slow down cluster recovery under all          |
   |                           |         | conditions.                                        |
   +---------------------------+---------+----------------------------------------------------+
