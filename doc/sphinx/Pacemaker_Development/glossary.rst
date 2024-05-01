.. index::
   single: glossary

.. _glossary:

Glossary
--------

.. glossary::

    assign
      In the scheduler, this refers to associating a resource with a node. Do
      not use *allocate* for this purpose.

    bundle
      The collective resource type associating instances of a container with
      storage and networking. Do not use :term:`container` when referring to
      the bundle as a whole.

    cluster layer
      The layer of the :term:`cluster stack` that provides membership and
      messaging capabilities (such as Corosync).

    cluster stack
      The core components of a high-availability cluster: the
      :term:`cluster layer` at the "bottom" of the stack, then Pacemaker, then
      resource agents, and then the actual services managed by the cluster at
      the "top" of the stack. Do not use *stack* for the cluster layer alone.

    CPG
      Corosync Process Group. This is the messaging layer in a Corosync-based
      cluster. Pacemaker daemons use CPG to communicate with their counterparts
      on other nodes.

    container
      This can mean either a container in the usual sense (whether as a
      standalone resource or as part of a bundle), or as the container resource
      meta-attribute (which does not necessarily reference a container in the
      usual sense).

    dangling migration
      Live migration of a resource consists of a **migrate_to** action on the
      source node, followed by a **migrate_from** on the target node, followed
      by a **stop** on the source node. If the **migrate_to** and
      **migrate_from** have completed successfully, but the **stop** has not
      yet been done, the migration is considered to be *dangling*.

    dependent
      In colocation constraints, this refers to the resource located relative
      to the :term:`primary` resource. Do not use *rh* or *right-hand* for this
      purpose.

    IPC
      Inter-process communication. In Pacemaker, clients send requests to
      daemons using libqb IPC.

    message
      This can refer to log messages, custom messages defined for a
      **pcmk_output_t** object, or XML messages sent via :term:`CPG` or
      :term:`IPC`.

    metadata
      In the context of options and resource agents, this refers to OCF-style
      metadata. Do not use a hyphen except when referring to the OCF-defined
      action name *meta-data*.

    primary
      In colocation constraints, this refers to the resource that the
      :term:`dependent` resource is located relative to. Do not use *lh* or
      *left-hand* for this purpose.

    primitive
      The fundamental resource type in Pacemaker. Do not use *native* for this
      purpose.

    score
      An integer value constrained between **-PCMK_SCORE_INFINITY** and
      **+PCMK_SCORE_INFINITY**. Certain strings (such as
      **PCMK_VALUE_INFINITY**) parse as particular score values. Do not use
      *weight* for this purpose.

    self-fencing
      When a node is chosen to execute its own fencing. Do not use *suicide*
      for this purpose.
