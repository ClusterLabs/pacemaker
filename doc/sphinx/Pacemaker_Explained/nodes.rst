Cluster Nodes
-------------

.. Convert_to_RST:
   
   == Defining a Cluster Node ==
   
   Each node in the cluster will have an entry in the nodes section
   containing its UUID, uname, and type.
   
   .Example Corosync cluster node entry
   ======
   [source,XML]
   <node id="101" uname="pcmk-1"/>
   ======
   
   In normal circumstances, the admin should let the cluster populate
   this information automatically from the communications and membership
   data.
   
.. _node_name:

Where Pacemaker Gets the Node Name
##################################
   
.. Convert_to_RST_2:
   
   Traditionally, Pacemaker required nodes to be referred to by the value
   returned by `uname -n`.  This can be problematic for services that
   require the `uname -n` to be a specific value (e.g. for a licence
   file).
   
   This requirement has been relaxed for clusters using Corosync 2.0 or later.
   The name Pacemaker uses is:
   
   . The value stored in +corosync.conf+ under *ring0_addr* in the *nodelist*, if it does not contain an IP address; otherwise
   . The value stored in +corosync.conf+ under *name* in the *nodelist*; otherwise
   . The value of `uname -n`
   
   Pacemaker provides the `crm_node -n` command which displays the name
   used by a running cluster.
   
   If a Corosync *nodelist* is used, `crm_node --name-for-id` pass:[<replaceable>number</replaceable>] is also
   available to display the name used by the node with the corosync
   *nodeid* of pass:[<replaceable>number</replaceable>], for example: `crm_node --name-for-id 2`.
   
.. _node_attributes:

Node Attributes
###############
   
.. Convert_to_RST_3:

   indexterm:[Node,attribute]
   Pacemaker allows node-specific values to be specified using 'node attributes'.
   A node attribute has a name, and may have a distinct value for each node.
   
   While certain node attributes have specific meanings to the cluster, they are
   mainly intended to allow administrators and resource agents to track any
   information desired.
   
   For example, an administrator might choose to define node attributes for how
   much RAM and disk space each node has, which OS each uses, or which server room
   rack each node is in.
   
   Users can configure <<ch-rules,rules>> that use node attributes to affect
   where resources are placed.
   
   === Setting and querying node attributes ===
   
   Node attributes can be set and queried using the `crm_attribute` and
   `attrd_updater` commands, so that the user does not have to deal with XML
   configuration directly.
   
   Here is an example of what XML configuration would be generated if an
   administrator ran this command:
         
   .Result of using crm_attribute to specify which kernel pcmk-1 is running
   ======
   -------
   # crm_attribute --type nodes --node pcmk-1 --name kernel --update $(uname -r)
   -------
   [source,XML]
   -------
   <node id="1" uname="pcmk-1">
      <instance_attributes id="nodes-1-attributes">
        <nvpair id="nodes-1-kernel" name="kernel" value="3.10.0-862.14.4.el7.x86_64"/>
      </instance_attributes>
   </node>
   -------
   ======
   
   To read back the value that was just set:
   ----
   # crm_attribute --type nodes --node pcmk-1 --name kernel --query
   scope=nodes  name=kernel value=3.10.0-862.14.4.el7.x86_64
   ----
   
   By specifying `--type nodes` the admin tells the cluster that this
   attribute is persistent across reboots. There are also transient attributes
   which are kept in the status section and are "forgotten" whenever the node
   leaves the cluster. Administrators can use this section by specifying
   `--type status`.
   
   === Special node attributes ===
   
   Certain node attributes have special meaning to the cluster.
   
   Node attribute names beginning with # are considered reserved for these
   special attributes. Some special attributes do not start with #, for
   historical reasons.
   
   Certain special attributes are set automatically by the cluster, should never
   be modified directly, and can be used only within <<ch-rules,rules>>;
   these are listed under <<node-attribute-expressions>>.
   
   For true/false values, the cluster considers a value of "1", "y", "yes", "on",
   or "true" (case-insensitively) to be true, "0", "n", "no", "off", "false", or
   unset to be false, and anything else to be an error.
   
   .Node attributes with special significance
   [width="95%",cols="2m,<5",options="header",align="center"]
   |====
   |Name |Description
   
   | fail-count-*
   | Attributes whose names start with +fail-count-+ are managed by the cluster
     to track how many times particular resource operations have failed on this
     node. These should be queried and cleared via the `crm_failcount` or
     `crm_resource --cleanup` commands rather than directly.
   indexterm:[Node,attribute,fail-count-]
   indexterm:[fail-count-,Node attribute]
   
   | last-failure-*
   | Attributes whose names start with +last-failure-+ are managed by the cluster
     to track when particular resource operations have most recently failed on
     this node. These should be cleared via the `crm_failcount` or
     `crm_resource --cleanup` commands rather than directly.
   indexterm:[Node,attribute,last-failure-]
   indexterm:[last-failure-,Node attribute]
   
   | maintenance
   | Similar to the +maintenance-mode+ <<s-cluster-options,cluster option>>, but for
     a single node. If true, resources will not be started or stopped on the node,
     resources and individual clone instances running on the node will become
     unmanaged, and any recurring operations for those will be cancelled.
   indexterm:[Node,attribute,maintenance]
   indexterm:[maintenance,Node attribute]
   
   | probe_complete
   | This is managed by the cluster to detect when nodes need to be reprobed, and
     should never be used directly.
   indexterm:[Node,attribute,probe_complete]
   indexterm:[probe_complete,Node attribute]
   
   | resource-discovery-enabled
   | If the node is a remote node, fencing is enabled, and this attribute is
     explicitly set to false (unset means true in this case), resource discovery
     (probes) will not be done on this node. This is highly discouraged; the
     +resource-discovery+ location constraint property is preferred for this
     purpose.
   indexterm:[Node,attribute,resource-discovery-enabled]
   indexterm:[resource-discovery-enabled,Node attribute]
   
   | shutdown
   | This is managed by the cluster to orchestrate the shutdown of a node,
     and should never be used directly.
   indexterm:[Node,attribute,shutdown]
   indexterm:[shutdown,Node attribute]
   
   | site-name
   | If set, this will be used as the value of the +#site-name+ node attribute
     used in rules. (If not set, the value of the +cluster-name+ cluster option
     will be used as +#site-name+ instead.)
   indexterm:[Node,attribute,site-name]
   indexterm:[site-name,Node attribute]
   
   | standby
   | If true, the node is in standby mode. This is typically set and queried via
     the `crm_standby` command rather than directly.
   indexterm:[Node,attribute,standby]
   indexterm:[standby,Node attribute]
   
   | terminate
   | If the value is true or begins with any nonzero number, the node will be
     fenced. This is typically set by tools rather than directly.
   indexterm:[Node,attribute,terminate]
   indexterm:[terminate,Node attribute]
   
   | #digests-*
   | Attributes whose names start with +#digests-+ are managed by the cluster to
     detect when <<s-unfencing,unfencing>> needs to be redone, and should never be
     used directly.
   indexterm:[Node,attribute,#digests-]
   indexterm:[#digests-,Node attribute]
   
   | #node-unfenced
   | When the node was last unfenced (as seconds since the epoch). This is managed
     by the cluster and should never be used directly.
   indexterm:[Node,attribute,#node-unfenced]
   indexterm:[#node-unfenced,Node attribute]
   
   |====
   
   [WARNING]
   ====
   Restarting pacemaker on a node that is in single-node maintenance mode will
   likely lead to undesirable effects. If +maintenance+ is set as a transient
   attribute, it will be erased when pacemaker is stopped, which will immediately
   take the node out of maintenance mode and likely get it fenced. Even if
   permanent, if pacemaker is restarted, any resources active on the node will
   have their local history erased when the node rejoins, so the cluster will no
   longer consider them running on the node and thus will consider them managed
   again, leading them to be started elsewhere. This behavior might be improved
   in a future release.
   ====
