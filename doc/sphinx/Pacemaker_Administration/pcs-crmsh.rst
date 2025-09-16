Quick Comparison of pcs and crm shell
-------------------------------------

``pcs`` and ``crm shell`` are two popular higher-level command-line interfaces
to Pacemaker. Each has its own syntax; this chapter gives a quick comparion of
how to accomplish the same tasks using either one. Some examples also show the
equivalent command using low-level Pacemaker command-line tools.

These examples show the simplest syntax; see the respective man pages for all
possible options.

Show Cluster Configuration and Status
#####################################

.. topic:: Show Configuration (Raw XML)

   .. code-block:: none

      crmsh     # crm configure show xml
      pcs       # pcs cluster cib
      pacemaker # cibadmin -Q

.. topic:: Show Configuration (Human-friendly)

   .. code-block:: none

      crmsh # crm configure show
      pcs   # pcs config

.. topic:: Show Cluster Status

   .. code-block:: none

      crmsh     # crm status
      pcs       # pcs status
      pacemaker # crm_mon -1

Manage Nodes
############

.. topic:: Put node "pcmk-1" in standby mode

   .. code-block:: none

      crmsh     # crm node standby pcmk-1
      pcs-0.9   # pcs cluster standby pcmk-1
      pcs-0.10  # pcs node standby pcmk-1
      pacemaker # crm_standby -N pcmk-1 -v on

.. topic:: Remove node "pcmk-1" from standby mode

   .. code-block:: none

      crmsh     # crm node online pcmk-1
      pcs-0.9   # pcs cluster unstandby pcmk-1
      pcs-0.10  # pcs node unstandby pcmk-1
      pacemaker # crm_standby -N pcmk-1 -v off

Manage Cluster Properties
#########################

.. topic:: Set the "fencing-enabled" cluster property to "false"

   .. code-block:: none

      crmsh     # crm configure property fencing-enabled=false
      pcs       # pcs property set fencing-enabled=false
      pacemaker # crm_attribute -n fencing-enabled -v false

Show Resource Agent Information
###############################

.. topic:: List Resource Agent (RA) Classes

   .. code-block:: none

      crmsh    # crm ra classes
      pcs      # pcs resource standards
      pacmaker # crm_resource --list-standards

.. topic:: List Available Resource Agents (RAs) by Standard

   .. code-block:: none

      crmsh     # crm ra list ocf
      pcs       # pcs resource agents ocf
      pacemaker # crm_resource --list-agents ocf

.. topic:: List Available Resource Agents (RAs) by OCF Provider

   .. code-block:: none

      crmsh     # crm ra list ocf pacemaker
      pcs       # pcs resource agents ocf:pacemaker
      pacemaker # crm_resource --list-agents ocf:pacemaker

.. topic:: List Available Resource Agent Parameters

   .. code-block:: none

      crmsh     # crm ra info IPaddr2
      pcs       # pcs resource describe IPaddr2
      pacemaker # crm_resource --show-metadata ocf:heartbeat:IPaddr2

You can also use the full ``class:provider:type`` format with crmsh and pcs if
multiple RAs with the same name are available.

.. topic:: Show Available Fence Agent Parameters

   .. code-block:: none

      crmsh # crm ra info stonith:fence_ipmilan
      pcs   # pcs stonith describe fence_ipmilan

Manage Resources
################

.. topic:: Create a Resource

   .. code-block:: none

      crmsh # crm configure primitive ClusterIP IPaddr2 params ip=192.168.122.120 cidr_netmask=24
      pcs   # pcs resource create ClusterIP IPaddr2 ip=192.168.122.120 cidr_netmask=24

Both crmsh and pcs determine the standard and provider (``ocf:heartbeat``) automatically
since ``IPaddr2`` is unique, and automatically create operations (including
monitor) based on the agent's meta-data.

.. topic:: Show Configuration of All Resources

   .. code-block:: none

      crmsh    # crm configure show
      pcs-0.9  # pcs resource show --full
      pcs-0.10 # pcs resource config

.. topic:: Show Configuration of One Resource

   .. code-block:: none

      crmsh    # crm configure show ClusterIP
      pcs-0.9  # pcs resource show ClusterIP
      pcs-0.10 # pcs resource config ClusterIP

.. topic:: Show Configuration of Fencing Resources

   .. code-block:: none

      crmsh    # crm resource status
      pcs-0.9  # pcs stonith show --full
      pcs-0.10 # pcs stonith config

.. topic:: Start a Resource

   .. code-block:: none

      crmsh     # crm resource start ClusterIP
      pcs       # pcs resource enable ClusterIP
      pacemaker # crm_resource -r ClusterIP --set-parameter target-role --meta -v Started

.. topic:: Stop a Resource

   .. code-block:: none

      crmsh     # crm resource stop ClusterIP
      pcs       # pcs resource disable ClusterIP
      pacemaker # crm_resource -r ClusterIP --set-parameter target-role --meta -v Stopped

.. topic:: Remove a Resource

   .. code-block:: none

      crmsh # crm configure delete ClusterIP
      pcs   # pcs resource delete ClusterIP

.. topic:: Modify a Resource's Instance Parameters

   .. code-block:: none

      crmsh     # crm resource param ClusterIP set clusterip_hash=sourceip
      pcs       # pcs resource update ClusterIP clusterip_hash=sourceip
      pacemaker # crm_resource -r ClusterIP --set-parameter clusterip_hash -v sourceip

crmsh also has an `edit` command which edits the simplified CIB syntax
(same commands as the command line) via a configurable text editor.

.. topic:: Modify a Resource's Instance Parameters Interactively

   .. code-block:: none

      crmsh # crm configure edit ClusterIP

Using the interactive shell mode of crmsh, multiple changes can be
edited and verified before committing to the live configuration:

.. topic:: Make Multiple Configuration Changes Interactively

   .. code-block:: none

      crmsh # crm configure
      crmsh # edit
      crmsh # verify
      crmsh # commit

.. topic:: Delete a Resource's Instance Parameters

   .. code-block:: none

      crmsh     # crm resource param ClusterIP delete nic
      pcs       # pcs resource update ClusterIP nic=  
      pacemaker # crm_resource -r ClusterIP --delete-parameter nic

.. topic:: List Current Resource Defaults

   .. code-block:: none

      crmsh     # crm configure show type:rsc_defaults
      pcs       # pcs resource defaults
      pacemaker # cibadmin -Q --scope rsc_defaults

.. topic:: Set Resource Defaults

   .. code-block:: none

      crmsh # crm configure rsc_defaults resource-stickiness=100
      pcs   # pcs resource defaults resource-stickiness=100

.. topic:: List Current Operation Defaults

   .. code-block:: none

      crmsh     # crm configure show type:op_defaults
      pcs       # pcs resource op defaults
      pacemaker # cibadmin -Q --scope op_defaults

.. topic:: Set Operation Defaults

   .. code-block:: none

      crmsh # crm configure op_defaults timeout=240s
      pcs   # pcs resource op defaults timeout=240s

.. topic:: Enable Resource Agent Tracing for a Resource

   .. code-block:: none

      crmsh # crm resource trace Website

.. topic:: Clear Fail Counts for a Resource

   .. code-block:: none

      crmsh     # crm resource cleanup Website
      pcs       # pcs resource cleanup Website
      pacemaker # crm_resource --cleanup -r Website

.. topic:: Create a Clone Resource

   .. code-block:: none

      crmsh # crm configure clone WebIP ClusterIP meta globally-unique=true clone-max=2 clone-node-max=2
      pcs   # pcs resource clone ClusterIP globally-unique=true clone-max=2 clone-node-max=2

.. topic:: Create a Promotable Clone Resource

   .. code-block:: none

      crmsh    # crm configure ms WebDataClone WebData \
                 meta master-max=1 master-node-max=1 \
                 clone-max=2 clone-node-max=1 notify=true
      crmsh    # crm configure clone WebDataClone WebData \
                 meta promotable=true \
                 promoted-max=1 promoted-node-max=1 \
                 clone-max=2 clone-node-max=1 notify=true
      pcs-0.9  # pcs resource master WebDataClone WebData \
                 master-max=1 master-node-max=1 \
                 clone-max=2 clone-node-max=1 notify=true
      pcs-0.10 # pcs resource promotable WebData WebDataClone \
                 promoted-max=1 promoted-node-max=1 \
                 clone-max=2 clone-node-max=1 notify=true

crmsh supports both ways ('configure ms' is deprecated) to configure promotable clone since crmsh 4.4.0.
pcs will generate the clone name automatically if it is omitted from the
command line.


Manage Constraints
##################

.. topic:: Create a Colocation Constraint

   .. code-block:: none

      crmsh # crm configure colocation website-with-ip INFINITY: WebSite ClusterIP
      pcs   # pcs constraint colocation add ClusterIP with WebSite INFINITY

.. topic:: Create a Colocation Constraint Based on Role

   .. code-block:: none

      crmsh # crm configure colocation another-ip-with-website inf: AnotherIP WebSite:Master
      pcs   # pcs constraint colocation add Started AnotherIP with Promoted WebSite INFINITY

.. topic:: Create an Ordering Constraint

   .. code-block:: none

      crmsh # crm configure order apache-after-ip mandatory: ClusterIP WebSite
      pcs   # pcs constraint order ClusterIP then WebSite

.. topic:: Create an Ordering Constraint Based on Role

   .. code-block:: none

      crmsh # crm configure order ip-after-website Mandatory: WebSite:Master AnotherIP
      pcs   # pcs constraint order promote WebSite then start AnotherIP

.. topic:: Create a Location Constraint

   .. code-block:: none

      crmsh # crm configure location prefer-pcmk-1 WebSite 50: pcmk-1
      pcs   # pcs constraint location WebSite prefers pcmk-1=50

.. topic:: Create a Location Constraint Based on Role

   .. code-block:: none

      crmsh # crm configure location prefer-pcmk-1 WebSite rule role=Master 50: \#uname eq pcmk-1
      pcs   # pcs constraint location WebSite rule role=Promoted 50 \#uname eq pcmk-1

.. topic:: Move a Resource to a Specific Node (by Creating a Location Constraint)

   .. code-block:: none

      crmsh     # crm resource move WebSite pcmk-1
      pcs       # pcs resource move WebSite pcmk-1
      pacemaker # crm_resource -r WebSite --move -N pcmk-1

.. topic:: Move a Resource Away from Its Current Node (by Creating a Location Constraint)

   .. code-block:: none

      crmsh     # crm resource ban Website pcmk-2
      pcs       # pcs resource ban Website pcmk-2
      pacemaker # crm_resource -r WebSite --move

.. topic:: Remove any Constraints Created by Moving a Resource

   .. code-block:: none

      crmsh     # crm resource unmove WebSite
      pcs       # pcs resource clear WebSite
      pacemaker # crm_resource -r WebSite --clear

Advanced Configuration
######################

Manipulate Configuration Elements by Type
_________________________________________

.. topic:: List Constraints with IDs

   .. code-block:: none

      pcs   # pcs constraint list --full

.. topic:: Remove Constraint by ID

   .. code-block:: none

      pcs   # pcs constraint remove cli-ban-Website-on-pcmk-1
      crmsh # crm configure remove cli-ban-Website-on-pcmk-1

crmsh's `show` and `edit` commands can be used to manage resources and
constraints by type:

.. topic:: Show Configuration Elements

   .. code-block:: none

      crmsh # crm configure show type:primitive
      crmsh # crm configure edit type:colocation

Batch Changes
_____________

.. topic:: Make Multiple Changes and Apply Together

   .. code-block:: none

      crmsh # crm
      crmsh # cib new drbd_cfg
      crmsh # configure primitive WebData ocf:linbit:drbd params drbd_resource=wwwdata \
              op monitor interval=60s
      crmsh # configure ms WebDataClone WebData meta master-max=1 master-node-max=1 \
              clone-max=2 clone-node-max=1 notify=true
      crmsh # cib commit drbd_cfg
      crmsh # quit

      pcs      # pcs cluster cib drbd_cfg
      pcs      # pcs -f drbd_cfg resource create WebData ocf:linbit:drbd drbd_resource=wwwdata \
                 op monitor interval=60s
      pcs-0.9  # pcs -f drbd_cfg resource master WebDataClone WebData \
                 master-max=1 master-node-max=1 clone-max=2 clone-node-max=1 notify=true
      pcs-0.10 # pcs -f drbd_cfg resource promotable WebData WebDataClone \
                 promoted-max=1 promoted-node-max=1 clone-max=2 clone-node-max=1 notify=true
      pcs      # pcs cluster cib-push drbd_cfg

Template Creation
_________________

.. topic:: Create Resource Template Based on Existing Primitives of Same Type

   .. code-block:: none

      crmsh # crm configure assist template ClusterIP AdminIP

Log Analysis
____________

.. topic:: Show Information About Recent Cluster Events

   .. code-block:: none

      crmsh # crm history
      crmsh # peinputs
      crmsh # transition pe-input-10
      crmsh # transition log pe-input-10

Configuration Scripts
_____________________

.. topic:: Script Multiple-step Cluster Configurations

   .. code-block:: none

      crmsh # crm script show apache
      crmsh # crm script run apache \
              id=WebSite \
              install=true \
              virtual-ip:ip=192.168.0.15 \
              database:id=WebData \
              database:install=true
