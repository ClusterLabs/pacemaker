<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
<!-- *generated with [DocToc](http://doctoc.herokuapp.com/)* -->
**Table of Contents** 

- [General Operations](#general-operations)
	- [Display the configuration](#display-the-configuration)
	- [Display the current status](#display-the-current-status)
	- [Node standby](#node-standby)
	- [Set cluster property](#set-cluster-property)
- [Resource manipulation](#resource-manipulation)
	- [List Resource Agent (RA) classes](#list-resource-agent-ra-classes)
	- [List available RAs](#list-available-ras)
	- [List RA info](#list-ra-info)
	- [Create a resource](#create-a-resource)
	- [Display a resource](#display-a-resource)
	- [Display fencing resources](#display-fencing-resources)
	- [Display Stonith RA info](#display-stonith-ra-info)
	- [Start a resource](#start-a-resource)
	- [Stop a resource](#stop-a-resource)
	- [Remove a resource](#remove-a-resource)
	- [Modify a resource](#modify-a-resource)
	- [List the current resource defaults](#list-the-current-resource-defaults)
	- [Set resource defaults](#set-resource-defaults)
	- [List the current operation defaults](#list-the-current-operation-defaults)
	- [Set operation defaults](#set-operation-defaults)
	- [Set Colocation](#set-colocation)
	- [Set ordering](#set-ordering)
	- [Set preferred location](#set-preferred-location)
	- [Move resources](#move-resources)
	- [Create a clone](#create-a-clone)
	- [Create a master/slave clone](#create-a-masterslave-clone)
- [Other operations](#other-operations)
	- [Batch changes](#batch-changes)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

# General Operations

## Display the configuration

    crmsh # crm configure show xml
    pcs   # pcs cluster cib

crmsh can show a simplified (non-xml) syntax as well

    crmsh # crm configure show
    
## Display the current status

    crmsh # crm status
    pcs   # pcs status

also

    # crm_mon -1

## Node standby

Put node in standby

    crmsh # crm node standby pcmk-1
    pcs   # pcs cluster standby pcmk-1

Remove node from standby

    crmsh # crm node online pcmk-1
    pcs   # pcs cluster unstandby pcmk-1

crm has the ability to set the status on reboot or forever. 
pcs can apply the change to all the nodes.

## Set cluster property

    crmsh # crm configure property stonith-enabled=false
    pcs   # pcs property set stonith-enabled=false

# Resource manipulation

## List Resource Agent (RA) classes

    crmsh # crm ra classes
    pcs   # pcs resource standards

## List available RAs

    crmsh # crm ra list ocf
    crmsh # crm ra list lsb
    crmsh # crm ra list service
    crmsh # crm ra list stonith
    pcs   # pcs resource agents ocf
    pcs   # pcs resource agents lsb
    pcs   # pcs resource agents service
    pcs   # pcs resource agents stonith
    pcs   # pcs resource agents

You can also filter by provider

    crmsh # crm ra list ocf pacemaker
    pcs   # pcs resource agents ocf:pacemaker

## List RA info

    crmsh # crm ra meta IPaddr2
    pcs   # pcs resource describe IPaddr2

Use any RA name (like IPaddr2) from the list displayed with the previous command
You can also use the full class:provider:RA format if multiple RAs with the same name are available :

    crmsh # crm ra meta ocf:heartbeat:IPaddr2
    pcs   # pcs resource describe ocf:heartbeat:IPaddr2

## Create a resource

    crmsh # crm configure primitive ClusterIP ocf:heartbeat:IPaddr2 \
            params ip=192.168.122.120 cidr_netmask=32 \
            op monitor interval=30s 
    pcs   # pcs resource create ClusterIP IPaddr2 ip=192.168.0.120 cidr_netmask=32

The standard and provider (`ocf:heartbeat`) are determined automatically since `IPaddr2` is unique.
The monitor operation is automatically created based on the agent's metadata.

## Display a resource

    crmsh # crm configure show
    pcs   # pcs resource show

crmsh also displays fencing resources. 
The result can be filtered by supplying a resource name (IE `ClusterIP`):

    crmsh # crm configure show ClusterIP
    pcs   # pcs resource show ClusterIP

crmsh also displays fencing resources. 

## Display fencing resources

    crmsh # crm resource show
    pcs   # pcs stonith show

pcs treats STONITH devices separately.

## Display Stonith RA info

    crmsh # crm ra meta stonith:fence_ipmilan
    pcs   # pcs stonith describe fence_ipmilan

## Start a resource

    crmsh # crm resource start ClusterIP
    pcs   # pcs resource enable ClusterIP

## Stop a resource

    crmsh # crm resource stop ClusterIP
    pcs   # pcs resource disable ClusterIP

## Remove a resource

    crmsh # crm configure delete ClusterIP
    pcs   # pcs resource delete ClusterIP

## Modify a resource

    crmsh # crm resource param ClusterIP set clusterip_hash=sourceip
    pcs   # pcs resource update ClusterIP clusterip_hash=sourceip

## Delete parameters for a given resource

    crmsh # crm resource param ClusterIP delete nic
    pcs   # pcs resource update ClusterIP ip=192.168.0.98 nic=  

## List the current resource defaults

    crmsh # crm configure show type:rsc_defaults
    pcs   # pcs resource rsc defaults

## Set resource defaults

    crmsh # crm configure rsc_defaults resource-stickiness=100
    pcs   # pcs resource rsc defaults resource-stickiness=100
    
## List the current operation defaults

    crmsh # crm configure show type:op_defaults
    pcs   # pcs resource op defaults

## Set operation defaults

    crmsh # crm configure op_defaults timeout=240s
    pcs   # pcs resource op defaults timeout=240s

## Set Colocation

    crmsh # crm configure colocation website-with-ip INFINITY: WebSite ClusterIP
    pcs   # pcs constraint colocation add ClusterIP with WebSite INFINITY

With roles

    crmsh # crm configure colocation website-with-another-ip inf: WebSite:Master AnotherIP
    pcs   # pcs constraint colocation add Started AnotherIP with Master WebSite INFINITY

## Set ordering

    crmsh # crm configure order apache-after-ip mandatory: ClusterIP WebSite
    pcs   # pcs constraint order ClusterIP then WebSite

With roles:

    crmsh # crm configure order ip-after-website Mandatory: WebSite:Master AnotherIP
    pcs   # pcs constraint order promote WebSite then start AnotherIP

## Set preferred location

    crmsh # crm configure location prefer-pcmk-1 WebSite 50: pcmk-1
    pcs   # pcs constraint location WebSite prefers pcmk-1=50
    
With roles:

    crmsh # crm configure location prefer-pcmk-1 WebSite rule role=Master 50: \#uname eq pcmk-1
    pcs   # pcs constraint location WebSite rule role=master 50 \#uname eq pcmk-1

## Move resources

    crmsh # crm resource move WebSite pcmk-1
    pcs   # pcs resource move WebSite pcmk-1
    
    crmsh # crm resource unmove WebSite
    pcs   # pcs resource unmove WebSite

Remember that moving a resource set a stickyness to -INF until unmoved    

## Create a clone

    crmsh # crm configure clone WebIP ClusterIP meta globally-unique=true clone-max=2 clone-node-max=2
    pcs   # pcs resource clone ClusterIP globally-unique=true clone-max=2 clone-node-max=2

## Create a master/slave clone

    crmsh # crm configure ms WebDataClone WebData \
            meta master-max=1 master-node-max=1 \
            clone-max=2 clone-node-max=1 notify=true
    pcs   # resource master WebDataClone WebData \
            master-max=1 master-node-max=1 clone-max=2 clone-node-max=1 \
            notify=true

# Other operations

## Batch changes

    crmsh # crm
    crmsh # cib new drbd_cfg
    crmsh # configure primitive WebData ocf:linbit:drbd params drbd_resource=wwwdata \
            op monitor interval=60s
    crmsh # configure ms WebDataClone WebData meta master-max=1 master-node-max=1 \
            clone-max=2 clone-node-max=1 notify=true
    crmsh # cib commit drbd_cfg
    crmsh # quit
.

    pcs   # pcs cluster cib drbd_cfg
    pcs   # pcs -f drbd_cfg resource create WebData ocf:linbit:drbd drbd_resource=wwwdata \
            op monitor interval=60s
    pcs   # pcs -f drbd_cfg resource master WebDataClone WebData master-max=1 master-node-max=1 \
            clone-max=2 clone-node-max=1 notify=true
    pcs   # pcs cluster push cib drbd_cfg
