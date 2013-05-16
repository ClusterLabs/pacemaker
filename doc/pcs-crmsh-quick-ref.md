## Display the configuration

    crmsh # crm configure show
    pcs   # pcs cluster cib
    
## Display the current status

    crmsh # crm_mon -1
    pcs   # pcs status

## Node standby

    crmsh # crm node standby
    pcs   # pcs cluster standby pcmk-1

    crmsh # crm node online
    pcs   # pcs cluster unstandby pcmk-1

## Setting configuration options

    crmsh # crm configure property stonith-enabled=false
    pcs   # pcs property set stonith-enabled=false

## Listing available resources

    crmsh # crm ra classes
    pcs   # pcs resource standards

    crmsh # crm ra list ocf pacemaker
    pcs   # pcs resource agents ocf:pacemaker

## Creating a resource

    crmsh # crm configure primitive ClusterIP ocf:heartbeat:IPaddr2 \
            params ip=192.168.122.120 cidr_netmask=32 \
            op monitor interval=30s 
    pcs   # pcs resource create ClusterIP IPaddr2 ip=192.168.0.120 cidr_netmask=32

The standard and provider (`ocf:heartbeat`) are determined automatically since `IPaddr2` is unique.
The monitor operation is automatically created based on the agent's metadata.

## Start a resource
    crmsh # crm resource start ClusterIP
    pcs   # pcs resource start ClusterIP

## Stop a resource

    crmsh # crm resource stop ClusterIP
    pcs   # pcs resource stop ClusterIP

## Remove a resource

    crmsh # crm configure delete ClusterIP
    pcs   # 

## Update a resource
    crmsh # crm configure edit ClusterIP
    pcs   # pcs resource update ClusterIP clusterip_hash=sourceip

## Display a resource

    crmsh # 
    pcs   # pcs resource show WebFS

## Resource defaults

    crmsh # crm configure rsc_defaults resource-stickiness=100
    pcs   # pcs rsc defaults resource-stickiness=100
    
Listing the current defaults:
    
    pcs   # pcs rsc defaults
    
## Operation defaults

    crmsh # crm configure op_defaults timeout=240s
    pcs   # pcs resource op defaults timeout=240s

Listing the current defaults:
    pcs   #  pcs resource op defaults

## Colocation

    crmsh # crm configure colocation website-with-ip INFINITY: WebSite ClusterIP
    pcs   # pcs constraint colocation add WebSite ClusterIP INFINITY

With roles

    crmsh #
    pcs   # 

## Start/stop ordering

    crmsh # crm configure order apache-after-ip mandatory: ClusterIP WebSite
    pcs   # pcs constraint order ClusterIP then WebSite

With roles:

    crmsh #
    pcs   # 

## Preferred locations

    crmsh # crm configure location prefer-pcmk-1 WebSite 50: pcmk-1
    pcs   # pcs constraint location WebSite prefers pcmk-1=50
    
With roles:

    crmsh #
    pcs   # 

## Moving resources

    crmsh # crm resource move WebSite pcmk-1
    pcs   # pcs constraint location WebSite prefers pcmk-1=INFINITY
    
    crmsh # crm resource unmove WebSite
    pcs   # pcs constraint rm location-WebSite-pcmk-1-INFINITY
    
## Creating a clone

    crmsh # configure clone WebIP ClusterIP meta globally-unique="true" clone-max="2" clone-node-max="2"
    pcs   # pcs resource clone ClusterIP globally-unique=true clone-max=2 clone-node-max=2

## Creating a master/slave clone

    crmsh # crm configure ms WebDataClone WebData \
            meta master-max=1 master-node-max=1 \
            clone-max=2 clone-node-max=1 notify=true
    pcs   # resource master WebDataClone WebData \
            master-max=1 master-node-max=1 clone-max=2 clone-node-max=1 \
            notify=true

## ...
    crmsh #
    pcs   # 

    crmsh #
    pcs   # 


## Batch changes

    crmsh # crm
    crmsh # cib new drbd_cfg
    crmsh # configure primitive WebData ocf:linbit:drbd params drbd_resource=wwwdata \
            op monitor interval=60s
    crmsh # configure ms WebDataClone WebData meta master-max=1 master-node-max=1 \
            clone-max=2 clone-node-max=1 notify=true
    crmsh # cib commit drbd_cfg
    crmsh # quit


    pcs   # pcs cluster cib drbd_cfg
    pcs   # pcs -f drbd_cfg resource create WebData ocf:linbit:drbd drbd_resource=wwwdata \
            op monitor interval=60s
    pcs   # pcs -f drbd_cfg resource master WebDataClone WebData master-max=1 master-node-max=1 \
            clone-max=2 clone-node-max=1 notify=true
    pcs   # pcs cluster push cib drbd_cfg
