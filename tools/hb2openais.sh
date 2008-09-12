#!/bin/sh

 # Copyright (C) 2008 Dejan Muhamedagic <dmuhamedagic@suse.de>
 # 
 # This program is free software; you can redistribute it and/or
 # modify it under the terms of the GNU General Public
 # License as published by the Free Software Foundation; either
 # version 2.1 of the License, or (at your option) any later version.
 # 
 # This software is distributed in the hope that it will be useful,
 # but WITHOUT ANY WARRANTY; without even the implied warranty of
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 # General Public License for more details.
 # 
 # You should have received a copy of the GNU General Public
 # License along with this library; if not, write to the Free Software
 # Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 #

. /etc/ha.d/shellfuncs
. $HA_NOARCHBIN/utillib.sh

PROG=`basename $0`
# FIXME: once this is part of the package!
PROGDIR=`dirname $0`
echo "$PROGDIR" | grep -qs '^/' || {
	test -f /usr/sbin/$PROG &&
		PROGDIR=/usr/sbin
	test -f $HA_NOARCHBIN/$PROG &&
		PROGDIR=$HA_NOARCHBIN
}

# the default syslog facility is not (yet) exported by heartbeat
# to shell scripts
#
DEFAULT_HA_LOGFACILITY="daemon"
export DEFAULT_HA_LOGFACILITY
LOGD_CF=`findlogdcf /etc $HA_DIR`
export LOGD_CF
AIS_CONF=/etc/ais/openais.conf
AIS_KEYF=/etc/ais/authkey

CIB=/var/lib/heartbeat/crm/cib.xml
CIBSIG=/var/lib/heartbeat/crm/cib.xml.sig
HOSTCACHE=/var/lib/heartbeat/hostcache
HB_UUID=/var/lib/heartbeat/hb_uuid
DONE_F=/var/run/heartbeat/.$PROG.conv_done
BACKUPDIR=/var/tmp/`basename $PROG .sh`.backup
BACKUP_FILES=" $CIB $CIBSIG $HOSTCACHE $HB_UUID $AIS_CONF "
RM_FILES=" $CIBSIG $HOSTCACHE $HB_UUID "
REMOTE_RM_FILES=" $CIB $CIBSIG $HOSTCACHE $HB_UUID "
DIST_FILES=" $AIS_CONF $AIS_KEYF $DONE_F "
MAN_TARF=/var/tmp/`basename $PROG .sh`.tar.gz

[ `id -un` = dejan ] && MYSUDO=sudo

: ${SSH_OPTS="-T"}

usage() {
	cat<<EOF

usage: $PROG [revert]

EOF
	exit
}

prerequisites() {
	[ -z "$DRY" ] && [ `id -u` != 0 ] &&
		fatal "you have to run me as root"
	test -f $HA_CF || {
		info "no need for conversion: heartbeat was never running"
		exit 0
	}
	grep -w "^crm" $HA_CF | egrep -qs 'respawn|yes' ||
		fatal "crm is not enabled: this program cannot convert legacy configurations"
	$DRY test -f $CIB ||
		fatal "CIB $CIB does not exist: cannot proceed"
}
# some notes about unsupported stuff
unsupported() {
	respawned_progs=`awk '/^respawn/{print $3}' $HA_CF |while read p; do basename $p; done`
	grep -qs "^serial" $HA_CF &&
		warning "serial media is not supported with OpenAIS"
	for prog in $respawned_progs; do
		case $prog in
		pingd|evmsd) : these two are fine
			;;
		*)
			warning "program $prog is being controlled by heartbeat (thru respawn)"
			warning "you have to find another way of running it"
			;;
		esac
	done
}
#
# does ssh work?
#
testsshuser() {
	if [ "$2" ]; then
		ssh -T -o Batchmode=yes $2@$1 true 2>/dev/null
	else
		ssh -T -o Batchmode=yes $1 true 2>/dev/null
	fi
}
findsshuser() {
	for u in "" $TRY_SSH; do
		rc=0
		for n in `getnodes`; do
			[ "$node" = "$WE" ] && continue
			testsshuser $n $u || {
				rc=1
				break
			}
		done
		if [ $rc -eq 0 ]; then
			echo $u
			return 0
		fi
	done
	return 1
}
newportinfo() {
	info "the port number for the multicast is set to 5405"
	info "please update your firewall rules (if any)"
}
changemediainfo() {
	info "openais uses multicast for communication"
	info "please make sure that your network infrastructure supports it"
}
multicastinfo() {
	info "multicast address for openais set to $1"
}
netaddrinfo() {
	info "network address for openais set to $1"
}
backup_files() {
	info "backing up $BACKUP_FILES to $BACKUPDIR"
	$DRY mkdir $BACKUPDIR || {
		echo sorry, could not create $BACKUPDIR directory
		echo please cleanup
		exit 1
	}
	for f in $BACKUP_FILES; do
		$DRY cp -p $f $BACKUPDIR || {
			echo sorry, could not copy $f to $BACKUPDIR
			exit 1
		}
	done
}
revert() {
	test -d $BACKUPDIR || {
		echo sorry, there is no $BACKUPDIR directory
		echo cannot revert
		exit 1
	}
	for f in $BACKUP_FILES; do
		cp -p $BACKUPDIR/`basename $f` $f || {
			echo sorry, could not copy $BACKUPDIR/`basename $f` to $f
		}
	done
}
pls_press_enter() {
	cat<<EOF

Please press enter to continue or ^C to exit ...
EOF
	read junk
	echo ""
}
introduction() {
	cat<<EOF

This is a Heartbeat to OpenAIS conversion tool.

* IMPORTANT * IMPORTANT * IMPORTANT * IMPORTANT * IMPORTANT *

Please read this and don't proceed before understanding what
we try to do and what is required.

1. You need to know your cluster in detail. This program will
inform you on changes it makes. It is up to you to verify
that the changes are meaningful. We will also probably ask
some questions now and again.

2. This procedure is supposed to be run on one node only.
Although the main cluster configuration (the CIB) is
automatically replicated, there are some things which have to
be copied by other means. For that to work, we need sshd
running on all nodes and root access working.

3. Do not run this procedure on more than one node!
EOF
	pls_press_enter
	cat<<EOF
The procedure consists of two parts: the OpenAIS
configuration and the Pacemaker/CRM CIB configuration.

The first part is obligatory. The second part may be skipped
unless your cluster configuration requires changes due to the
change from Heartbeat to OpenAIS.

We will try to analyze your configuration and let you know
whether the CIB configuration should be changed as well.
However, you will still have a choice to skip the CIB
mangling part in case you want to do that yourself.

The next step is to create the OpenAIS configuration. If you
want to leave, now is the time to interrupt the program.
EOF
	pls_press_enter
}
want_to_proceed() {
	while :; do
		printf "Do you want to proceed? (y/n) "
		read ans
		if echo $ans | grep -iqs '^[yn]'; then
			echo $ans | grep -iqs '^y'
			return $?
		else
			echo Please answer with y or n
		fi
	done
}
intro_part2() {
	cat<<EOF

The second part of the configuration deals with the CIB.
According to our analysis (you should have seen some
messages), this step is necessary.
EOF
	want_to_proceed || return
}

gethbmedia() {
	grep "^[bum]cast" $HA_CF
}
pl_ipcalc() {
perl -e '
# stolen from internet!
my $ipaddr=$ARGV[0];
my $nmask=$ARGV[1];
my @addrarr=split(/\./,$ipaddr);
my ( $ipaddress ) = unpack( "N", pack( "C4",@addrarr ) );
my @maskarr=split(/\./,$nmask);
my ( $netmask ) = unpack( "N", pack( "C4",@maskarr ) );
# Calculate network address by logical AND operation of addr &
# netmask
# and convert network address to IP address format
my $netadd = ( $ipaddress & $netmask );
my @netarr=unpack( "C4", pack( "N",$netadd ) );
my $netaddress=join(".",@netarr);
print "$netaddress\n";
' $1 $2
}
get_if_val() {
	test "$1" || return
	awk -v key=$1 '
	{ for( i=1; i<=NF; i++ )
		if( match($i,key) ) {
			sub(key,"",$i);
			print $i
			exit
		}
	}'
}
netaddress() {
	ip=`ifconfig $1 | grep 'inet addr:' | get_if_val addr:`
	mask=`ifconfig $1 | grep 'Mask:' | get_if_val Mask:`
	test "$mask" ||
		fatal "could not get the network mask for interface $1"
	pl_ipcalc $ip $mask
}

sw=0
do_tabs() {
	for i in `seq $sw`; do printf "\t"; done
}
newstanza() {
	do_tabs
	printf "%s {\n" $1
	let sw=sw+1
}
endstanza() {
	let sw=sw-1
	do_tabs
	printf "}\n"
}
setvalue() {
	name=$1
	val=$2
	test "$val" || {
		fatal "sorry, no value set for $name"
	}
	do_tabs
	echo "$name: $val"
}
setdebug() {
	cfdebug=`getcfvar debug` # prefer debuglog if set
	isnumber $cfdebug || cfdebug=""
	[ "$cfdebug" ] && [ $cfdebug -gt 0 ] &&
		echo "on" || echo "off"
}

[ "$1" = "-h" ] && usage

prerequisites

[ "$1" = revert ] && {
	revert
	exit
}

if [ -f "$DONE_F" ]; then
	echo "Conversion to OpenAIS already done, exiting"
	exit 0
fi

introduction

backup_files

WE=`uname -n`  # who am i?
unsupported

# 1. Generate the openais.conf

openaisconf() {

info "Generating $AIS_CONF from $HA_CF ..."

# the totem stanza

cpunum=`grep -c ^processor /proc/cpuinfo`
newstanza totem
setvalue threads $cpunum
setvalue secauth on
setvalue version 2
ring=0
gethbmedia | while read media_type iface address rest
do
	info "Processing interface $iface of type $media_type ..."
	newstanza interface
	setvalue ringnumber $ring
	setvalue bindnetaddr `netaddress $iface`
	netaddrinfo `netaddress $iface`
	setvalue mcastport 5405
	case "$media_type" in
	ucast|bcast)
		setvalue mcastaddr 226.94.1.1
		multicastinfo 226.94.1.1
		newportinfo
		;;
	mcast)
		setvalue mcastaddr $address
		newportinfo
		;;
	esac
	let ring=$ring+1
	endstanza
done
changemediainfo
endstanza

# the logging stanza

getlogvars
# enforce some syslog facility
: ${HA_LOGFACILITY=$DEFAULT_HA_LOGFACILITY}
debugsetting=`setdebug`
newstanza logging
setvalue debug $debugsetting
setvalue fileline off
setvalue to_stderr no
setvalue to_file no
setvalue to_syslog yes
setvalue syslog_facility $HA_LOGFACILITY
endstanza

newstanza amf
setvalue mode disabled
endstanza

newstanza aisexec
setvalue user	root
setvalue group	root
endstanza

newstanza pacemaker
setvalue logfacility $HA_LOGFACILITY
setvalue debug $debugsetting
endstanza
}

if [ -z "$DRY" ]; then
	openaisconf > $AIS_CONF ||
		fatal "cannot create $AIS_CONF"
	grep -wqs interface $AIS_CONF ||
		fatal "no media found in $HA_CF"
else
	openaisconf
fi

info "Generating a key for OpenAIS authentication ..."
$DRY ais-keygen ||
	fatal "cannot generate the key using ais-keygen"

# remove various files which could get in a way

$DRY rm -f $RM_FILES

zap_nodes() {
	$MYSUDO python - <<EOF
import os,sys
import xml.dom.minidom
from tempfile import mkstemp

def load_cib(cibfile):
	file = open(cibfile, 'r')
	doc = xml.dom.minidom.parseString(''.join(file))
	file.close()
	return doc
def is_whitespace(node):
	return node.nodeType == node.TEXT_NODE and not node.data.strip()
def rmnodes(node_list):
	for node in node_list:
		node.parentNode.removeChild(node)
		node.unlink()
def is_element(xmlnode):
	return xmlnode.nodeType == xmlnode.ELEMENT_NODE
def xml_processnodes(xmlnode,filter,proc):
	'''
	Process with proc all nodes that match filter.
	'''
	node_list = []
	for child in xmlnode.childNodes:
		if filter(child):
			node_list.append(child)
		elif child.hasChildNodes():
			xml_processnodes(child,filter,proc)
	if node_list:
		proc(node_list)
def write_tmp(s):
	fd,tmp = mkstemp()
	f = os.fdopen(fd,"w")
	f.write(s)
	f.close()
	return tmp
def skip_first(s):
	l = s.split('\n')
	return '\n'.join(l[1:])

CIB = "$CIB"
doc = load_cib(CIB)
xml_processnodes(doc,is_whitespace,rmnodes)
nodes = doc.getElementsByTagName("nodes")[0]
if not nodes:
	print >> sys.stderr, "ERROR: sorry, no nodes section in the CIB, cannot proceed"
	sys.exit(1)

for c in nodes.childNodes:
	nodes.removeChild(c)

s = skip_first(doc.toprettyxml())
tmp = write_tmp(s)
print tmp
EOF
}

# remove the nodes section from the CIB

tmpfile=`zap_nodes`
$MYSUDO [ -f "$tmpfile" ] ||
	fatal "cannot remove the nodes section from the CIB"
$DRY mv $tmpfile $CIB

info "Done converting ha.cf to openais.conf"
#
# first part done (openais), on to the CIB

analyze_cib() {
	info "Analyze the CIB..."
	$MYSUDO python - <<EOF
import os,sys
import xml.dom.minidom

def load_cib(cibfile):
	file = open(cibfile, 'r')
	doc = xml.dom.minidom.parseString(''.join(file))
	file.close()
	return doc
def get_param(node,p):
	l = node.getElementsByTagName("instance_attributes")
	if not l:
		return ''
	inst_attr = l[0]
	for nvpair in inst_attr.getElementsByTagName("nvpair"):
		if p == nvpair.getAttribute("name"):
			return nvpair.getAttribute("value")
	return ''

CIB = "$CIB"
doc = load_cib(CIB)
rc = 0
for rsc in doc.getElementsByTagName("primitive"):
	rsc_type = rsc.getAttribute("type")
	if rsc_type == "EvmsSCC":
		print >> sys.stderr, "INFO: evms configuration found; conversion required"
		rc = 1
	elif rsc_type == "Filesystem":
		if get_param(rsc,"fstype") == "ocfs2":
			print >> sys.stderr, "INFO: ocfs2 configuration found; conversion required"
			rc = 1
sys.exit(rc)
EOF
}
convert_cib() {
	$MYSUDO python - <<EOF
import os,sys
import xml.dom.minidom
from tempfile import mkstemp

def load_cib(cibfile):
	file = open(cibfile, 'r')
	doc = xml.dom.minidom.parseString(''.join(file))
	file.close()
	return doc
def set_attribute(tag,node,p,value):
	rsc_id = node.getAttribute("id")
	attr_set = node.getElementsByTagName(tag)
	if not attr_set:
		return
	attributes = attr_set[0].getElementsByTagName("attributes")
	if not attributes:
		attributes = doc.createElement("attributes")
		attr_set.appendChild(attributes)
	else:
		attributes = attributes[0]
	for nvp in attributes.getElementsByTagName("nvpair"):
		if p == nvp.getAttribute("name"):
			nvp.setAttribute("value",value)
			return
	attributes.appendChild(nvpair(rsc_id,p,value))
def get_attribute(tag,node,p):
	attr_set = node.getElementsByTagName(tag)
	if not attr_set:
		return ''
	attributes = attr_set[0].getElementsByTagName("attributes")
	if not attributes:
		return ''
	attributes = attributes[0]
	for nvpair in attributes.getElementsByTagName("nvpair"):
		if p == nvpair.getAttribute("name"):
			return nvpair.getAttribute("value")
	return ''
def rm_attribute(tag,node,p):
	attr_set = node.getElementsByTagName(tag)
	if not attr_set:
		return ''
	attributes = attr_set[0].getElementsByTagName("attributes")
	if not attributes:
		return ''
	attributes = attributes[0]
	for nvpair in attributes.getElementsByTagName("nvpair"):
		if p == nvpair.getAttribute("name"):
			nvpair.parentNode.removeChild(nvpair)
def get_param(node,p):
	return get_attribute("instance_attributes",node,p)
def set_param(node,p,value):
	set_attribute("instance_attributes",node,p,value)
def rm_param(node,p):
	rm_attribute("instance_attributes",node,p)
def is_whitespace(node):
	return node.nodeType == node.TEXT_NODE and not node.data.strip()
def rmnodes(node_list):
	for node in node_list:
		node.parentNode.removeChild(node)
		node.unlink()
def is_element(xmlnode):
	return xmlnode.nodeType == xmlnode.ELEMENT_NODE
def xml_processnodes(xmlnode,filter,proc):
	'''
	Process with proc all nodes that match filter.
	'''
	node_list = []
	for child in xmlnode.childNodes:
		if filter(child):
			node_list.append(child)
		elif child.hasChildNodes():
			xml_processnodes(child,filter,proc)
	if node_list:
		proc(node_list)
def write_tmp(s):
	fd,tmp = mkstemp()
	f = os.fdopen(fd,"w")
	f.write(s)
	f.close()
	return tmp
def skip_first(s):
	l = s.split('\n')
	return '\n'.join(l[1:])

def get_input(msg):
	while True:
		ans = raw_input(msg)
		if ans:
			if os.access(ans,os.F_OK):
				return ans
			else:
				print >> sys.stderr, "Cannot read %s" % ans
		print >> sys.stderr, "We do need this input to continue."
def nvpair(id,name,value):
	nvpair = doc.createElement("nvpair")
	nvpair.setAttribute("id",id + "_" + name)
	nvpair.setAttribute("name",name)
	nvpair.setAttribute("value",value)
	return nvpair
def mk_lvm(rsc_id,volgrp):
	node = doc.createElement("primitive")
	node.setAttribute("id",rsc_id)
	node.setAttribute("type","LVM")
	node.setAttribute("provider","heartbeat")
	node.setAttribute("class","ocf")
	operations = doc.createElement("operations")
	node.appendChild(operations)
	mon_op = doc.createElement("op")
	operations.appendChild(mon_op)
	mon_op.setAttribute("id", rsc_id + "_mon")
	mon_op.setAttribute("name","monitor")
	interval = "120s"
	timeout = "60s"
	mon_op.setAttribute("interval", interval)
	mon_op.setAttribute("timeout", timeout)
	instance_attributes = doc.createElement("instance_attributes")
	instance_attributes.setAttribute("id", rsc_id + "_inst_attr")
	node.appendChild(instance_attributes)
	attributes = doc.createElement("attributes")
	instance_attributes.appendChild(attributes)
	attributes.appendChild(nvpair(rsc_id,"volgrpname",volgrp))
	return node
def mk_clone(id,ra_type,ra_class,prov):
	c = doc.createElement("clone")
	c.setAttribute("id",id + "-clone")
	meta = doc.createElement("meta_attributes")
	c.appendChild(meta)
	meta.setAttribute("id",id + "_meta")
	attributes = doc.createElement("attributes")
	meta.appendChild(attributes)
	attributes.appendChild(nvpair(id,"globally-unique","false"))
	attributes.appendChild(nvpair(id,"interleave","true"))
	p = doc.createElement("primitive")
	c.appendChild(p)
	p.setAttribute("id",id)
	p.setAttribute("type",ra_type)
	if prov:
		p.setAttribute("provider",prov)
	p.setAttribute("class",ra_class)
	operations = doc.createElement("operations")
	p.appendChild(operations)
	mon_op = doc.createElement("op")
	operations.appendChild(mon_op)
	mon_op.setAttribute("id", id + "_mon")
	mon_op.setAttribute("name","monitor")
	interval = "60s"
	timeout = "30s"
	mon_op.setAttribute("interval", interval)
	mon_op.setAttribute("timeout", timeout)
	return c
def add_ocfs_clones(id):
	c1 = mk_clone(id+"-o2cb","o2cb","lsb","")
	c2 = mk_clone(id+"-dlm","controld","ocf","pacemaker")
	resources.appendChild(c1)
	resources.appendChild(c2)
def mk_order(r1,r2):
	rsc_order = doc.createElement("rsc_order")
	rsc_order.setAttribute("id","rsc_order_"+r1+"_"+r2)
	rsc_order.setAttribute("from",r1)
	rsc_order.setAttribute("to",r2)
	rsc_order.setAttribute("type","before")
	rsc_order.setAttribute("symmetrical","true")
	return rsc_order
def mk_colocation(r1,r2):
	rsc_colocation = doc.createElement("rsc_colocation")
	rsc_colocation.setAttribute("id","rsc_colocation_"+r1+"_"+r2)
	rsc_colocation.setAttribute("from",r1)
	rsc_colocation.setAttribute("to",r2)
	rsc_colocation.setAttribute("score","INFINITY")
	return rsc_colocation
def add_ocfs_constraints(rsc,id):
	node = rsc.parentNode
	if node.tagName != "clone":
		node = rsc
	clone_id = node.getAttribute("id")
	c1 = mk_order(id+"-o2cb-clone",clone_id)
	c2 = mk_colocation(id+"-o2cb-clone",clone_id)
	constraints.appendChild(c1)
	constraints.appendChild(c2)
	c1 = mk_order(id+"-dlm-clone",id+"-o2cb-clone")
	c2 = mk_colocation(id+"-dlm-clone",id+"-o2cb-clone")
	constraints.appendChild(c1)
	constraints.appendChild(c2)
def change_ocfs2_device(rsc):
	print >> sys.stderr, "The current device for ocfs2 depends on evms: %s"%get_param(rsc,"device")
	dev = get_input("Please supply the device where %s ocfs2 resource resides: "%rsc.getAttribute("id"))
	set_param(rsc,"device",dev)
def stop_ocfs2(rsc):
	node = rsc.parentNode
	if node.tagName != "clone":
		node = rsc
	id = node.getAttribute("id")
	l = rsc.getElementsByTagName("meta_attributes")
	if l:
		meta = l[0]
	else:
		meta = doc.createElement("meta_attributes")
		meta.setAttribute("id",id + "_meta")
		node.appendChild(meta)
		attributes = doc.createElement("attributes")
		meta.appendChild(attributes)
	rm_param(rsc,"target_role")
	set_attribute("meta_attributes",node,"target_role","Stopped")
def new_pingd_rsc(options,host_list):
	rsc_id = "pingd"
	c = mk_clone(rsc_id,"pingd","heartbeat","ocf")
	node = c.getElementsByTagName("primitive")[0]
	instance_attributes = doc.createElement("instance_attributes")
	instance_attributes.setAttribute("id", rsc_id + "_inst_attr")
	node.appendChild(instance_attributes)
	attributes = doc.createElement("attributes")
	instance_attributes.appendChild(attributes)
	attributes.appendChild(nvpair(rsc_id,"options",options))
	return c
def handle_pingd_respawn():
	f = open("/etc/ha.d/ha.cf", 'r')
	opts = ''
	ping_list = []
	for l in f:
		s = l.split()
		if not s:
			continue
		if s[0] == "respawn" and s[2].find("pingd") > 0:
			opts = ' '.join(s[3:])
		elif s[0] == "ping":
			ping_list.append(s[1])
	f.close()
	return opts,' '.join(ping_list)

CIB = "$CIB"
doc = load_cib(CIB)
xml_processnodes(doc,is_whitespace,rmnodes)
resources = doc.getElementsByTagName("resources")[0]
constraints = doc.getElementsByTagName("constraints")[0]
if not resources:
	print >> sys.stderr, "ERROR: sorry, no resources section in the CIB, cannot proceed"
	sys.exit(1)
if not constraints:
	print >> sys.stderr, "ERROR: sorry, no constraints section in the CIB, cannot proceed"
	sys.exit(1)

opts,pingd_host_list = handle_pingd_respawn()
if opts:
	clone = new_pingd_rsc(opts,pingd_host_list)
	resources.appendChild(clone)

for rsc in doc.getElementsByTagName("primitive"):
	rsc_id = rsc.getAttribute("id")
	rsc_type = rsc.getAttribute("type")
	if rsc_type == "Evmsd":
		print >> sys.stderr, "INFO: removing the Evmsd resource"
		resources.removeChild(rsc)
	elif rsc_type == "EvmsSCC":
		print >> sys.stderr, "INFO: EvmsSCC resource is going to be replaced by LVM"
		vg = get_input("Please supply the name of the volume group corresponding to %s: "%rsc_id)
		node = mk_lvm(rsc_id,vg)
		parent = rsc.parentNode
		parent.removeChild(rsc)
		parent.appendChild(node)
		rsc.unlink()
	elif rsc_type == "pingd":
		if pingd_host_list:
			set_param(rsc,"host_list",pingd_host_list)
	elif rsc_type == "Filesystem":
		if get_param(rsc,"fstype") == "ocfs2":
			if get_param(rsc,"device").find("evms") > 0:
				change_ocfs2_device(rsc)
			id = rsc.getAttribute("id")
			print >> sys.stderr, "INFO: adding required cloned resources for %s"%id
			add_ocfs_clones(id)
			print >> sys.stderr, "INFO: adding constraints for %s"%id
			add_ocfs_constraints(rsc,id)
			print >> sys.stderr, "INFO: adding target_role=Stopped to %s"%id
			stop_ocfs2(rsc)

s = skip_first(doc.toprettyxml())
tmp = write_tmp(s)
print tmp

EOF
}

part2() {
	intro_part2 || return 0
	tmpfile=`convert_cib`
	$MYSUDO [ -f "$tmpfile" ] ||
		fatal "failed to process the CIB"
	$DRY mv $tmpfile $CIB
	info "Processed the CIB successfully"
}
dcidle() {
	try_crmadmin=10
	dc=""
	while [ -z "$dc" -a $try_crmadmin -gt 0 ]; do
		dc=`$MYSUDO crmadmin -D | awk '{print $NF}'`
		try_crmadmin=$((try_crmadmin-1))
	done

	if [ x = x"$dc" ]; then
		echo "sorry, no dc found/elected"
		exit 1
	fi
	maxcnt=60 cnt=0
	while [ $cnt -lt $maxcnt ]; do
		stat=`$MYSUDO crmadmin -S $dc`
		ec=$?
		echo $stat | grep -qs S_IDLE && break
		[ "$1" = "-v" ] && echo $stat
		sleep 1
		printf "."
		cnt=$((cnt+1))
	done
	echo status: $stat
	echo waited: $cnt
	echo $stat | grep -qs S_IDLE
}
wait_cluster() {
	printf "waiting for crm to start."
	for i in 1 2 3 4 5; do
		for j in 1 2; do
			sleep 1; printf "."
		done
	done
	dcidle
}
tune_ocfs2() {
	cat<<EOF
The ocfs2 metadata has to change to reflect the cluster stack
change. To do that, we have to start the cluster stack on
this node.
EOF
	pls_press_enter
	$DRY /etc/init.d/openais start
	if wait_cluster; then
		info "starting the tunefs.ocfs2"
		$DRY tunefs.ocfs2 --update-cluster-stack
	else
		fatal "could not start pacemaker; please check the logs"
	fi
}

analyze_cib
rc=$?
[ $rc -gt 1 ] && fatal "error while analyzing CIB"
if [ $rc -eq 1 ] ||
	grep -qs "^respawn.*pingd" $HA_CF &&
		info "a pingd resource has to be created"; then
	part2
	if grep -qs '<primitive.*type="ocfs2"' $CIB; then
		tune_ocfs2
	fi
fi

$DRY touch $DONE_F

# finally, copy files to all nodes
info "Copying files to other nodes ..."
info "(please provide root password if prompted)"
ssh_opts="-l root $SSH_OPTS"
rc=0
for node in `getnodes`; do
	[ "$node" = "$WE" ] &&
		continue
	echo "Copying to node $node ..."
	(cd / && tar czf - $DIST_FILES) |
		ssh $ssh_opts $node "$DRY rm -f $REMOTE_RM_FILES &&
			cd / && $DRY tar xzf -"
	let rc=$rc+$?
done
info "Done transfering files"
if [ $rc -ne 0 ]; then
	warning "we could not update some ssh nodes"
	info "before starting the cluster stack on those nodes:"
	info "copy and unpack $MAN_TARF (from the / directory)"
	info "and execute: rm -f $REMOTE_RM_FILES"
	(cd / && tar czf $MAN_TARF $DIST_FILES)
fi
