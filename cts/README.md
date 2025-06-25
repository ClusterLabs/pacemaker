# Pacemaker Cluster Test Suite (CTS)

The Cluster Test Suite (CTS) refers to all Pacemaker testing code that can be
run in an installed environment. (Pacemaker also has unit tests that must be
run from a source distribution.)

CTS includes:

* Regression tests: These test specific Pacemaker components individually (no
  integration tests). The primary front end is cts-regression in this
  directory. Run it with the --help option to see its usage.

  cts-regression is a wrapper for individual component regression tests also
  in this directory (cts-cli, cts-exec, cts-fencing, and cts-scheduler).

  The CLI and scheduler regression tests can also be run from a source
  distribution. The other regression tests can only run in an installed
  environment, and the cluster should not be running on the node running these
  tests.

* The CTS lab: This is a cluster exerciser for intensively testing the behavior
  of an entire working cluster. It is primarily for developers and packagers of
  the Pacemaker source code, but it can be useful for users who wish to see how
  their cluster will react to various situations. Most of the lab code is in
  the Pacemaker Python module. The front end, cts-lab, is in this directory.

  The CTS lab runs a randomized series of predefined tests on the cluster. It
  can be run against a pre-existing cluster configuration or overwrite the
  existing configuration with a test configuration.

* Helpers: Some of the component regression tests and the CTS lab require
  certain helpers to be installed as root. These include a dummy LSB init
  script, dummy systemd service, etc. In a source distribution, the source for
  these is in cts/support.

  The tests will install these as needed and uninstall them when done. This
  means that the cluster configuration created by the CTS lab will generate
  failures if started manually after the lab exits. However, the helper
  installer can be run manually to make the configuration usable, if you want
  to do your own further testing with it:

      /usr/libexec/pacemaker/cts-support install

  As you might expect, you can also remove the helpers with:

      /usr/libexec/pacemaker/cts-support uninstall

  (The actual directory location may vary depending on how Pacemaker was
  built.)

* Cluster benchmark: The benchmark subdirectory of this directory contains some
  cluster test environment benchmarking code. It is not particularly useful for
  end users.

* Valgrind suppressions: When memory-testing Pacemaker code with valgrind,
  various bugs in non-Pacemaker libraries and such can clutter the results. The
  valgrind-pcmk.suppressions file in this directory can be used with valgrind's
  --suppressions option to eliminate many of these.


## Using the CTS lab

### Requirements

* Three or more machines (one test exerciser and at least two cluster nodes).

* The test cluster nodes should be on the same subnet and have journalling
  filesystems (ext4, xfs, etc.) for all of their filesystems other than
  /boot. You also need a number of free IP addresses on that subnet if you
  intend to test IP address takeover.

* The test exerciser machine doesn't need to be on the same subnet as the test
  cluster machines. Minimal demands are made on the exerciser; it just has to
  stay up during the tests.

* Tracking problems is easier if all machines' clocks are closely synchronized.
  NTP does this automatically, but you can do it by hand if you want.

* The account on the exerciser used to run the CTS lab (which does not need to
  be root) must be able to ssh as root to the cluster nodes without a password
  challenge. See the Mini-HOWTO at the end of this file for details about how
  to configure ssh for this.

* The exerciser needs to be able to resolve all cluster node names, whether by
  DNS or /etc/hosts.

* CTS is not guaranteed to run on all platforms that Pacemaker itself does.
  It calls commands such as service that may not be provided by all OSes.


### Preparation

* Install Pacemaker, including the testing code, on all machines. The testing
  code must be the same version as the rest of Pacemaker, and the Pacemaker
  version must be the same on the exerciser and all cluster nodes.

  You can install from source, although many distributions package the testing
  code (named pacemaker-cts or similar). Typically, everything needed by the
  CTS lab is installed in /usr/share/pacemaker/tests/cts.

* Configure the cluster layer (Corosync) on the cluster machines (*not* the
  exerciser), and verify it works. Node names used in the cluster configuration
  *must* match the hosts' names as returned by `uname -n`; they do not have to
  match the machines' fully qualified domain names.

* Optionally, configure the exerciser as a log aggregator, using something like
  `rsyslog` log forwarding. If aggregation is detected, the exerciser will look
  for new messages locally instead of requesting them repeatedly from cluster
  nodes.
  * Currently, `/var/log/messages` on the exerciser is the only supported log
    destination. Further, if it's specified explicitly on the command line as
    the log file, then CTS lab will not check for aggregation.
  * CTS lab does not currently detect systemd journal log aggregation.

* Optionally, if the lab nodes use the systemd journal for logs, create
  /etc/systemd/journald.conf.d/cts-lab.conf on each with
  `RateLimitIntervalSec=0` or `RateLimitBurst=0`, to avoid issues with log
  detection.

### Run

The primary interface to the CTS lab is the cts-lab executable:

    /usr/share/pacemaker/tests/cts-lab [options] <number-of-tests-to-run>

(The actual directory location may vary depending on how Pacemaker was built.)

As part of the options, specify the cluster nodes with --nodes, for example:

    --nodes "pcmk-1 pcmk-2 pcmk-3"

Most people will want to save the output to a file, for example:

    --outputfile ~/cts.log

Unless you want to test a pre-existing cluster configuration, you also want
(*warning*: with these options, any existing configuration will be lost):

    --clobber-cib
    --populate-resources

You can test floating IP addresses (*not* already used by any host), one per
cluster node, by specifying the first, for example:

    --test-ip-base 192.168.9.100

Configure some sort of fencing, for example to use fence\_xvm:

    --stonith xvm

Putting all the above together, a command line might look like:

    /usr/share/pacemaker/tests/cts-lab --nodes "pcmk-1 pcmk-2 pcmk-3" \
        --outputfile ~/cts.log --clobber-cib --populate-resources \
        --test-ip-base 192.168.9.100 --stonith xvm 50

For more options, run with the --help option.

There are also a couple of wrappers for cts-lab that some users may find more
convenient: cts, which is typically installed in the same place as the rest of
the testing code; and cluster\_test, which is in the source directory and
typically not installed.

To extract the result of a particular test, run:

    crm_report -T $test


### Optional: Memory testing

Pacemaker has various options for testing memory management. On cluster nodes,
Pacemaker components use various environment variables to control these
options. How these variables are set varies by OS, but usually they are set in
a file such as /etc/sysconfig/pacemaker or /etc/default/pacemaker.

Valgrind is a program for detecting memory management problems such as
use-after-free errors. If you have valgrind installed, you can enable it by
setting the following environment variables on all cluster nodes:

    PCMK_valgrind_enabled=pacemaker-attrd,pacemaker-based,pacemaker-controld,pacemaker-execd,pacemaker-fenced,pacemaker-schedulerd
    VALGRIND_OPTS="--leak-check=full --trace-children=no --num-callers=25
        --log-file=/var/lib/pacemaker/valgrind-%p
        --suppressions=/usr/share/pacemaker/tests/valgrind-pcmk.suppressions
        --gen-suppressions=all"

If running the CTS lab with valgrind enabled on the cluster nodes, add these
options to cts-lab:

    --valgrind-procs "pacemaker-attrd pacemaker-based pacemaker-controld pacemaker-execd pacemaker-schedulerd pacemaker-fenced"

These options should only be set while specifically testing memory management,
because they may slow down the cluster significantly, and they will disable
writes to the CIB. If desired, you can enable valgrind on a subset of pacemaker
components rather than all of them as listed above.

Valgrind will put a text file for each process in the location specified by
valgrind's --log-file option. See
https://www.valgrind.org/docs/manual/mc-manual.html for explanations of the
messages valgrind generates.

Separately, if you are using the GNU C library, the G\_SLICE,
MALLOC\_PERTURB\_, and MALLOC\_CHECK\_ environment variables can be set to
affect the library's memory management functions.

When using valgrind, G\_SLICE should be set to "always-malloc", which helps
valgrind track memory by always using the malloc() and free() routines
directly. When not using valgrind, G\_SLICE can be left unset, or set to
"debug-blocks", which enables the C library to catch many memory errors
but may impact performance.

If the MALLOC\_PERTURB\_ environment variable is set to an 8-bit integer, the C
library will initialize all newly allocated bytes of memory to the integer
value, and will set all newly freed bytes of memory to the bitwise inverse of
the integer value. This helps catch uses of uninitialized or freed memory
blocks that might otherwise go unnoticed. Example:

    MALLOC_PERTURB_=221

If the MALLOC\_CHECK\_ environment variable is set, the C library will check for
certain heap corruption errors. The most useful value in testing is 3, which
will cause the library to print a message to stderr and abort execution.
Example:

    MALLOC_CHECK_=3

Valgrind should be enabled for either all nodes or none when used with the CTS
lab, but the C library variables may be set differently on different nodes.


### Optional: Remote node testing

If the pacemaker-remoted daemon is installed on all cluster nodes, the CTS lab
will enable remote node tests.

The remote node tests choose a random node, stop the cluster on it, start
pacemaker-remoted on it, and add an ocf:pacemaker:remote resource to turn it
into a remote node. When the test is done, the lab will turn the node back into
a cluster node.

To avoid conflicts, the lab will rename the node, prefixing the original node
name with "remote-". For example, "pcmk-1" will become "remote-pcmk-1". These
names do not need to be resolvable.

The name change may require special fencing configuration, if the fence agent
expects the node name to be the same as its hostname. A common approach is to
specify the "remote-" names in pcmk\_host\_list. If you use
pcmk\_host\_list=all, the lab will expand that to all cluster nodes and their
"remote-" names.  You may additionally need a pcmk\_host\_map argument to map
the "remote-" names to the hostnames. Example:

    --stonith xvm --stonith-args \
    pcmk_host_list=all,pcmk_host_map=remote-pcmk-1:pcmk-1;remote-pcmk-2:pcmk-2


### Optional: Remote node testing with valgrind

When running the remote node tests, the Pacemaker components on the *cluster*
nodes can be run under valgrind as described in the "Memory testing" section.
However, pacemaker-remoted cannot be run under valgrind that way, because it is
started by the OS's regular boot system and not by Pacemaker.

Details vary by system, but the goal is to set the VALGRIND\_OPTS environment
variable and then start pacemaker-remoted by prefixing it with the path to
valgrind.

The init script and systemd service file provided with pacemaker-remoted will
load the pacemaker environment variables from the same location used by other
Pacemaker components, so VALGRIND\_OPTS will be set correctly if using one of
those.

For an OS using systemd, you can override the ExecStart parameter to run
valgrind. For example:

    mkdir /etc/systemd/system/pacemaker_remote.service.d
    cat >/etc/systemd/system/pacemaker_remote.service.d/valgrind.conf <<EOF
    [Service]
    ExecStart=
    ExecStart=/usr/bin/valgrind /usr/sbin/pacemaker-remoted
    EOF


### Mini-HOWTO: Allow passwordless remote SSH connections

The CTS lab runs "ssh -l root" so you don't have to do any of your testing
logged in as root on the exerciser. Here is how to allow such connections
without requiring a password to be entered each time:

* On your test exerciser, create an SSH key if you do not already have one.
  Most commonly, SSH keys will be in your ~/.ssh directory, with the
  private key file not having an extension, and the public key file
  named the same with the extension ".pub" (for example, ~/.ssh/id\_rsa.pub).

  If you don't already have a key, you can create one with:

      ssh-keygen -t rsa

* From your test exerciser, authorize your SSH public key for root on all test
  machines (both the exerciser and the cluster test machines):

      ssh-copy-id -i ~/.ssh/id_rsa.pub root@$MACHINE

  You will probably have to provide your password, and possibly say
  "yes" to some questions about accepting the identity of the test machines.

  The above assumes you have a RSA SSH key in the specified location;
  if you have some other type of key (DSA, ECDSA, etc.), use its file name
  in the -i option above.

* To verify, try this command from the exerciser machine for each
  of your cluster machines, and for the exerciser machine itself.

      ssh -l root $MACHINE

  If this works without prompting for a password, you're in business.
  If not, look at the documentation for your version of ssh.
