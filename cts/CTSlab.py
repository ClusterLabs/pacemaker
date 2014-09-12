#!/usr/bin/python

'''CTS: Cluster Testing System: Lab environment module
 '''

__copyright__ = '''
Copyright (C) 2001,2005 Alan Robertson <alanr@unix.sh>
Licensed under the GNU GPL.
'''

#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA.

from UserDict import UserDict
import sys, types, string, string, signal, os, socket

pdir = os.path.dirname(sys.path[0])
sys.path.insert(0, pdir) # So that things work from the source directory

try:
    from cts.CTSvars    import *
    from cts.CM_ais     import *
    from cts.CM_lha     import crm_lha
    from cts.CTSaudits  import AuditList
    from cts.CTStests   import TestList
    from cts.CTSscenarios import *
    from cts.logging      import LogFactory

except ImportError:
    sys.stderr.write("abort: couldn't find cts libraries in [%s]\n" %
                     ' '.join(sys.path))
    sys.stderr.write("(check your install and PYTHONPATH)\n")

    # Now do it again to get more details
    from cts.CTSvars    import *
    from cts.CM_ais     import *
    from cts.CM_lha     import crm_lha
    from cts.CTSaudits  import AuditList
    from cts.CTStests   import TestList
    from cts.CTSscenarios import *
    from cts.logging      import LogFactory
    sys.exit(-1)

cm = None
scenario = None

LogFactory().add_stderr()
def sig_handler(signum, frame) :
    LogFactory().log("Interrupted by signal %d"%signum)
    if scenario: scenario.summarize()
    if signum == 15 :
        if scenario: scenario.TearDown()
        sys.exit(1)

if __name__ == '__main__':

    Environment = CtsLab(sys.argv[1:])
    NumIter = Environment["iterations"]
    Tests = []

    # Set the signal handler
    signal.signal(15, sig_handler)
    signal.signal(10, sig_handler)

    # Create the Cluster Manager object
    if Environment["Stack"] == "heartbeat":
        cm = crm_lha(Environment)

    elif Environment["Stack"] == "openais (whitetank)":
        cm = crm_whitetank(Environment)
        
    elif Environment["Stack"] == "corosync 2.x":
        cm = crm_mcp(Environment)
        
    elif Environment["Stack"] == "corosync (cman)":
        cm = crm_cman(Environment)
        
    elif Environment["Stack"] == "corosync (plugin v1)":
        cm = crm_cs_v1(Environment)
        
    elif Environment["Stack"] == "corosync (plugin v0)":
        cm = crm_cs_v0(Environment)
    else:
        LogFactory().log("Unknown stack: "+Environment["stack"])
        sys.exit(1)

    if Environment["TruncateLog"] == 1:
        Environment.log("Truncating %s" % LogFile)
        lf = open(LogFile, "w");
        if lf != None:
            lf.truncate(0)
            lf.close()

    Audits = AuditList(cm)

    if Environment["ListTests"] == 1:
        Tests = TestList(cm, Audits)
        LogFactory().log("Total %d tests"%len(Tests))
        for test in Tests :
            LogFactory().log(str(test.name));
        sys.exit(0)

    elif len(Environment["tests"]) == 0:
        Tests = TestList(cm, Audits)

    else:
        Chosen = Environment["tests"]
        for TestCase in Chosen:
           match = None

           for test in TestList(cm, Audits):
               if test.name == TestCase:
                   match = test

           if not match:
               usage("--choose: No applicable/valid tests chosen")
           else:
               Tests.append(match)

    # Scenario selection
    if Environment["scenario"] == "basic-sanity":
        scenario = RandomTests(cm, [ BasicSanityCheck(Environment) ], Audits, Tests)

    elif Environment["scenario"] == "all-once":
        NumIter = len(Tests)
        scenario = AllOnce(
            cm, [ BootCluster(Environment), PacketLoss(Environment) ], Audits, Tests)
    elif Environment["scenario"] == "sequence":
        scenario = Sequence(
            cm, [ BootCluster(Environment), PacketLoss(Environment) ], Audits, Tests)
    elif Environment["scenario"] == "boot":
        scenario = Boot(cm, [ LeaveBooted(Environment)], Audits, [])
    else:
        scenario = RandomTests(
            cm, [ BootCluster(Environment), PacketLoss(Environment) ], Audits, Tests)

    LogFactory().log(">>>>>>>>>>>>>>>> BEGINNING " + repr(NumIter) + " TESTS ")
    LogFactory().log("Stack:                  %s (%s)" % (Environment["Stack"], Environment["Name"]))
    LogFactory().log("Schema:                 %s" % Environment["Schema"])
    LogFactory().log("Scenario:               %s" % scenario.__doc__)
    LogFactory().log("CTS Master:             %s" % Environment["cts-master"])
    LogFactory().log("CTS Logfile:            %s" % Environment["OutputFile"])
    LogFactory().log("Random Seed:            %s" % Environment["RandSeed"])
    LogFactory().log("Syslog variant:         %s" % Environment["syslogd"].strip())
    LogFactory().log("System log files:       %s" % Environment["LogFileName"])
#    Environment.log(" ")
    if Environment.has_key("IPBase"):
        LogFactory().log("Base IP for resources:  %s" % Environment["IPBase"])
    LogFactory().log("Cluster starts at boot: %d" % Environment["at-boot"])

    Environment.dump()
    rc = Environment.run(scenario, NumIter)
    sys.exit(rc)
