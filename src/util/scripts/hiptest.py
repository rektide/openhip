#!/usr/bin/python
#
# Copyright (c)2011-2012 the Boeing Company.
#
# author: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
#
# HIP automated testing script, for use as a 'make check' target.
# This script requires that CORE be installed, see:
#     http://code.google.com/p/coreemu/
#


HIP_CFG_CACHE="~/.hiptest"
HIP_CFG_DIR="/usr/local/etc/hip"

import optparse, sys, os, datetime, time, shutil, re
from stat import *
from core import pycore
from core.misc import ipaddr
from core.misc.utils import check_call, mutecheck_call
from core.misc.ipaddr import *

# node list (count from 1)
nodes = [None]

class HipSession(pycore.Session):
    def buildknownhosts(self):
        ''' Collect HITs from HipNodes into a known_host_identities.xml file,
            and deploy that file to all nodes.
        '''
        hits = [None]
        cfgbase = os.path.expanduser(HIP_CFG_CACHE)
        knownhosts = os.path.join(cfgbase, "known_host_identities.xml")
        kh = open(knownhosts, "w")
        kh.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
        kh.write("<known_host_identities>\n")
        # collect
        for n in self.objs():
            if not isinstance(n, HipNode):
                continue
            pub = os.path.join(n.nodedir, "%s_host_identities.pub.xml" % n.name)
            f = open(pub, "r")
            publines = f.readlines()
            publines.insert(-2, "    <addr>%s</addr>\n" % n.getpreferredaddr())
            if (len(n.legacynodes) > 1):
                for line in publines:
                    if line.startswith("    <HIT>"):
                        hits.append(line.strip(' </HIT>\n'))
                publines.insert(-2,"    <legacyNodesIp>%s</legacyNodesIp>\n" % \
                                         n.legacynodes[1].getaddr())
            kh.write("".join(publines[3:-1]))
            f.close()
        if (len(hits) > 2):
            for hit in hits[2:]:
                kh.write("  <peer_allowed>\n")
                kh.write("    <hit1>%s</hit1>\n" % hits[1])
                kh.write("    <hit2>%s</hit2>\n" % hit)
                kh.write("  </peer_allowed>\n")
        kh.write("</known_host_identities>\n")
        kh.close()
        # deploy
        for n in self.objs():
            if not isinstance(n, HipNode):
                continue           
            dst = os.path.join(cfgbase, n.name, "known_host_identities.xml")
            shutil.copy(knownhosts, dst)

    def pingcheck(self, src, dst):
        ''' Ping the LSI of the dst node from the src node.
        '''
        lsi = dst.checkforlsi()
        if dst is None:
            print "LSI for %s not found!" % dst.name
            return False
        status, res = src.cmdresult(['ping', '-c', '3', lsi])
        if res.find(" 0% packet loss"):
            return True
        if status == 0:
            return True
        return False

    def lnpingcheck(self, src, dst):
        ''' Ping the legacy node IP of the dst node from the src node.
        '''
        ip = dst.getaddr()
        if ip is None:
            print "IP for %s not found!" % dst.name
            return False
        status, res = src.cmdresult(['ping', '-c', '3', ip])
        if res.find(" 0% packet loss"):
            return True
        if status == 0:
            return True
        return False

    def bex(self, init, resp, verbose=True):
        ''' Run a base exchange between nodes 1 and 2, and check the result.
        Assumes HIP is already running. Returns True for success/pass, False for
        failure.
        '''
        if verbose:
            print "triggering base exchange from %s to %s using ping..." % \
                    (init.name, resp.name)
        ok = self.pingcheck(init, resp)
        if verbose:
            print "ping returned",
            if ok:
                print "OK"
            else:
                print "FAIL"

        for h in (init, resp):
            if verbose:
                print "log file for", h.name,
            if h.checkhiplog('HIP exchange complete.'):
                if verbose:
                    print "indicates base exchange completed OK"
            else:
                ok = False
                if verbose:
                    print "does not list completed base exchange! FAIL"
        return ok

    def mob(self, init, resp, verbose=True):
        ''' Change the IP address of a node and check the result.
        Assumes HIP is already running and a base exchange has completed.
        Returns True for success/pass, False for failure.
        '''
        addr = init.getpreferredaddr(family=socket.AF_INET)
        if verbose:
            print "readdressing", init.name, "from", addr, "to",
        addr += "1"
        if verbose:
            print addr, "..."
        init.cmd(['ifconfig', 'eth0', addr], wait=True)

        ok = True
        for h in (init, resp):
            if verbose:
                print "log file for", h.name,
            if h.checkhiplog('Update completed (rekey)'):
                if verbose:
                    print "indicates readdress completed OK"
            else:
                ok = False
                if verbose:
                    print "does not list completed update exchange! FAIL"
        ok2 = self.pingcheck(init, resp)
        if verbose:
            print "ping following readdress",
            if ok2:
                print "OK"
            else:
                print "FAIL"
        return ok and ok2

    def rekey(self, init, resp, verbose=True):
        print "waiting for rekey..."
        wait = 5.0
        ok = False
        while wait > 0.0:
            if init.checkhiplog('Update completed (rekey)') and \
                resp.checkhiplog('Update completed (rekey)'):
                ok = True
                break
            time.sleep(1.0)
            wait -= 1.0
        if verbose:
            print "log file indicates rekey", 
            if ok:
                print "completed on both hosts OK"
            else:
                print "incomplete FAIL"
        ok2 = self.pingcheck(init, resp)
        if verbose:
            print "ping following rekey",
            if ok2:
                print "OK"
            else:
                print "FAIL"
        return ok and ok2

    def endboxbex(self, init, resp, verbose=True):
        ''' Initialize a base exchange between between the endboxes by pinging
        from the legacy nodes for the endboxes, and check the result.
        Assumes HIP is already running on the endboxes. Returns True for
        success/pass, False for failure.
        '''
        if verbose:
            print "triggering base exchange on endboxes by using ping " \
                  "from %s to %s..." % \
                  (init.legacynodes[1].name, resp.legacynodes[1].name)
        ok = self.lnpingcheck(init.legacynodes[1], resp.legacynodes[1])
        if verbose:
            print "ping returned",
            if ok:
                print "OK"
            else:
                print "FAIL"

        for h in (init, resp):
            if verbose:
                print "log file for", h.name,
            if h.checkhiplog('HIP exchange complete.'):
                if verbose:
                    print "indicates base exchange completed OK"
            else:
                ok = False
                if verbose:
                    print "does not list completed base exchange! FAIL"
        return ok

class LegacyNode(pycore.nodes.LxcNode):
    def __init__(self, *args, **kwds):
        super(LegacyNode, self).__init__(*args, **kwds)

    def getaddr(self, family=socket.AF_INET):
        for ifc in self.netifs():
            if isinstance(ifc, pycore.nodes.TunTap):
                continue
            for addr in ifc.addrlist:
                ip = addr.split("/")[0]
                if family == socket.AF_INET and isIPv4Address(ip):
                    return ip
                elif family == socket.AF_INET6 and isIPv6Address(ip):
                    return ip

class HipNode(pycore.nodes.LxcNode):
    def __init__(self, *args, **kwds):
        super(HipNode, self).__init__(*args, **kwds)
        self.hip_path = None
        self.addtap(name="hip0")
        self.legacynodes = [None]

    def addtap(self, name):
        ''' Install a TAP device into the namespace for use by the HIP daemon.
        '''
        localname = "%s.%s" % (self.name, name)
        try:
            mutecheck_call(["tunctl", "-t", localname])
        except OSError, e:
            print "error creating TUN/TAP device '%s':\n\t%s" % (localname, e)
            print "make sure the 'tunctl' utility is installed"
            sys.exit(1)
        tap = pycore.nodes.TunTap(node=self, name=name, localname=localname)
        tap.install()

    def hipconfpath(self):
        cfgbase = os.path.expanduser(HIP_CFG_CACHE)
        cfgpath = os.path.join(cfgbase, self.name)
        return os.path.join(cfgpath, "hip.conf")

    def hipbridgeup(self):
        contents = []
        contents.append("#!/bin/bash")
        contents.append("brctl addbr hipbr")
        contents.append("brctl addif hipbr eth1")
        contents.append("brctl addif hipbr hip0")
        contents.append("ifconfig hip0 mtu 1500")
        contents.append("ifconfig hipbr up")
        return "\n".join(contents)

    def hipbridgedown(self):
        contents = []
        contents.append("#!/bin/bash")
        contents.append("ifconfig hipbr down")
        contents.append("brctl delif hipbr hip0")
        contents.append("brctl delif hipbr eth1")
        contents.append("brctl delbr hipbr")
        return "\n".join(contents)

    def hitgen(self):
        ''' Generate a HIP config for the given node. First check for cached
        config under HIP_CFG_CACHE.
        '''
        cfgbase = os.path.expanduser(HIP_CFG_CACHE)
        if not os.path.exists(cfgbase):
            os.mkdir(cfgbase)
        cfgpath = os.path.join(cfgbase, self.name)
        print "checking for cached config in %s..." % cfgpath,
        if not os.path.exists(cfgpath):
            os.mkdir(cfgpath)
        myhosts = os.path.join(cfgpath, "my_host_identities.xml")
        if not os.path.exists(myhosts):
            print "generating host ID..."
            mutecheck_call(["./hitgen", "-noinput", "-name", self.name,
                        "-file", myhosts])
        else:
            print "cached."
        hipconf = os.path.join(cfgpath, "hip.conf")
        if not os.path.exists(hipconf):
            mutecheck_call(["./hitgen", "-file", hipconf, "-conf"])

        self.mount(cfgpath, HIP_CFG_DIR)
        pub = os.path.join(cfgpath, "%s_host_identities.pub.xml" % self.name)
        if not os.path.exists(pub):
            self.cmd([os.path.join(self.hip_path, "hitgen"), "-publish"])

    def hipbridgefiles(self):
        cfgbase = os.path.expanduser(HIP_CFG_CACHE)
        cfgpath = os.path.join(cfgbase, self.name)

        hipbridgeup = os.path.join(cfgpath, "bridge_up.sh")
        if not os.path.exists(hipbridgeup):
            f = open(hipbridgeup, "w")
            f.write(self.hipbridgeup())
            f.close()
        os.chmod(hipbridgeup, S_IREAD | S_IWRITE | S_IEXEC)

        hipbridgedown = os.path.join(cfgpath, "bridge_down.sh")
        if not os.path.exists(hipbridgedown):
            f = open(hipbridgedown, "w")
            f.write(self.hipbridgedown())
            f.close()
        os.chmod(hipbridgedown, S_IREAD | S_IWRITE | S_IEXEC)

    def hipconfval(self, key, value):
        ''' Update the specified key in the hip.conf file with the given value.
        Copy hip.conf to hip.conf.default first.
        '''
        hipconf = self.hipconfpath()
        if not os.path.exists(hipconf):
            mutecheck_call(["./hitgen", "-file", hipconf, "-conf"])
        hipconfdef = hipconf + ".default"
        # make backup copy of hip.conf if it doesn't exist yet
        if not os.path.exists(hipconfdef):
            shutil.copy2(hipconf, hipconfdef)
        # modify the value
        f = open(hipconf, 'r')
        lines = f.readlines()
        f.close()
        f = open(hipconf, 'w')
        changed = False
        for line in lines:
            if line.startswith("  <%s>" % key):
                line = "  <%s>%s</%s>\n" % (key, value, key)
                changed = True
            if line.startswith("</hip_configuration>"):
                if (not changed):
                    newline = "  <%s>%s</%s>\n" % (key, value, key)
                    f.write(newline)
            f.write(line)
        f.close()

    def hipconfrestore(self):
        ''' Restore hip.conf.default to hip.conf after hipconfval() was used.
        '''
        hipconf = self.hipconfpath()
        hipconfdef = hipconf + ".default"
        if os.path.exists(hipconfdef):
            os.remove(hipconf)
            shutil.move(hipconfdef, hipconf)

    def getpreferredaddr(self, family=socket.AF_INET):
        ''' Return the preferred address string.
        '''
        for ifc in self.netifs():
            if isinstance(ifc, pycore.nodes.TunTap):
                continue
            for addr in ifc.addrlist:
                ip = addr.split("/")[0]
                if family == socket.AF_INET and isIPv4Address(ip):
                    return ip
                elif family == socket.AF_INET6 and isIPv6Address(ip):
                    return ip


    def sethippath(self, path):
        ''' Set the path to HIP binaries and create some useful symlinks.
        '''
        self.hip_path = path
        for p in ["hip", "hitgen", "hipstatus"]:
            os.symlink(os.path.join(self.hip_path, p),
                       os.path.join(self.nodedir, p))
        for p in ["hip.conf", "my_host_identities.xml",
                  "known_host_identities.xml"]:
            os.symlink(os.path.join(HIP_CFG_DIR, p),
                       os.path.join(self.nodedir, p))

    def starthip(self):
        ''' Start the HIP daemon.
        '''
        args = [os.path.join(self.hip_path, "hip"), "-v"]
        infd = open(os.devnull, "r").fileno()
        log = open(os.path.join(self.nodedir, "var.log", "hip.log"), "w")
        logfd = log.fileno()
        self.redircmd(infd=infd, outfd=logfd, errfd=logfd,
                      args=args, wait=False)

    def checkforlsi(self, ifname="hip0", retries=10):
        while retries > 0:
            (status, result) = self.cmdresult(["/sbin/ip", "addr", "show",
                                               "dev", "hip0"])
            if status == 0:
                r = re.search('    inet 1\.[\d]+\.[\d]+\.[\d]+', result)
                lsi = r.group().split(' ')[-1]
                return lsi
            retries -= 1
            time.sleep(0.25)
        return None

    def checkhiplog(self, search, retries=15):
        while retries > 0:
            log = open(os.path.join(self.nodedir, "var.log", "hip.log"), "r")
            for line in log:
                if line.find(search) >= 0:
                    log.close()
                    return True
            log.close()
            retries -= 1
            time.sleep(0.25)
        return False


    def checkforhip(self):
        ''' Check that HIP is running.
        '''
        r = True
        print " %s checking for hip process..." % self.name,
        (status, result) = self.cmdresult(["pidof", "hip"])
        if status == 0:
            print "OK"
        else:
            print "error"
            r = False
        print " %s checking for hip0 interface..." % self.name,
        if self.checkforlsi():
            print "OK"
        else:
            print "error"
            r = False
        print " %s checking log file for startup..." % self.name,
        if self.checkhiplog('HIP threads initialization completed.'):
            print "OK"
        else:
            print "error"
            r = False
        return r



def main():
    tests = ["bex","mobility","rekey","shell","endbox"]
    usagestr = "usage: %prog [-h] [options] [tests]\n"
    usagestr += "valid tests are: %s" % tests
    parser = optparse.OptionParser(usage = usagestr)
    parser.set_defaults(numnodes = 2)

    parser.add_option("-n", "--numnodes", dest = "numnodes", type = int,
                      help = "number of nodes")

    def usage(msg = None, err = 0):
        sys.stdout.write("\n")
        if msg:
            sys.stdout.write(msg + "\n\n")
        parser.print_help()
        sys.exit(err)

    # parse command line options
    (options, args) = parser.parse_args()

    if options.numnodes < 1:
        usage("invalid number of nodes: %s" % options.numnodes)

    for a in args:
        if a not in tests:
            sys.stderr.write("ignoring command line argument: '%s'\n" % a)

    if os.geteuid() != 0:
        sys.stderr.write("\nRe-run this script with root privileges, e.g.:\n")
        sys.stderr.write("    sudo make check\n\n")
        sys.exit(1)

    start = datetime.datetime.now()

    print "- - - - -  hiptest.py: %s  - - - - -" % args

    # IP subnet
    prefix = ipaddr.IPv4Prefix("10.83.0.0/16")
    overlayprefix = ipaddr.IPv4Prefix("192.168.0.0/24")
    session = HipSession(persistent=True)
    # emulated Ethernet switch
    switch = session.addobj(cls = pycore.nodes.SwitchNode)
    print "creating %d nodes with addresses from %s session %d" % \
          (options.numnodes, prefix, session.sessionid)
    nln = 0
    for i in xrange(1, options.numnodes + 1):
        n = session.addobj(cls = HipNode, name = "n%d" % i)
        n.newnetif(switch, ["%s/%s" % (prefix.addr(i), prefix.prefixlen)])
        n.cmd(["sysctl", "net.ipv4.icmp_echo_ignore_broadcasts=0"])
        n.sethippath(os.getcwd())
        n.hitgen()
        if "endbox" in args:
            overlayswitch = session.addobj(cls = pycore.nodes.SwitchNode)
            n.newnetif(overlayswitch)
            n.hipbridgefiles()
            n.hipconfval("disable_udp", "yes")
            n.hipconfval("master_interface", "eth0")
            n.hipconfval("cfg_library", "/usr/local/lib/libhipcfgfiles.so")
            nln = nln + 1
            ln = session.addobj(cls = LegacyNode, name = "ln%d" % nln)
            ln.newnetif(overlayswitch,
               ["%s/%s" % (overlayprefix.addr(nln), overlayprefix.prefixlen)])
            n.legacynodes.append(ln)
        nodes.append(n)

    # The known_host_identities.xml file is built after all of the host IDs
    # have been generated.
    session.buildknownhosts()

    # make non-standard configuration file changes for tests here
    if "rekey" in args:
        nodes[1].hipconfval("sa_lifetime", "3")


    # HIP is started after the known_host_identities.xml is built.
    for n in nodes[1:]:
        n.starthip()

    print "pausing 0.5 seconds for hip initialization..."
    time.sleep(0.5)
    problem = False
    for n in nodes[1:]:
        if not n.checkforhip():
            problem = True

    if "shell" in args:
        print "spawning terminal shells for nodes 1 and 2"
        nodes[1].term("bash")
        nodes[2].term("bash")
        if "endbox" in args:
          nodes[1].legacynodes[1].term("bash")
          nodes[2].legacynodes[1].term("bash")
        print "leaving session %d running" % session.sessionid
        print "run 'sudo core-cleanup.sh' to clean up this test environment"
        sys.exit(0)

    if "bex" in args:
        if not session.bex(nodes[1], nodes[2]):
            problem = True
    if "mobility" in args:
        if not session.bex(nodes[1], nodes[2], verbose=False):
            print "problem with base exchange for mobility test!"
            problem = True
        if not session.mob(nodes[1], nodes[2]):
            problem = True
    if "rekey" in args:
        if not session.bex(nodes[1], nodes[2], verbose=False):
            print "problem with base exchange for rekey test!"
            problem = True
        if not session.rekey(nodes[1], nodes[2]):
            problem = True
        nodes[1].hipconfrestore()
    if "endbox" in args:
        if not session.endboxbex(nodes[1], nodes[2]):
            print "problem with legacy node connectivity!"
            problem = True
        nodes[1].hipconfrestore()
        nodes[2].hipconfrestore()

    print "shutting down session %d" % session.sessionid
    session.shutdown()
    print "- - - - -  hiptest.py elapsed time: %s  - - - - -" % \
            (datetime.datetime.now() - start)
    if problem:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
