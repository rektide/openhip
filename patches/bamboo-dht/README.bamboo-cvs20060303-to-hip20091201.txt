Boeing-modified  Bamboo DHT Server
==================================
12/1/2009
Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>

--------------------------------------------------------------------------------
INTRODUCTION
--------------------------------------------------------------------------------

This software is the Bamboo DHT server implementation from available from:
  http://bamboo-dht.org
Bamboo formed the basis for the OpenDHT public service running on PlanetLab,
which is now unmaintained:
  http://opendht.org

The DHT server has been modified to enable a HIP-aware DHT server. The HIP-aware
server validates the authenticity of HIP records stored in the server and can
be configured to disallow all invalid and non-HIP records. Such a server is
described by the Internet-Draft:
  http://www.watersprings.org/pub/id/draft-ahrenholz-hiprg-dht-06.txt

-------------------------------------------------------------------------------
LICENSE
-------------------------------------------------------------------------------

The Bamboo DHT server and this patch file is licensed under the BSD license, 
a copy of which may be found in the LICENSE file of this directory.

--------------------------------------------------------------------------------
INSTALLATION
--------------------------------------------------------------------------------

To install on Ubuntu 9.10, you need Sun's Java Development Kit package:
sudo apt-get install sun-java6-jdk

Download Berkeley DB 4.8.24 from here:
#http://www.oracle.com/technology/software/products/berkeley-db/index.html
tar xzf db-4.8.24.tar.gz
cd db-4.8.24/build_unix
../dist/configure --enable-java
make
sudo make install

The Bamboo software is available from here:
http://bamboo-dht.org/bamboo-cvs-2006-03-03.tgz

Use the included patch:
tar xzf bamboo-cvs-2006-03-03.tgz
cd bamboo
patch -p1 -i ../bamboo-cvs20060303-to-hip20091201.patch

Update Bamboo with the newer Berkeley DB 4.8.24:
cd bamboo/lib
cp /usr/local/BerkeleyDB.4.8/lib/db.jar db-4.8.24.jar
# if version differs, edit bamboo/bin/run-java and update db-*.jar version, 
# add /usr/local/BerkeleyDB.4.8/lib to LD_LIBRARY_PATH

From the top-level directory type 'make'. The Bamboo server may be run from
the build directory. There is no 'make install' target. You can manually copy
this directory to the location of your choosing.


--------------------------------------------------------------------------------
USAGE
--------------------------------------------------------------------------------
See the sample hip.cfg for an example of running a single HIP-aware DHT server.

The <Gateway> section of the configuration file has three new options. These
allow validation of the HIP address (hip-addr application) and HIP names 
(hip-name application), and a policy option to allow only these two HIP put
operations. They are marked with a plus (+) below.

        <Gateway>
            class bamboo.dht.Gateway
            <initargs>
                debug_level 0
                port 5852
+               validate_hip_addr true
+               validate_hip_name false
+               allow_only_hip true
            </initargs>
        </Gateway>

The hip-name certificate validation has not been implemented yet. Primitives
are in place to do so.

You do not need to run the Bamboo DHT server as root. You can start it from the
build directory using the provided script:
   ./bamboo.sh

The relevant log file is stored in ./var/log/bamboo.log. You can stop the server
using the provided script:
   ./bamboo.sh stop


--------------------------------------------------------------------------------
CHANGELOG
--------------------------------------------------------------------------------
This is an attempt to record some history of Bamboo DHT code. As of this
writing, the base code has not been updated for almost four years. Patches
were gathered from the web to bring the code more up-to-date.
Please add to this section as code patches are applied.

--------------------------------------------------------------------------------
(this is the base release)
bambo-cvs-2006-03-03
sean.c.rhea@gmail.com
This is the latest release available from this URL:
http://bamboo-dht.org/bamboo-cvs-2006-03-03.tgz

--------------------------------------------------------------------------------
bamboo-socket-exception.patch
src/bamboo/lss/UdpCC.java
Tom Goff <thomas.goff@boeing.com>

makes some errors non-fatal and was added to handle situations when there's no route to a destination a little more gracefully

--------------------------------------------------------------------------------
bamboo_fix_TO_ipv4-20060303_FOR_assertion.diff
Blerta Bishaj HIIT
src/bamboo/dht/Dht.java
check added to avoid assertion with half-open connections

--------------------------------------------------------------------------------
src/bamboo/db/StorageManager.java
Bogdan Nicolae <bogdan.nicolae@irisa.fr>
I've updated the Bamboo Storage Manager to use the new Berkeley DB
java API. Tested (briefly) with DB v4.6.18 and jdk 1.6.

For those interested, just replace src/db/StorageManager.java with the
provided one (March 2006 revision).
This update solves some checkpointing crashes other people (including me)
experienced as well.

http://www.opendht.org/mailing-list-archives/2008-February/000352.html

--------------------------------------------------------------------------------
 bamboo_changes_TO_ipv4-20060303_FOR_fedora-script.diff [1]
Blerta Bishaj HIIT

Bamboo init scripts for Fedora - writes output to log file, PID file

--------------------------------------------------------------------------------


