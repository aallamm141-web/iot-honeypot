#!/bin/sh
mkdir -p /cowrie/cowrie-git/share/cowrie/txtcmds/bin
mkdir -p /cowrie/cowrie-git/share/cowrie/txtcmds/sbin
mkdir -p /cowrie/cowrie-git/share/cowrie/txtcmds/usr/bin
mkdir -p /cowrie/cowrie-git/share/cowrie/txtcmds/etc
mkdir -p /cowrie/cowrie-git/share/cowrie/txtcmds/proc

echo "Linux iot-gateway-01 3.10.0-1160.el7.x86_64 #1 SMP Mon Oct 19 16:18:59 UTC 2020 x86_64 GNU/Linux" > /cowrie/cowrie-git/share/cowrie/txtcmds/bin/uname

cat > /cowrie/cowrie-git/share/cowrie/txtcmds/etc/passwd << 'EOF'
root:x:0:0:root:/root:/bin/bash
admin:x:1000:1000:System Admin:/home/admin:/bin/sh
support:x:1001:1001:Tech Support:/home/support:/bin/sh
guest:x:1002:1002:Guest:/home/guest:/bin/sh
daemon:x:2:2:daemon:/sbin:/sbin/nologin
bin:x:1:1:bin:/bin:/sbin/nologin
EOF

echo "iot-gateway-01" > /cowrie/cowrie-git/share/cowrie/txtcmds/etc/hostname

cat > /cowrie/cowrie-git/share/cowrie/txtcmds/etc/network << 'EOF'
DEVICE=eth0
BOOTPROTO=static
IPADDR=192.168.1.1
NETMASK=255.255.255.0
GATEWAY=192.168.1.254
DNS1=8.8.8.8
DNS2=8.8.4.4
ONBOOT=yes
EOF

cat > /cowrie/cowrie-git/share/cowrie/txtcmds/etc/fstab << 'EOF'
# /etc/fstab
/dev/sda1   /           ext4    defaults        1 1
/dev/sda2   /boot       ext4    defaults        1 2
tmpfs       /tmp        tmpfs   defaults        0 0
EOF

cat > /cowrie/cowrie-git/share/cowrie/txtcmds/etc/os-release << 'EOF'
PRETTY_NAME="CentOS Linux 7 (Core)"
NAME="CentOS Linux"
VERSION_ID="7"
ID=centos
ID_LIKE=rhel
HOME_URL="https://www.centos.org/"
EOF

echo "CentOS Linux release 7.9.2009 (Core)" > /cowrie/cowrie-git/share/cowrie/txtcmds/etc/redhat-release

cat > /cowrie/cowrie-git/share/cowrie/txtcmds/proc/version << 'EOF'
Linux version 3.10.0-1160.el7.x86_64 (mockbuild@kbuilder.bsys.centos.org)
(gcc version 4.8.5 20150623 (Red Hat 4.8.5-44) (GCC))
#1 SMP Mon Oct 19 16:18:59 UTC 2020
EOF

cat > /cowrie/cowrie-git/share/cowrie/txtcmds/proc/cpuinfo << 'EOF'
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 85
model name	: Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz
cpu MHz		: 2300.000
cache size	: 30720 KB
EOF

cat > /cowrie/cowrie-git/share/cowrie/txtcmds/proc/meminfo << 'EOF'
MemTotal:        8175956 kB
MemFree:         6421344 kB
MemAvailable:    7102332 kB
SwapTotal:       2097148 kB
SwapFree:        2097148 kB
EOF

cat > /cowrie/cowrie-git/share/cowrie/txtcmds/bin/ifconfig << 'EOF'
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.1  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::1  prefixlen 64  scopeid 0x20<link>
        ether 00:1a:2b:3c:4d:5e  txqueuelen 1000  (Ethernet)
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
EOF

cat > /cowrie/cowrie-git/share/cowrie/txtcmds/bin/netstat << 'EOF'
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:502             0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:1883            0.0.0.0:*               LISTEN
EOF

cat > /cowrie/cowrie-git/share/cowrie/txtcmds/bin/ps << 'EOF'
root      1234  0.0  0.1  12345  1234 ?  Ss  Oct19  0:01 /sbin/init
root       234  0.0  0.0   9876   876 ?  S   Oct19  0:00 /usr/sbin/sshd
admin      456  0.0  0.1  23456  2345 ?  S   Oct19  0:05 /usr/bin/python /opt/scada/gateway.py
root       789  0.0  0.0   5432   543 ?  Ss  Oct19  0:00 /usr/sbin/crond
EOF
