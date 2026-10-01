@load base/frameworks/notice
@load base/frameworks/software
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/ssh

module HoneypotDetect;

export {
    redef enum Notice::Type += {
        PortScan,
        PingSweep,
        SSHBruteForce,
        SSHLoginSuccess,
        HoneypotAccess,
        MalwareDownload,
    };

    redef Notice::default_suppression_interval = 1min;
}

const honeypot_ports: set[port] = {
    2222/tcp, 2223/tcp,
    80/tcp, 102/tcp, 502/tcp, 21/tcp, 44818/tcp,
    8800/tcp, 10201/tcp, 5020/tcp, 2121/tcp,
    445/tcp, 135/tcp, 3306/tcp, 1433/tcp,
    1883/tcp, 1723/tcp, 5060/tcp,
};

const service_names: table[port] of string = {
    [2222/tcp]  = "SSH Honeypot (Cowrie)",
    [2223/tcp]  = "Telnet Honeypot (Cowrie)",
    [80/tcp]    = "SCADA Web Interface (Conpot)",
    [8800/tcp]  = "SCADA Web Interface (Conpot)",
    [102/tcp]   = "Siemens S7Comm PLC (Conpot)",
    [10201/tcp] = "Siemens S7Comm PLC (Conpot)",
    [502/tcp]   = "Modbus Industrial Protocol (Conpot)",
    [5020/tcp]  = "Modbus Industrial Protocol (Conpot)",
    [21/tcp]    = "FTP Server (Conpot)",
    [2121/tcp]  = "FTP Server (Conpot)",
    [44818/tcp] = "EtherNet/IP (Conpot)",
    [445/tcp]   = "SMB - Possible WannaCry/EternalBlue (Dionaea)",
    [135/tcp]   = "RPC Endpoint (Dionaea)",
    [3306/tcp]  = "MySQL Database (Dionaea)",
    [1433/tcp]  = "MSSQL Database (Dionaea)",
    [1883/tcp]  = "MQTT IoT Broker (Dionaea)",
    [1723/tcp]  = "PPTP VPN (Dionaea)",
    [5060/tcp]  = "SIP VoIP (Dionaea)",
};

global port_tracker: table[addr] of set[port] &create_expire=2min;
global ssh_tracker:  table[addr] of count &default=0 &create_expire=5min;
global icmp_tracker: table[addr] of count &default=0 &create_expire=30secs;

# فلتر - قبول الـ private networks بس
function is_private(a: addr): bool {
    return (a in 192.168.0.0/16 ||
            a in 172.16.0.0/12  ||
            a in 10.0.0.0/8);
}

# Port Scan + Honeypot Access
event connection_state_remove(c: connection) {
    local src      = c$id$orig_h;
    local dst      = c$id$resp_h;
    local dst_port = c$id$resp_p;

    # تجاهل أي حاجة مش على الشبكة المحلية
    if (!is_private(dst))
        return;

    # Port Scan
    if (src !in port_tracker)
        port_tracker[src] = set();
    add port_tracker[src][dst_port];

    if (|port_tracker[src]| == 5) {
        local ports_str = "";
        for (pp in port_tracker[src]) {
            if ( ports_str == "" )
                ports_str = fmt("%s", pp);
            else
                ports_str = fmt("%s, %s", ports_str, pp);
        }
        NOTICE([$note=PortScan,
                $msg=fmt("PORT SCAN DETECTED | Attacker: %s | Ports: %s | Possible Nmap/Masscan",
                         src, ports_str),
                $src=src,
                $suppress_for=2min,
                $identifier=fmt("%s-portscan", src)]);
        delete port_tracker[src];
    }

    # Honeypot Access
    if (dst_port !in honeypot_ports)
        return;

    local svc = dst_port in service_names ? service_names[dst_port] : fmt("Port %s", dst_port);

    NOTICE([$note=HoneypotAccess,
            $msg=fmt("HONEYPOT ACCESS | Service: %s | Attacker: %s | Target: %s:%s",
                     svc, src, dst, dst_port),
            $src=src,
            $suppress_for=1min,
            $identifier=fmt("%s-%s", src, dst_port)]);
}

# Scanner Detection
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) {
    if (!is_private(c$id$resp_h))
        return;

    if (c?$http && c$http?$user_agent) {
        local ua = c$http$user_agent;
        if (/[Nn]map|masscan|nikto|sqlmap|zgrab|dirbuster|gobuster/i in ua) {
            NOTICE([$note=PortScan,
                    $msg=fmt("SCANNER TOOL DETECTED | Attacker: %s | Tool: %s | URI: %s",
                             c$id$orig_h, ua, original_URI),
                    $src=c$id$orig_h,
                    $suppress_for=2min,
                    $identifier=fmt("%s-scanner", c$id$orig_h)]);
        }
    }
}

# Malware Download
event http_reply(c: connection, version: string, code: count, reason: string) {
    if (!is_private(c$id$resp_h))
        return;

    local src = c$id$orig_h;
    local uri = "";
    if (c?$http && c$http?$uri)
        uri = c$http$uri;

    if (code == 200 && /\.(exe|elf|bin|sh|py|ps1|dll|bat|vbs)$/i in uri) {
        NOTICE([$note=MalwareDownload,
                $msg=fmt("MALWARE DOWNLOAD | Attacker: %s | File: %s | HTTP %d",
                         src, uri, code),
                $src=src,
                $suppress_for=1min,
                $identifier=fmt("%s-%s-malware", src, uri)]);
    }
}

# SSH Brute Force
event ssh_auth_failed(c: connection) {
    local src = c$id$orig_h;
    ssh_tracker[src] += 1;

    if (ssh_tracker[src] == 5 || ssh_tracker[src] % 20 == 0) {
        NOTICE([$note=SSHBruteForce,
                $msg=fmt("SSH BRUTE FORCE | Attacker: %s | %d failed attempts on SSH Honeypot",
                         src, ssh_tracker[src]),
                $src=src,
                $suppress_for=1min,
                $identifier=fmt("%s-bf-%d", src, ssh_tracker[src])]);
    }
}

# SSH Login Success
event ssh_auth_successful(c: connection, auth_method_none: bool) {
    NOTICE([$note=SSHLoginSuccess,
            $msg=fmt("SSH LOGIN SUCCESS - HONEYPOT BREACHED | Attacker: %s | Honeypot: %s",
                     c$id$orig_h, c$id$resp_h),
            $src=c$id$orig_h,
            $suppress_for=1min,
            $identifier=fmt("%s-ssh-breach", c$id$orig_h)]);
}

# ICMP Ping Sweep
event icmp_echo_request(c: connection, info: icmp_info,
                        id: count, seq: count, payload: string) {
    if (!is_private(c$id$resp_h))
        return;

    local src = c$id$orig_h;
    icmp_tracker[src] += 1;

    if (icmp_tracker[src] == 3) {
        NOTICE([$note=PingSweep,
                $msg=fmt("PING SWEEP DETECTED | Attacker: %s | %d ICMP echo requests",
                         src, icmp_tracker[src]),
                $src=src,
                $suppress_for=1min,
                $identifier=fmt("%s-ping", src)]);
    }
}
