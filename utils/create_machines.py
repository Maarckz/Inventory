#############################################
## Gerador de arquivos JSON de inventário ##
## Compatível com schema do SOC1.json     ##
#############################################

import json
import random
from datetime import datetime, timezone
import uuid

FAKE_PACKAGES = [f"package-{i}" for i in range(1, 300)]
FAKE_PROCESSES = [f"proc{i}" for i in range(1, 300)]

def gerar_agente():
    # Data UTC com timezone-aware
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
    os_info = random.choice([
        {"name": "Ubuntu", "version": "24.04.2 LTS", "platform": "ubuntu", "codename": "noble"},
        {"name": "Debian", "version": "12.1",     "platform": "debian", "codename": "bookworm"},
        {"name": "CentOS", "version": "8.5.2111", "platform": "centos", "codename": ""},
        {"name": "Windows", "version": "10 Pro", "platform": "windows", "codename": ""},
        {"name": "Windows", "version": "Server 2022", "platform": "windows", "codename": ""},
        {"name": "RHEL", "version": "9.0", "platform": "rhel", "codename": ""},
        {"name": "Fedora", "version": "36", "platform": "fedora", "codename": ""},
        {"name": "openSUSE", "version": "15.4", "platform": "opensuse", "codename": ""},
    ])

    agent_id = str(uuid.uuid4())[:8]
    hostname = f"host-{random.randint(100, 999)}"
    ip = f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
    status = random.choice(["active", "inactive"])

    agent_info = {
        "agent_info": {
            "os": {
                "name": os_info["name"],
                "platform": os_info["platform"],
                "version": os_info["version"]
            },
            "id": agent_id,
            "ip": ip,
            "name": hostname,
            "status": status,
            "lastKeepAlive": now,
            "calculated_status": "Ligado" if status == "active" else "Desligado"
        }
    }

    hardware = [{
        "cpu": {
            "cores": random.choice([2, 4, 8]),
            "mhz": random.randint(1800, 3800),
            "name": random.choice([
                "Intel Xeon", "AMD Ryzen 7", "Intel i5", "Intel i9", "AMD EPYC",
                "AMD Ryzen Threadripper", "Intel Core i7", "AMD Ryzen 5", "Intel Core i3"
            ])
        },
        "ram": {
            "free": random.randint(500_000, 2_000_000),
            "total": random.choice([4, 8, 16, 32, 64, 128]) * 1024 * 1024,
            "usage": random.randint(20, 95)
        },
        "scan": {
            "id": 0,
            "time": now
        },
        "board_serial": str(uuid.uuid4())[:8]
    }]
#
    os_block = [{
        "os": {
            "codename": os_info["codename"],
            "major": os_info["version"].split(".")[0],
            "minor": os_info["version"].split(".")[1] if len(os_info["version"].split(".")) > 1 else "",
            "name": os_info["name"],
            "platform": os_info["platform"],
            "version": f"{os_info['version']} ({os_info['codename'].capitalize()})"
        },
        "scan": {
            "id": 0,
            "time": now
        },
        "version": f"#{random.randint(60, 100)}-{os_info['name']} SMP PREEMPT_DYNAMIC",
        "architecture": random.choice(["x86_64", "arm64"]),
        "sysname": "Linux",
        "hostname": hostname,
        "release": f"{random.randint(5,6)}.{random.randint(0,19)}.{random.randint(0,99)}-generic"
    }]

    packages = []
    for _ in range(200):
        pkg = random.choice(FAKE_PACKAGES)
        packages.append({
            "scan": {
                "id": 0,
                "time": now
            },
            "version": f"{random.randint(1,10)}.{random.randint(0,99)}",
            "description": f"{pkg} package description",
            "source": pkg,
            "architecture": random.choice(["amd64", "all"]),
            "vendor": "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
            "location": "/",
            "section": random.choice(["utils", "admin", "python", "libs"]),
            "size": random.randint(10_000, 500_000),
            "install_time": now,
            "format": random.choice(["deb", "pypi"]),
            "name": pkg,
            "multiarch": "foreign",
            "priority": random.choice(["optional", "required", "standard"])
        })

    processes = []
    for _ in range(181):
        name = random.choice(FAKE_PROCESSES)
        processes.append({
            "pid": random.randint(100, 9_999),
            "ppid": random.randint(1, 50),
            "user": random.choice(["root", "syslog", "www-data", "ubuntu"]),
            "name": name,
            "cmd": f"/usr/bin/{name} --option",
            "cpu": round(random.uniform(0.0, 10.0), 2),
            "mem": round(random.uniform(0.0, 5.0), 2),
            "scan": {
                "id": 0,
                "time": now
            }
        })

    netiface = []
    for i in range(10):
        name = f"eth{i}"
        netiface.append({
            "name": name,
            "type": random.choice(["ethernet", "wifi"]),
            "mac": ":".join(f"{random.randint(0,255):02x}" for _ in range(6)),
            "state": random.choice(["up", "down"]),
            "mtu": 1500,
            "rx": {
                "bytes": random.randint(10_000, 10_000_000),
                "dropped": random.randint(0, 10),
                "errors": 0,
                "packets": random.randint(1_000, 1_000_000)
            },
            "tx": {
                "bytes": random.randint(10_000, 10_000_000),
                "dropped": 0,
                "errors": 0,
                "packets": random.randint(1_000, 1_000_000)
            },
            "scan": {
                "id": 0,
                "time": now
            }
        })

    netaddr = []
    for i in range(10):
        netaddr.append({
            "scan": {"id": 0},
            "address": f"192.168.1.{i+1}",
            "proto": "ipv4",
            "iface": f"eth{i}",
            "broadcast": "192.168.1.255",
            "netmask": "255.255.255.0"
        })

    netproto = []
    for i in range(13):
        netproto.append({
            "scan": {"id": 0},
            "dhcp": random.choice(["enabled", "disabled"]),
            "type": "ipv4",
            "iface": f"eth{i%10}",
            "gateway": "192.168.1.1"
        })

    ports = []
    for _ in range(20):
        ports.append({
            "local": {
                "ip": "0.0.0.0",
                "port": random.choice([22, 80, 443, 3306, 5432, 6379, 5000])
            },
            "remote": {
                "ip": "0.0.0.0",
                "port": 0
            },
            "scan": {
                "id": 0,
                "time": now
            },
            "state": random.choice(["listening", "established"]),
            "tx_queue": 0,
            "pid": random.randint(100, 9_999),
            "inode": random.randint(1_000, 10_000),
            "rx_queue": 0,
            "process": random.choice(["nginx", "sshd", "postgres", "python", "redis-server", "httpd", "mysqld", "apache2", "node", "java", "celery"]),
            "protocol": random.choice(["tcp", "udp"])
        })

    agent_info["inventory"] = {
        "hardware":  hardware,
        "os":        os_block,
        "packages":  packages,
        "processes": processes,
        "netiface":  netiface,
        "netaddr":   netaddr,
        "netproto":  netproto,
        "ports":     ports
    }

    return agent_info

if __name__ == "__main__":
    for i in range(1, 25):
        a = gerar_agente()
        with open(f"../data/inventory/agent_{i}.json", "w") as f:
            json.dump(a, f, indent=4)
        print(f"[✓] agent_{i}.json salvo.")
