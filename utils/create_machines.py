import json
import random
from datetime import datetime, timedelta
import uuid
import ipaddress

def generate_random_agent(num_agents=5):
    agents = []
    for i in range(num_agents):
        agent_id = str(uuid.uuid4())[:8]
        hostname = f"host-{random.choice(['web', 'db', 'app', 'dev', 'prod'])}-{random.randint(1,100)}"
        ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
        
        # Status aleatório (apenas active ou inactive)
        status = random.choice(["active", "inactive"])
        
        # Data do último keepalive (1-30 dias atrás) - Sintaxe corrigida
        last_keepalive = (datetime.now() - timedelta(days=random.randint(1, 30))).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        
        # Gerar hardware aleatório
        cpu_models = ["Intel Xeon E5-2678", "AMD Ryzen 9 5950X", "Intel Core i9-12900K", 
                     "AMD EPYC 7763", "Apple M1 Max"]
        ram_sizes = [4, 8, 16, 32, 64, 128]
        
        hardware = {
            "cpu": {
                "cores": random.choice([2, 4, 8, 16, 32]),
                "mhz": random.randint(2000, 5000),
                "name": random.choice(cpu_models)
            },
            "ram": {
                "free": random.randint(1024, 32768) * 1024,
                "total": random.choice(ram_sizes) * 1024 * 1024,
                "usage": random.randint(10, 90)
            },
            "scan": {
                "id": 0,
                "time": last_keepalive
            },
            "board_serial": str(uuid.uuid4())[:8]
        }
        
        # Gerar OS aleatório
        os_versions = [
            {"name": "Ubuntu", "version": "22.04.3 LTS", "codename": "jammy"},
            {"name": "Ubuntu", "version": "24.04.2 LTS", "codename": "noble"},
            {"name": "CentOS", "version": "7.9.2009", "codename": ""},
            {"name": "CentOS", "version": "8.5.2111", "codename": ""},
            {"name": "Debian", "version": "11.6", "codename": "bullseye"},
            {"name": "Windows", "version": "10 Pro", "codename": ""},
            {"name": "Windows", "version": "Server 2022", "codename": ""}
        ]
        os_info = random.choice(os_versions)
        
        os_data = {
            "os": {
                "codename": os_info["codename"],
                "major": os_info["version"].split('.')[0] if '.' in os_info["version"] else "",
                "minor": os_info["version"].split('.')[1] if '.' in os_info["version"] and len(os_info["version"].split('.')) > 1 else "",
                "name": os_info["name"],
                "platform": os_info["name"].lower(),
                "version": os_info["version"] + (" (" + os_info["codename"] + ")" if os_info["codename"] else "")
            },
            "scan": {
                "id": 0,
                "time": last_keepalive
            },
            "hostname": hostname,
            "version": f"#{random.randint(50,200)}-{os_info['name']} SMP PREEMPT_DYNAMIC",
            "architecture": random.choice(["x86_64", "arm64", "amd64"]),
            "sysname": "Linux" if os_info["name"] != "Windows" else "Windows",
            "release": f"{random.randint(3,6)}.{random.randint(0,20)}.{random.randint(0,100)}-generic"
        }
        
        # Gerar portas aleatórias
        common_ports = [
            (80, "tcp", "nginx/apache"),
            (443, "tcp", "nginx/apache"),
            (22, "tcp", "sshd"),
            (3306, "tcp", "mysql"),
            (5432, "tcp", "postgresql"),
            (27017, "tcp", "mongodb"),
            (6379, "tcp", "redis"),
            (9200, "tcp", "elasticsearch"),
            (5601, "tcp", "kibana"),
            (8080, "tcp", "tomcat/webapp")
        ]
        
        ports = []
        num_ports = random.randint(3, 15)
        selected_ports = random.sample(common_ports, min(num_ports, len(common_ports)))
        
        for port, protocol, process in selected_ports:
            port_data = {
                "local": {
                    "ip": random.choice(["0.0.0.0", "127.0.0.1", ip]),
                    "port": port
                },
                "remote": {
                    "ip": "0.0.0.0",
                    "port": 0
                },
                "scan": {
                    "id": 0,
                    "time": last_keepalive
                },
                "state": random.choice(["listening", "established", "time_wait"]),
                "tx_queue": random.randint(0, 100),
                "pid": random.randint(100, 5000),
                "inode": random.randint(1000, 20000),
                "rx_queue": random.randint(0, 100),
                "process": process,
                "protocol": protocol
            }
            ports.append(port_data)
        
        # Gerar interfaces de rede aleatórias
        iface_types = ["ethernet", "wifi", "vpn", "bridge", "docker"]
        num_ifaces = random.randint(1, 5)
        ifaces = []
        netaddrs = []
        netprotos = []
        
        for j in range(num_ifaces):
            iface_name = f"eth{j}" if j == 0 else random.choice([
                f"eth{j}", f"wlan{j}", f"vpn{j}", 
                f"br-{str(uuid.uuid4())[:8]}", 
                f"veth{str(uuid.uuid4())[:8]}"
            ])
            mac = ":".join([f"{random.randint(0,255):02x}" for _ in range(6)])
            
            # Gerar endereços IP
            ipv4 = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            ipv6 = f"fe80::{random.randint(0,65535):x}:{random.randint(0,65535):x}:{random.randint(0,65535):x}:{random.randint(0,65535):x}"
            
            netaddr_ipv4 = {
                "scan": {"id": 0},
                "address": ipv4,
                "proto": "ipv4",
                "iface": iface_name,
                "broadcast": f"10.{random.randint(0,255)}.{random.randint(0,255)}.255",
                "netmask": "255.255.255.0"
            }
            
            netaddr_ipv6 = {
                "scan": {"id": 0},
                "address": ipv6,
                "proto": "ipv6",
                "iface": iface_name,
                "netmask": "ffff:ffff:ffff:ffff::"
            }
            
            netaddrs.extend([netaddr_ipv4, netaddr_ipv6])
            
            # Gerar protocolos de rede
            netproto_ipv4 = {
                "scan": {"id": 0},
                "dhcp": random.choice(["enabled", "disabled", "unknown"]),
                "type": "ipv4",
                "iface": iface_name,
                "gateway": f"10.{random.randint(0,255)}.{random.randint(0,255)}.1"
            }
            
            netproto_ipv6 = {
                "scan": {"id": 0},
                "dhcp": random.choice(["enabled", "disabled", "unknown"]),
                "type": "ipv6",
                "iface": iface_name,
                "gateway": "::"
            }
            
            netprotos.extend([netproto_ipv4, netproto_ipv6])
            
            # Gerar estatísticas de interface
            rx_bytes = random.randint(1000, 100000000)
            tx_bytes = random.randint(1000, 100000000)
            
            iface = {
                "rx": {
                    "bytes": rx_bytes,
                    "dropped": random.randint(0, 100),
                    "errors": random.randint(0, 50),
                    "packets": random.randint(100, 10000)
                },
                "scan": {
                    "id": 0,
                    "time": last_keepalive
                },
                "tx": {
                    "bytes": tx_bytes,
                    "dropped": random.randint(0, 100),
                    "errors": random.randint(0, 50),
                    "packets": random.randint(100, 10000)
                },
                "name": iface_name,
                "type": random.choice(iface_types),
                "mac": mac,
                "state": random.choices(["up", "down"], weights=[8, 1])[0],
                "mtu": random.choice([1500, 9000, 1492])
            }
            ifaces.append(iface)
        
        # Criar estrutura final do agente
        agent = {
            "agent_info": {
                "os": {
                    "name": os_info["name"],
                    "platform": os_info["name"].lower(),
                    "version": os_info["version"]
                },
                "status": status,
                "ip": ip,
                "name": hostname,
                "id": agent_id,
                "lastKeepAlive": last_keepalive,
                "calculated_status": "Ligado" if status == "active" else "Desligado"
            },
            "inventory": {
                "hardware": [hardware],
                "os": [os_data],
                "ports": ports,
                "netaddr": netaddrs,
                "netiface": ifaces,
                "netproto": netprotos
            }
        }
        
        agents.append(agent)
    
    return agents

# Gerar 5 agentes aleatórios
random_agents = generate_random_agent(30)

# Salvar cada agente em um arquivo JSON separado
for i, agent in enumerate(random_agents, 1):
    filename = f"agent_{i}.json"
    with open(filename, 'w') as f:
        json.dump(agent, f, indent=4)
    print(f"Arquivo {filename} gerado com sucesso!")

print("\nTodos os arquivos foram gerados com sucesso!")
