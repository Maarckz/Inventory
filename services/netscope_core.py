
import json
import threading
from datetime import datetime

def _plausible_hostname(name, ip=''):
    if not name:
        return False
    n = name.strip().rstrip('.').lower()
    if not n or len(n) > 253:
        return False
    if n.endswith('.in-addr.arpa') or n.endswith('.ip6.arpa'):
        return False
    if not any(c.isalpha() for c in n):
        return False
    if ip and n == str(ip).strip().lower():
        return False
    return True

def _implausible(name):
    return not _plausible_hostname(name)

OUI = {
    '000C29':'VMware','005056':'VMware','001C14':'VMware',
    '00C0CA':'Cisco','00D0B7':'Cisco','00236B':'Cisco',
    'F4CE46':'Cisco','C0A00D':'Cisco','B4A984':'Cisco',
    '001A2B':'Apple','0023AE':'Apple','00256B':'Apple',
    '0C4D1A':'Apple','108008':'Apple','18C04D':'Apple',
    '28CFDA':'Apple','3C22FB':'Apple','A4B197':'Apple',
    'A0F1C5':'Apple','AC87A3':'Apple',
    '001124':'Google','3C5AB4':'Google','FCC233':'Google',
    '0017F2':'Google','6470A1':'Google','D8FEF6':'Google',
    '002243':'Cisco','0021A0':'Cisco','00260B0':'Cisco',
    '001EE5':'Cisco','000BCD':'Cisco',
    'F45EAB':'Tp-Link','50BD5F':'Tp-Link','C006C3':'Tp-Link',
    '50C7BF':'Tp-Link','14CC20':'Tp-Link','18A6F7':'Tp-Link',
    '0024E4':'Tp-Link','002719':'Tp-Link','EC086B':'Tp-Link',
    '000F86':'Tp-Link','002195':'Tp-Link',
    '0418D6':'Ubiquiti','00B3FA':'Ubiquiti','04E8D2':'Ubiquiti',
    '24A43C':'Ubiquiti','245A4C':'Ubiquiti','44D9E7':'Ubiquiti',
    '687234':'Ubiquiti','784558':'Ubiquiti','788A20':'Ubiquiti',
    '802AA8':'Ubiquiti','9C05D6':'Ubiquiti','B4FBE4':'Ubiquiti',
    'E063DA':'Ubiquiti','ECE348':'Ubiquiti','F0272D':'Ubiquiti',
    'F92129':'Ubiquiti','FC5733':'Ubiquiti',
    '0012EB':'Intel','0019D1':'Intel','001B21':'Intel',
    '00215C':'Intel','00265C':'Intel','0024D6':'Intel',
    '0050B6':'Intel','009027':'Intel','00A0C6':'Intel',
    '00C0CA':'Intel','00CE2B':'Intel','00E018':'Intel',
    '0013CE':'Intel','0014A8':'Intel','001517':'Intel',
    '00173A':'Intel','0019D2':'Intel','001B77':'Intel',
    '001E64':'Intel','001F3B':'Intel','0020E6':'Intel',
    '002191':'Intel','0022FA':'Intel','0024D0':'Intel',
    '0026C7':'Intel','002710':'Intel','00293A':'Intel',
    'DC0EA1':'Asus','0026B7':'Asus','E89D87':'Asus',
    '0090F5':'Asus','00E0CC':'Asus','0CC2C0':'Asus',
    '40167E':'Asus','48E244':'Asus','54145C':'Asus',
    '60EB69':'Asus','6470B6':'Asus','7445FD':'Asus',
    'A0CEC8':'Asus','AC9E17':'Asus','B8551A':'Asus',
    'C86000':'Asus','D8D090':'Asus','E0E7A2':'Asus',
    'F0CC7D':'Asus',
    'F46D04':'D-Link','00055D':'D-Link','000CDB':'D-Link',
    '000D88':'D-Link','001195':'D-Link','001346':'D-Link',
    '001599':'D-Link','00179A':'D-Link','001B11':'D-Link',
    '001CF0':'D-Link','001E58':'D-Link','002196':'D-Link',
    '0022B0':'D-Link','002401':'D-Link','00265A':'D-Link',
    'B05FB8':'Dell','0023AE7':'Dell','F8DBF8':'Dell',
    '00B0D0':'Dell','001C23':'Dell','0019B9':'Dell',
    'F8B156':'Dell','D4AE52':'Dell','E4B297':'Dell',
    '005056':'Dell','0014C2':'Dell','00219B':'Dell',
    'B8CA3A':'Dell','14FEB7':'Dell','18A905':'Dell',
    '1CB76A':'Dell','20A3F0':'Dell','24FD0F':'Dell',
    '28F55E':'Dell','2C4D54':'Dell','302F1E':'Dell',
    '34E6D7':'Dell','3CA9F4':'Dell','442A60':'Dell',
    '504B6E':'Dell','54BF01':'Dell','58AC67':'Dell',
    '5C2DE0':'Dell','6032B7':'Dell','641950':'Dell',
    '689C5E':'Dell','708873':'Dell','74E543':'Dell',
    '78C5E5':'Dell','7C0CE0':'Dell','805E0C':'Dell',
    '843893':'Dell','88518E':'Dell','8C8C28':'Dell',
    '90B11E':'Dell','94C16E':'Dell','98288B':'Dell',
    '9CC2E4':'Dell','A00460':'Dell','A4BADB':'Dell',
    'A8E049':'Dell','AC16B2':'Dell','B0FAEB':'Dell',
    'B4B62F':'Dell','BC305D':'Dell','C0E786':'Dell',
    'C8D78A':'Dell','CCD8FC':'Dell','D06FB3':'Dell',
    'D4F07D':'Dell','DCD7B4':'Dell','E0DB55':'Dell',
    'E447C7':'Dell','E8AE3F':'Dell','ECB1D7':'Dell',
    'F0155E':'Dell','F40D78':'Dell','F831C4':'Dell',
    'FCD0F0':'Dell',
    '000BCD':'HP','001702':'HP','0017A4':'HP','001B78':'HP',
    '001EC9':'HP','001FE0':'HP','00237D':'HP','002608':'HP',
    '002696':'HP','002720':'HP','00270D':'HP','002A0E':'HP',
    '002C76':'HP','003018':'HP','003BA7':'HP','0050FE':'HP',
    '006008':'HP','006B9E':'HP','0081ED':'HP','0090FB':'HP',
    '00A073':'HP','00B0C8':'HP','00B1E6':'HP','00C0EE':'HP',
    '00CAE5':'HP','00E081':'HP','00E091':'HP','00E0BB':'HP',
    '0CC324':'HP','1008B1':'HP','145233':'HP','148F1F':'HP',
    '14F0B4':'HP','180014':'HP','1C2D8B':'HP','1C659D':'HP',
    '1CC1DE':'HP','20026F':'HP','203C88':'HP','24B620':'HP',
    '28C033':'HP','2C97A0':'HP','300926':'HP','30146F':'HP',
    '30500B':'HP','30D673':'HP','340A33':'HP','346488':'HP',
    '3818A4':'HP','3C0E23':'HP','3C5A37':'HP','3CD098':'HP',
    '3CE1A1':'HP','401F6A':'HP','40B387':'HP','442A60':'HP',
    '481FCC':'HP','4C1F33':'HP','4C7A6F':'HP','4CE376':'HP',
    '50259F':'HP','509A4C':'HP','543695':'HP','581549':'HP',
    '5C8AA8':'HP','5CC3C7':'HP','601855':'HP','604A8C':'HP',
    '640711':'HP','647630':'HP','685B35':'HP','6888CA':'HP',
    '6CE04A':'HP','7001A6':'HP','70107B':'HP','7444F2':'HP',
    '781580':'HP','789E11':'HP','7C0ECE':'HP','7C2B23':'HP',
    '80167F':'HP','801AB5':'HP','842914':'HP','848E0C':'HP',
    '8493F1':'HP','84A938':'HP','881AAE':'HP','8C3371':'HP',
    '8C8C28':'HP','900B9A':'HP','902B34':'HP','907010':'HP',
    '940AC0':'HP','943AC6':'HP','944D80':'HP','946979':'HP',
    '9482BC':'HP','949ECD':'HP','98AC15':'HP','988335':'HP',
    '9C1F84':'HP','9C2A70':'HP','9CB6D0':'HP','A00460':'HP',
    'A01A5C':'HP','A036BC':'HP','A04891':'HP','A07339':'HP',
    'A0AE94':'HP','A434D9':'HP','A4BADB':'HP','A81758':'HP',
    'A82066':'HP','A848FA':'HP','AC1F74':'HP','AC3F19':'HP',
    'B0098B':'HP','B04E26':'HP','B4B62F':'HP','B85066':'HP',
    'BC0A22':'HP','BC30BB':'HP','C006C3':'HP','C0FBF9':'HP',
    'C434CD':'HP','C46EDC':'HP','C8138B':'HP','C8D7B0':'HP',
    'CC52AF':'HP','D08C7B':'HP','D0B47B':'HP','D48C5D':'HP',
    'D4AE52':'HP','D85E8C':'HP','DCD0F7':'HP','E01584':'HP',
    'E0B6F5':'HP','E4369B':'HP','E81513':'HP','EC2C8E':'HP',
    'F009C8':'HP','F40D78':'HP','FC3D93':'HP',
    '000C29':'VMware','005056':'VMware','001C14':'VMware',
    'E84F10':'Amazon','40B4CD':'Amazon','FCA183':'Amazon',
    '442A32':'Amazon','747548':'Amazon','74C246':'Amazon',
    'AC84C6':'Amazon','685456':'Amazon','F0D1A9':'Amazon',
    '000B82':'Mikrotik','001500':'Mikrotik','0017E0':'Mikrotik',
    '001946':'Mikrotik','002214':'Mikrotik','0040B0':'Mikrotik',
    '004924':'Mikrotik','005017':'Mikrotik','005008':'Mikrotik',
    '005014':'Mikrotik','005020':'Mikrotik','0050BA':'Mikrotik',
    '005003':'Mikrotik','005007':'Mikrotik','00500C':'Mikrotik',
    '00500E':'Mikrotik','00500F':'Mikrotik','005023':'Mikrotik',
    '005024':'Mikrotik','00503F':'Mikrotik','005043':'Mikrotik',
    '005049':'Mikrotik','00504C':'Mikrotik','00504D':'Mikrotik',
    '005068':'Mikrotik','00507F':'Mikrotik','00509C':'Mikrotik',
    '0050C2':'Mikrotik','0050DA':'Mikrotik','0050F8':'Mikrotik',
    '0050FE':'Mikrotik','005104':'Mikrotik','005108':'Mikrotik',
    '005118':'Mikrotik','005137':'Mikrotik','00513B':'Mikrotik',
    '00513E':'Mikrotik','005142':'Mikrotik','00514C':'Mikrotik',
    '005152':'Mikrotik','005167':'Mikrotik','00516B':'Mikrotik',
    '00517E':'Mikrotik','005180':'Mikrotik','00518C':'Mikrotik',
    '0051AE':'Mikrotik','0051B4':'Mikrotik','0051C9':'Mikrotik',
    '0051CE':'Mikrotik','0051E1':'Mikrotik','0051E5':'Mikrotik',
    '0051FA':'Mikrotik','005203':'Mikrotik','005209':'Mikrotik',
    '00521D':'Mikrotik','005223':'Mikrotik','00522F':'Mikrotik',
    '005244':'Mikrotik','005254':'Mikrotik','005255':'Mikrotik',
    '00525F':'Mikrotik','005263':'Mikrotik','005268':'Mikrotik',
    '005272':'Mikrotik','005276':'Mikrotik','00527B':'Mikrotik',
    '00528F':'Mikrotik','005298':'Mikrotik','00529F':'Mikrotik',
    '0052A8':'Mikrotik','0052AC':'Mikrotik','0052B2':'Mikrotik',
    '0052C1':'Mikrotik','0052C2':'Mikrotik','0052CE':'Mikrotik',
    '0052D6':'Mikrotik','0052E6':'Mikrotik','0052F6':'Mikrotik',
    '00530A':'Mikrotik','00530E':'Mikrotik','005317':'Mikrotik',
    '005326':'Mikrotik','00532F':'Mikrotik','005338':'Mikrotik',
    '005340':'Mikrotik','00534A':'Mikrotik','005352':'Mikrotik',
    '00535A':'Mikrotik','005364':'Mikrotik','005366':'Mikrotik',
    '00536E':'Mikrotik','005379':'Mikrotik','00538D':'Mikrotik',
    '005392':'Mikrotik','0053A0':'Mikrotik','0053A8':'Mikrotik',
    '0053B0':'Mikrotik','0053B5':'Mikrotik','0053B8':'Mikrotik',
    '0053C0':'Mikrotik','0053C5':'Mikrotik','0053C9':'Mikrotik',
    '0053D0':'Mikrotik','0053D6':'Mikrotik','0053DF':'Mikrotik',
    '0053E6':'Mikrotik','0053F0':'Mikrotik','0053F4':'Mikrotik',
    '0053FA':'Mikrotik','005401':'Mikrotik','00540A':'Mikrotik',
    '005410':'Mikrotik','005415':'Mikrotik','00541B':'Mikrotik',
    '005421':'Mikrotik','005428':'Mikrotik','00542F':'Mikrotik',
    '005439':'Mikrotik','005442':'Mikrotik','005449':'Mikrotik',
    '00544D':'Mikrotik','005455':'Mikrotik','00545E':'Mikrotik',
    '005462':'Mikrotik','005467':'Mikrotik','00546F':'Mikrotik',
    '005479':'Mikrotik','00547E':'Mikrotik','005481':'Mikrotik',
    '005485':'Mikrotik','00548D':'Mikrotik','005493':'Mikrotik',
    '00549D':'Mikrotik','0054A0':'Mikrotik','0054A4':'Mikrotik',
    '0054AC':'Mikrotik','0054B3':'Mikrotik','0054BC':'Mikrotik',
    '0054C1':'Mikrotik','0054C6':'Mikrotik','0054C9':'Mikrotik',
    '0054D1':'Mikrotik','0054DA':'Mikrotik','0054DD':'Mikrotik',
    '0054E5':'Mikrotik','0054EB':'Mikrotik','0054F2':'Mikrotik',
    '0054F7':'Mikrotik','0054F9':'Mikrotik','0054FE':'Mikrotik',
    '005501':'Mikrotik','005505':'Mikrotik','00550A':'Mikrotik',
    '00550F':'Mikrotik','005514':'Mikrotik','005519':'Mikrotik',
    '00551D':'Mikrotik','005522':'Mikrotik','005528':'Mikrotik',
    '00552C':'Mikrotik','005533':'Mikrotik','005538':'Mikrotik',
    '00553F':'Mikrotik','005544':'Mikrotik','005548':'Mikrotik',
    '00554D':'Mikrotik','005553':'Mikrotik','005556':'Mikrotik',
    '00555B':'Mikrotik','005560':'Mikrotik','005563':'Mikrotik',
    '005567':'Mikrotik','00556C':'Mikrotik','005570':'Mikrotik',
    '005576':'Mikrotik','00557B':'Mikrotik','00557F':'Mikrotik',
    '005584':'Mikrotik','005588':'Mikrotik','00558D':'Mikrotik',
    '005591':'Mikrotik','005595':'Mikrotik','00559A':'Mikrotik',
    '00559E':'Mikrotik','0055A2':'Mikrotik','0055A6':'Mikrotik',
    '0055AA':'Mikrotik','0055AE':'Mikrotik','0055B2':'Mikrotik',
    '0055B6':'Mikrotik','0055BA':'Mikrotik','0055BE':'Mikrotik',
    '0055C2':'Mikrotik','0055C6':'Mikrotik','0055CA':'Mikrotik',
    '0055CE':'Mikrotik','0055D2':'Mikrotik','0055D6':'Mikrotik',
    '0055DA':'Mikrotik','0055DE':'Mikrotik','0055E2':'Mikrotik',
    '0055E6':'Mikrotik','0055EA':'Mikrotik','0055EE':'Mikrotik',
    '0055F2':'Mikrotik','0055F6':'Mikrotik','0055FA':'Mikrotik',
    '0055FE':'Mikrotik','005602':'Mikrotik','005606':'Mikrotik',
    '00560A':'Mikrotik','00560E':'Mikrotik','005612':'Mikrotik',
    '005616':'Mikrotik','00561A':'Mikrotik','00561E':'Mikrotik',
    '005622':'Mikrotik','005626':'Mikrotik','00562A':'Mikrotik',
    '00562E':'Mikrotik','005632':'Mikrotik','005636':'Mikrotik',
    '00563A':'Mikrotik','00563E':'Mikrotik','005642':'Mikrotik',
    '005646':'Mikrotik','00564A':'Mikrotik','00564E':'Mikrotik',
    '005652':'Mikrotik','005656':'Mikrotik','00565A':'Mikrotik',
    '00565E':'Mikrotik','005662':'Mikrotik','005666':'Mikrotik',
    '00566A':'Mikrotik','00566E':'Mikrotik','005672':'Mikrotik',
    '005676':'Mikrotik','00567A':'Mikrotik','00567E':'Mikrotik',
    '005682':'Mikrotik','005686':'Mikrotik','00568A':'Mikrotik',
    '00568E':'Mikrotik','005692':'Mikrotik','005696':'Mikrotik',
    '00569A':'Mikrotik','00569E':'Mikrotik','0056A2':'Mikrotik',
    '0056A6':'Mikrotik','0056AA':'Mikrotik','0056AE':'Mikrotik',
    '0056B2':'Mikrotik','0056B6':'Mikrotik','0056BA':'Mikrotik',
    '0056BE':'Mikrotik','0056C2':'Mikrotik','0056C6':'Mikrotik',
    '0056CA':'Mikrotik','0056CE':'Mikrotik','0056D2':'Mikrotik',
    '0056D6':'Mikrotik','0056DA':'Mikrotik','0056DE':'Mikrotik',
    '0056E2':'Mikrotik','0056E6':'Mikrotik','0056EA':'Mikrotik',
    '0056EE':'Mikrotik','0056F2':'Mikrotik','0056F6':'Mikrotik',
    '0056FA':'Mikrotik','0056FE':'Mikrotik','005702':'Mikrotik',
    '005706':'Mikrotik','00570A':'Mikrotik','00570E':'Mikrotik',
    '005712':'Mikrotik','005716':'Mikrotik','00571A':'Mikrotik',
    '00571E':'Mikrotik','005722':'Mikrotik','005726':'Mikrotik',
    '00572A':'Mikrotik','00572E':'Mikrotik','005732':'Mikrotik',
    '005736':'Mikrotik','00573A':'Mikrotik','00573E':'Mikrotik',
    '005742':'Mikrotik','005746':'Mikrotik','00574A':'Mikrotik',
    '00574E':'Mikrotik','005752':'Mikrotik','005756':'Mikrotik',
    '00575A':'Mikrotik','00575E':'Mikrotik','005762':'Mikrotik',
    '005766':'Mikrotik','00576A':'Mikrotik','00576E':'Mikrotik',
    '005772':'Mikrotik','005776':'Mikrotik','00577A':'Mikrotik',
    '00577E':'Mikrotik','005782':'Mikrotik','005786':'Mikrotik',
    '00578A':'Mikrotik','00578E':'Mikrotik','005792':'Mikrotik',
    '005796':'Mikrotik','00579A':'Mikrotik','00579E':'Mikrotik',
    '0057A2':'Mikrotik','0057A6':'Mikrotik','0057AA':'Mikrotik',
    '0057AE':'Mikrotik','0057B2':'Mikrotik','0057B6':'Mikrotik',
    '0057BA':'Mikrotik','0057BE':'Mikrotik','0057C2':'Mikrotik',
    '0057C6':'Mikrotik','0057CA':'Mikrotik','0057CE':'Mikrotik',
    '0057D2':'Mikrotik','0057D6':'Mikrotik','0057DA':'Mikrotik',
    '0057DE':'Mikrotik','0057E2':'Mikrotik','0057E6':'Mikrotik',
    '0057EA':'Mikrotik','0057EE':'Mikrotik','0057F2':'Mikrotik',
    '0057F6':'Mikrotik','0057FA':'Mikrotik','0057FE':'Mikrotik',
}

def guess_vendor(mac):
    oui = mac.replace(':', '').replace('-', '').upper()[:6]
    return OUI.get(oui, '')

def infer_type(ip, vendor='', gateway=None, os_platform=''):
    if gateway and ip == gateway:
        return 'router'
    if ip and ip.endswith('.1'):
        return 'router'
    v = (vendor or '').lower()
    kw = {
        'router': ['cisco', 'juniper', 'mikrotik', 'ubiquiti', 'tp-link', 'fortinet', 'arista', 'gateway', 'meraki'],
        'switch': ['cisco catalyst', 'cisco nexus', 'hp procurve', 'aruba', 'dell powerconnect', 'netgear prosafe', 'tp-link tl-sg', 'tp-link t1600', 'juniper ex'],
        'ap': ['unifi', 'meraki', 'ruckus', 'aruba', 'access point'],
        'firewall': ['fortigate', 'pfsense', 'opnsense', 'sonicwall', 'sophos', 'firewall', 'watchguard', 'pal alto', 'paloalto'],
        'loadbalancer': ['f5 ', 'big-ip', 'bigip', 'load balancer', 'loadbalancer', 'kemp', 'haproxy'],
        'hypervisor': ['esxi', 'vcenter', 'proxmox', 'hyper-v', 'xenserver', 'xcp-ng', 'hypervisor', 'kvm'],
        'server': ['server', 'servidor', 'poweredge', 'proliant', 'thinksystem'],
        'voip': ['voip', 'grandstream', 'yealink', 'polycom', 'snom', 'cisco spa', 'ip phone'],
        'tablet': ['ipad', 'tablet', 'galaxy tab'],
        'phone': ['iphone', 'samsung', 'huawei', 'xiaomi', 'pixel', 'motorola'],
        'smarttv': ['android tv', 'smart tv', 'roku', 'chromecast', 'lg electronics'],
        'printer': ['hp ', 'brother', 'canon', 'epson', 'xerox', 'printer'],
        'camera': ['hikvision', 'dahua', 'axis', 'reolink'],
        'nas': ['synology', 'qnap', 'western digital', 'buffalo', 'netgear'],
        'iot': ['arduino', 'esp32', 'esp8266', 'sonoff', 'tuya', 'smart plug', 'alexa', 'echo dot', 'shelly', 'iot'],
        'rpi': ['raspberry pi'],
    }
    for dtype, keywords in kw.items():
        if any(k in v for k in keywords):
            return dtype
    if os_platform:
        op = os_platform.lower()
        if any(k in op for k in ('esxi', 'proxmox', 'hyper-v', 'xenserver', 'xcp-ng', 'hypervisor')):
            return 'hypervisor'
        if 'vmware' in op:
            return 'vm'
    return 'desktop'

def gen_mac():

    import random
    return ':'.join(f'{random.randint(0, 255):02x}' for _ in range(6))

def _ip_sort_key(raw_ip):

    ip = str(raw_ip or '').strip()
    if not ip or ip == '0.0.0.0':
        return (0, ())
    try:
        octets = tuple(int(o) for o in ip.split('.'))
    except ValueError:
        return (0, ())
    if not octets:
        return (0, ())
    return (1, octets)

def gen_uid():

    import uuid
    return 'id-' + uuid.uuid4().hex[:8]

def dev_key(dev):

    if not isinstance(dev, dict):
        return ''
    return (dev.get('uid') or dev.get('mac') or '').lower()

def normalize_mac(value):

    raw = (value or '').strip().lower()
    if not raw:
        return '', None
    compact = raw.replace(':', '').replace('-', '').replace('.', '')
    if len(compact) != 12 or any(c not in '0123456789abcdef' for c in compact):
        return raw, 'MAC inv\u00e1lido — use o formato AA:BB:CC:DD:EE:FF'
    return ':'.join(compact[i:i + 2] for i in range(0, 12, 2)), None

def mac_from_agent(agent_id):

    import hashlib
    h = hashlib.md5(str(agent_id).encode()).hexdigest()[:12]
    return ':'.join(f'{int(h[i:i+2], 16):02x}' for i in range(0, 12, 2))

DEFAULT_CONFIG = {
    "networks": [],
    "scan": {"timeout": 1, "workers": 64},
    "auto_scan": {"enabled": False, "interval_minutes": 5},
    "arp_monitor": {"enabled": True, "interval_minutes": 5},
    "ports": {
        "21": "FTP", "22": "SSH", "23": "Telnet", "53": "DNS",
        "80": "HTTP", "443": "HTTPS", "161": "SNMP", "3306": "MySQL",
        "3389": "RDP", "5432": "PostgreSQL", "5900": "VNC",
        "6379": "Redis", "8080": "HTTP-Alt", "8443": "HTTPS-Alt"
    },
    "port_timeout": 0.3,
    "port_scan": {"workers": 512, "tcp_timeout": 0.3,
                  "udp_timeout": 0.5, "banner": True},
    "switches": {}
}

CONFIG_KEY = 'netscope_config'

def _pg_models():

    from models import db, NetscopeDevice, NetscopeSetting
    return db, NetscopeDevice, NetscopeSetting

def load_config():
    cfg = None
    try:
        from models import NetscopeSetting
        row = NetscopeSetting.query.filter_by(key=CONFIG_KEY).first()
        if row:
            cfg = row.value
    except Exception:
        cfg = None
    if cfg is None:
        cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    for k, v in DEFAULT_CONFIG.items():
        if k not in cfg:
            cfg[k] = json.loads(json.dumps(v))
    return cfg

def save_config(cfg):
    from models import db, NetscopeSetting
    row = NetscopeSetting.query.filter_by(key=CONFIG_KEY).first()
    if row:
        row.value = cfg
    else:
        db.session.add(NetscopeSetting(key=CONFIG_KEY, value=cfg))
    db.session.commit()

def _parse_dt(iso):
    if not iso:
        return None
    try:
        return datetime.fromisoformat(str(iso))
    except (ValueError, TypeError):
        return None

ASSET_FIELDS = (
    'user', 'department', 'location', 'asset_tag',
    'vendor', 'model', 'serial_number', 'os', 'seal_number',
)

AGENT_FIELDS = ('has_agent', 'agent_id', 'agent_name', 'agent_status',
                'agent_last_keepalive', 'agent_groups', 'agent_ip')

class Store:

    def __init__(self):
        self._cache = None
        self._lock = threading.RLock()

    def _load(self):
        if self._cache is not None:
            return self._cache
        try:
            from models import NetscopeDevice
            rows = NetscopeDevice.query.all()
            devices = []
            for r in rows:
                dev = dict(r.data) if isinstance(r.data, dict) else {}
                dev.setdefault('mac', (r.mac or '').lower())
                if not dev.get('uid'):
                    dev['uid'] = dev['mac'] or gen_uid()
                devices.append(dev)
            self._cache = {'devices': devices}
        except Exception:
            self._cache = {'devices': []}
        return self._cache

    def _flush(self):

        if self._cache is None:
            return
        from models import db, NetscopeDevice
        try:
            all_rows = NetscopeDevice.query.all()
            rows_by_mac = {r.mac: r for r in all_rows if r.mac}
            seen_uids = set()
            for dev in self._cache['devices']:
                mac = (dev.get('mac') or '').lower()
                uid = (dev.get('uid') or mac or gen_uid()).lower()
                dev['uid'] = uid
                if uid in seen_uids:
                    continue
                seen_uids.add(uid)

                row = rows_by_mac.get(mac) if mac else None
                if row is None:
                    for r in all_rows:
                        if r.data and isinstance(r.data, dict) and \
                           str(r.data.get('uid', '')).lower() == uid:
                            row = r
                            break

                doc = json.loads(json.dumps(dev, default=str))
                if row is None:
                    db.session.add(NetscopeDevice(
                        mac=mac or None,
                        ip=dev.get('ip') or '',
                        hostname=dev.get('hostname') or '',
                        deleted=bool(dev.get('deleted')),
                        last_seen=_parse_dt(dev.get('last_seen')),
                        data=doc,
                    ))
                else:
                    row.mac = mac or None
                    row.ip = dev.get('ip') or ''
                    row.hostname = dev.get('hostname') or ''
                    row.deleted = bool(dev.get('deleted'))
                    row.last_seen = _parse_dt(dev.get('last_seen'))
                    row.data = doc

            alive_uids = {(d.get('uid') or '').lower() for d in self._cache['devices']}
            alive_macs = {(d.get('mac') or '').lower() for d in self._cache['devices']}
            for r in all_rows:
                r_uid = ''
                if r.data and isinstance(r.data, dict):
                    r_uid = str(r.data.get('uid', '')).lower()
                r_mac = (r.mac or '').lower()
                if r_mac and r_mac in alive_macs:
                    continue
                if r_uid and r_uid in alive_uids:
                    continue
                db.session.delete(r)
            db.session.commit()
        except Exception:
            try:
                db.session.rollback()
            except Exception:
                pass
            raise

    def active(self):
        return [d for d in self._load()['devices'] if not d.get('deleted')]

    def trashed(self):
        return [d for d in self._load()['devices'] if d.get('deleted')]

    def find(self, key, include_deleted=False):

        if not key:
            return None
        key = str(key).lower()
        pool = self._load()['devices'] if include_deleted else self.active()
        for d in pool:
            if (d.get('uid') or '').lower() == key or (d.get('mac') or '').lower() == key:
                return d
        return None

    def find_by_ip(self, ip, include_deleted=False):
        if not ip:
            return None
        pool = self._load()['devices'] if include_deleted else self.active()
        for d in pool:
            if (d.get('ip') or '') == ip:
                return d
        return None

    def ip_conflicts(self):

        by_ip = {}
        for d in self.active():
            ip = (d.get('ip') or '').strip()
            if not ip:
                continue
            by_ip.setdefault(ip, []).append(d)
        out = []
        for ip, devs in by_ip.items():
            if len(devs) < 2:
                continue
            out.append({
                'ip': ip,
                'devices': [{
                    'uid': dev_key(d),
                    'mac': d.get('mac') or '',
                    'name': d.get('hostname') or d.get('name')
                            or d.get('dns_name') or d.get('ip', ''),
                    'type': d.get('type') or 'desktop',
                    'source': d.get('source') or '',
                    'status': d.get('status') or '',
                } for d in devs],
            })
        out.sort(key=lambda g: (-len(g['devices']), g['ip']))
        return out

    def mac_conflicts(self):

        by_mac = {}
        for d in self.active():
            mac = (d.get('mac') or '').strip().lower()
            if not mac or mac == '00:00:00:00:00:00':
                continue
            by_mac.setdefault(mac, []).append(d)
        out = []
        for mac, devs in by_mac.items():
            if len(devs) < 2:
                continue
            ips = sorted({(d.get('ip') or '').strip() for d in devs} - {''})
            if len(ips) < 2:
                continue
            out.append({
                'mac': mac,
                'ips': ips,
                'devices': [{
                    'uid': dev_key(d),
                    'mac': d.get('mac') or '',
                    'name': d.get('hostname') or d.get('name')
                            or d.get('dns_name') or d.get('ip', ''),
                    'type': d.get('type') or 'desktop',
                    'source': d.get('source') or '',
                    'status': d.get('status') or '',
                } for d in devs],
            })
        out.sort(key=lambda g: (-len(g['devices']), g['mac']))
        return out

    def is_circular(self, child_key, parent_key):

        cur = self.find(parent_key, include_deleted=True)
        while cur:
            pid = cur.get('parent_id')
            if pid == child_key:
                return True
            if not pid:
                break
            cur = self.find(pid, include_deleted=True)
        return False

    def stats(self):
        act = self.active()
        online = sum(1 for d in act if d.get('status') == 'online')
        types = {}
        for d in act:
            t = d.get('type', 'desktop')
            types[t] = types.get(t, 0) + 1
        today = datetime.now().isoformat()[:10]
        new_today = sum(1 for d in act
                        if d.get('first_seen') and d['first_seen'][:10] == today)
        documented = sum(1 for d in act if d.get('user'))
        with_agent = sum(1 for d in act if d.get('has_agent'))
        agent_exempt = sum(1 for d in act
                           if not d.get('has_agent') and d.get('agent_exempt'))
        return {'total': len(act), 'online': online, 'offline': len(act) - online,
                'types': types, 'new_today': new_today,
                'documented': documented,
                'undocumented': len(act) - documented,
                'with_agent': with_agent,
                'without_agent': len(act) - with_agent - agent_exempt,
                'agent_exempt': agent_exempt}

    def _new_device(self, mac, ip, vendor='', subnet='', gateway=None, source=''):

        now = datetime.now().isoformat()
        mac = (mac or '').strip().lower()
        return {
            'uid': mac or gen_uid(),
            'mac': mac, 'ip': ip, 'hostname': '', 'dns_name': '',
            'vendor': vendor, 'type': infer_type(ip, vendor, gateway),
            'subnet': subnet or '.'.join(ip.split('.')[:3]) if ip else '',
            'status': 'online', 'parent_id': None,
            'parent_inferred': False, 'parent_confidence': 0,
            'avg_rtt': None, 'ttl': None, 'open_ports': [],
            'discovery': '',
            'first_seen': now, 'last_seen': now,
            'notes': '', 'deleted': False, 'deleted_at': None,
            'source': source or '',
            'user': '', 'department': '', 'location': '',
            'asset_tag': '', 'model': '', 'serial_number': '', 'os': '',
            'seal_number': '',
            'switch_port': None,
            'pos': None,
            'has_agent': False, 'agent_id': '', 'agent_name': '',
            'agent_status': '', 'agent_last_keepalive': '',
            'agent_groups': [], 'agent_ip': '',
            'agent_exempt': False,
        }

    def upsert_scan_result(self, mac, info, flush=True):

        with self._lock:
            self._load()
            existing = self.find(mac, include_deleted=True)
            gw = info.get('gateway', '')
            now = datetime.now().isoformat()
            if existing and not existing.get('deleted'):
                existing['ip'] = info['ip']
                existing['vendor'] = info['vendor'] or existing.get('vendor', '')
                existing['status'] = 'online'
                existing['last_seen'] = now
                existing['subnet'] = info['subnet']
                if not existing.get('source'):
                    existing['source'] = 'scan'
                dns = info.get('dns_name', '')
                if dns:
                    if dns != existing.get('dns_name'):
                        existing['dns_name'] = dns
                    short = dns.split('.')[0]
                    if (short and not existing.get('name_manual')
                            and short != existing.get('hostname')):
                        existing['hostname'] = short
                elif _implausible(existing.get('dns_name')):
                    existing['dns_name'] = ''
                    if not existing.get('name_manual'):
                        existing['hostname'] = ''
                elif (not existing.get('name_manual')
                      and _implausible(existing.get('hostname'))):
                    existing['hostname'] = ''
                if info.get('ttl'):
                    existing['ttl'] = info['ttl']
                if info.get('discovery'):
                    existing['discovery'] = info['discovery']
                if existing['ip'] == gw and existing['type'] != 'router':
                    existing['type'] = 'router'
                if flush:
                    self._flush()
                return False
            else:
                if existing and existing.get('deleted') and existing.get('merged_into'):
                    if flush:
                        self._flush()
                    return False
                if existing and existing.get('deleted'):
                    self._cache['devices'].remove(existing)

                if mac:
                    for d in self._cache['devices']:
                        if (not d.get('deleted') and not d.get('mac')
                                and (d.get('ip') or '') == info['ip']):
                            d['mac'] = mac.lower()
                            d['vendor'] = info.get('vendor') or d.get('vendor', '')
                            d['status'] = 'online'
                            d['last_seen'] = now
                            d['subnet'] = info['subnet']
                            dns = info.get('dns_name', '')
                            if dns:
                                d['dns_name'] = dns
                                if not d.get('hostname'):
                                    d['hostname'] = dns.split('.')[0]
                            if info.get('ttl'):
                                d['ttl'] = info['ttl']
                            if info.get('discovery'):
                                d['discovery'] = info['discovery']
                            if (d.get('source') or '') == 'manual':
                                d['source'] = 'manual+scan'
                            if d.get('ip') == gw and d['type'] != 'router':
                                d['type'] = 'router'
                            if flush:
                                self._flush()
                            return False

                dev = self._new_device(mac, info['ip'], info['vendor'],
                                       info['subnet'], gw,
                                       source=info.get('source') or 'scan')
                dev['dns_name'] = info.get('dns_name', '')
                dev['hostname'] = info.get('dns_name', '').split('.')[0]
                dev['ttl'] = info.get('ttl')
                dev['discovery'] = info.get('discovery', '')
                self._cache['devices'].append(dev)
                if flush:
                    self._flush()
                return True

    def apply_dns_refresh(self, results):

        changed = 0
        with self._lock:
            self._load()
            for mac, dns in (results or {}).items():
                if not mac:
                    continue
                dev = self.find(mac, include_deleted=False)
                if not dev:
                    continue
                if not dns:
                    if _implausible(dev.get('dns_name')):
                        dev['dns_name'] = ''
                        changed += 1
                    if (not dev.get('name_manual')
                            and _implausible(dev.get('hostname'))):
                        dev['hostname'] = ''
                        changed += 1
                    continue
                if dns != dev.get('dns_name'):
                    dev['dns_name'] = dns
                    changed += 1
                short = dns.split('.')[0]
                if (short and not dev.get('name_manual')
                        and short != dev.get('hostname')):
                    dev['hostname'] = short
                    changed += 1
            if changed:
                self._flush()
        return changed

    def mark_offline(self, found_macs):

        with self._lock:
            self._load()
            for d in self._cache['devices']:
                if not d.get('deleted'):
                    if (d.get('mac') or '') and d['mac'] in found_macs:
                        d['status'] = 'online'
                    elif d.get('has_agent') and d.get('agent_status') == 'active':
                        d['status'] = 'online'
                    else:
                        d['status'] = 'offline'
            self._flush()

    def create_device(self, body, cfg):

        with self._lock:
            self._load()
            ip = (body.get('ip') or '').strip()
            if not ip:
                return None, 400, 'IP obrigatório'

            mac, mac_err = normalize_mac(body.get('mac') or '')
            if mac_err:
                return None, 400, mac_err
            if mac and self.find(mac):
                return None, 409, 'Dispositivo com este MAC já existe'

            subnet_str = body.get('subnet', '').strip()
            gw = ''
            if subnet_str:
                gw = next((n.get('gateway', '') for n in cfg.get('networks', []) if n['subnet'] == subnet_str), '')
            dev = self._new_device(mac, ip, body.get('vendor', ''), subnet_str, gw or None, source='manual')
            dev['hostname'] = body.get('hostname', '')
            dev['type'] = body.get('type', dev['type'])
            dev['notes'] = body.get('notes', '')
            dev['parent_id'] = body.get('parent_id')
            for f in ASSET_FIELDS:
                if f in body:
                    dev[f] = body[f]
            self._cache['devices'].append(dev)
            self._flush()
            return dev, 201, None

    def update_device(self, key, body):

        with self._lock:
            dev = self.find(key, include_deleted=True)
            if not dev:
                return None, 404, 'Não encontrado'

            if 'mac' in body:
                new_mac, mac_err = normalize_mac(body.get('mac') or '')
                if mac_err:
                    return None, 400, mac_err
                old_mac = (dev.get('mac') or '').lower()
                if new_mac != old_mac:
                    if new_mac:
                        other = self.find(new_mac, include_deleted=True)
                        if other and other is not dev:
                            return None, 409, 'Dispositivo com este MAC já existe'
                    dev['mac'] = new_mac

            for key_ in ('hostname', 'type', 'notes', 'subnet', 'name', 'ip'):
                if key_ in body:
                    dev[key_] = body[key_]
            if 'hostname' in body:
                dev['name_manual'] = bool((body.get('hostname') or '').strip())
            for f in ASSET_FIELDS:
                if f in body:
                    dev[f] = body[f]
            if 'agent_exempt' in body:
                dev['agent_exempt'] = bool(
                    body['agent_exempt'] in (True, 1, '1', 'true', 'True', 'sim', 'yes'))
            if 'switch_port' in body:
                sp = body['switch_port']
                old_sp = dev.get('switch_port')
                if sp and isinstance(sp, dict) and sp.get('switch_mac') and sp.get('port'):
                    dev['switch_port'] = {
                        'switch_mac': sp['switch_mac'].lower(),
                        'port': int(sp['port']),
                        'label': sp.get('label', ''),
                        'vlan': sp.get('vlan', ''),
                        'speed': sp.get('speed', ''),
                        'duplex': sp.get('duplex', ''),
                    }
                    self._mirror_host_port_to_switch(dev, dev['switch_port'], old_sp)
                else:
                    dev['switch_port'] = None
                    if old_sp:
                        self._release_switch_port(dev_key(dev), old_sp)
            if 'pos' in body:
                pos = body['pos']
                if pos and isinstance(pos, dict):
                    dev['pos'] = {'x': float(pos.get('x', 0)), 'y': float(pos.get('y', 0))}
                else:
                    dev['pos'] = None
            if 'parent_id' in body:
                dev['parent_id'] = body['parent_id']
                dev['parent_inferred'] = False
                dev['parent_confidence'] = 100 if body['parent_id'] else 0
            dev['last_seen'] = datetime.now().isoformat()
            self._flush()
            return dev, 200, None

    def _mirror_host_port_to_switch(self, dev, sp, old_sp=None):

        try:
            cfg = load_config()
            sws = cfg.get('switches', {})
            sw_key = sp['switch_mac']
            port = int(sp['port'])
            sw = sws.get(sw_key)
            if not isinstance(sw, dict):
                sw = {'port_count': 24, 'ports': {}}
            try:
                if port > int(sw.get('port_count', 24)):
                    sw['port_count'] = port
            except (TypeError, ValueError):
                sw['port_count'] = max(24, port)
            ports = sw.setdefault('ports', {})
            for _m, _sw in sws.items():
                if not isinstance(_sw, dict):
                    continue
                for p_str, p_info in _sw.get('ports', {}).items():
                    if (p_info.get('device_mac') or '').lower() == dev_key(dev) \
                            and not (_m == sw_key and p_str == str(port)):
                        p_info['device_mac'] = ''
            prev = ports.get(str(port)) or {}
            ports[str(port)] = {
                'label': sp.get('label') or prev.get('label') or ('Fa0/' + str(port)),
                'vlan': sp.get('vlan', '') or '',
                'speed': sp.get('speed', '') or prev.get('speed', ''),
                'duplex': sp.get('duplex', '') or prev.get('duplex', ''),
                'device_mac': dev_key(dev),
                'notes': prev.get('notes', ''),
            }
            sws[sw_key] = sw
            cfg['switches'] = sws
            save_config(cfg)
            for d in self.active():
                if d is dev:
                    continue
                other = d.get('switch_port')
                if other and other.get('switch_mac', '').lower() == sw_key \
                        and str(other.get('port')) == str(port):
                    d['switch_port'] = None
        except Exception:
            pass

    def _release_switch_port(self, dkey, sp):

        try:
            cfg = load_config()
            sws = cfg.get('switches', {})
            sw = sws.get(sp.get('switch_mac', ''))
            if not isinstance(sw, dict):
                return
            p = sw.get('ports', {}).get(str(sp.get('port')))
            if p and (p.get('device_mac') or '').lower() == dkey:
                p['device_mac'] = ''
                save_config(cfg)
        except Exception:
            pass

    def soft_delete(self, key):

        with self._lock:
            self._load()
            dev = self.find(key, include_deleted=True)
            if not dev:
                return False, 404
            dev['deleted'] = True
            dev['deleted_at'] = datetime.now().isoformat()
            removed_key = dev_key(dev)
            for d in self._cache['devices']:
                if (d.get('parent_id') or '').lower() == removed_key:
                    d['parent_id'] = None
                    d['parent_inferred'] = False
                    d['parent_confidence'] = 0
            cfg = load_config()
            sws = cfg.get('switches', {})
            for sw_key, sw in sws.items():
                ports = sw.get('ports', {})
                for p_num, p_info in list(ports.items()):
                    if p_info.get('device_mac', '').lower() == removed_key:
                        p_info['device_mac'] = ''
            save_config(cfg)
            self._flush()
            return True, 200

    def permanent_delete(self, key):

        with self._lock:
            self._load()
            dev = self.find(key, include_deleted=True)
            if not dev:
                return False, 404
            k = dev_key(dev)
            self._cache['devices'] = [d for d in self._cache['devices']
                                      if dev_key(d) != k]
            self._flush()
            return True, 200

    def restore(self, key):

        with self._lock:
            dev = self.find(key, include_deleted=True)
            if not dev or not dev.get('deleted'):
                return False, 404
            dev['deleted'] = False
            dev['deleted_at'] = None
            dev.pop('merged_into', None)
            dev.pop('merge_reason', None)
            self._flush()
            return True, 200

    def create_link(self, child_key, parent_key):

        with self._lock:
            self._load()
            child = self.find(child_key)
            parent = self.find(parent_key)
            if not child or not parent:
                return False, 404, 'Dispositivo não encontrado'
            child_key = dev_key(child)
            parent_key = dev_key(parent)
            if child_key == parent_key:
                return False, 400, 'Auto-referência não permitida'
            if self.is_circular(child_key, parent_key):
                return False, 400, 'Link circular detectado'
            child['parent_id'] = parent_key
            child['parent_inferred'] = False
            child['parent_confidence'] = 100
            self._flush()
            return True, 200, None

    def remove_link(self, key):

        with self._lock:
            dev = self.find(key)
            if not dev:
                return False, 404
            dev['parent_id'] = None
            dev['parent_inferred'] = False
            dev['parent_confidence'] = 0
            self._flush()
            return True, 200

    def infer_links(self, cfg):

        with self._lock:
            self._load()
            devices = self.active()
            if not devices:
                return 0
            gw_map = {n['subnet']: n.get('gateway', '').lower() for n in cfg.get('networks', [])}
            groups = {}
            for d in devices:
                groups.setdefault(d.get('subnet', '?'), []).append(d)
            changed = 0
            for subnet, devs in groups.items():
                gw_ip = gw_map.get(subnet, '')
                gateway = next((d for d in devs if d.get('ip') == gw_ip), None)
                if not gateway:
                    gateway = next((d for d in devs if d.get('ip', '').endswith('.1')), None)
                if not gateway:
                    devs.sort(key=lambda d: _ip_sort_key(d.get('ip')))
                    gateway = devs[0] if devs else None
                if not gateway:
                    continue
                gw_key = dev_key(gateway)
                for d in devs:
                    if dev_key(d) != gw_key and not d.get('parent_id'):
                        d['parent_id'] = gw_key
                        d['parent_inferred'] = True
                        d['parent_confidence'] = 75
                        changed += 1
            if changed:
                self._flush()
            return changed

store = Store()
