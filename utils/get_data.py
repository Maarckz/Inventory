import json
import os
import requests
import urllib3
from datetime import datetime, timedelta
import logging

# Disable insecure HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Constants
INVENTORY_FOLDER = 'data/inventory'
DEFAULT_STATUS = "Desligado"
ENDPOINTS = [
    'hardware', 
    'os', 
    #'packages', 
    'ports', 
    #'processes',
    'netaddr', 
    'netiface', 
    'netproto'
]

class WazuhAPI:
    """Encapsulates Wazuh API operations"""
    def __init__(self, protocol, host, port, user, password):
        self.base_url = f'{protocol}://{host}:{port}'
        self.credentials = (user, password)
        self.session = requests.Session()
        self.session.verify = False
        self.token = None

    def authenticate(self):
        """Obtain JWT token from Wazuh API"""
        url = f"{self.base_url}/security/user/authenticate?raw=true"
        try:
            response = self.session.get(url, auth=self.credentials, timeout=10)
            response.raise_for_status()
            self.token = response.text.strip()
            self.session.headers.update({'Authorization': f'Bearer {self.token}'})
            logging.info("Authentication successful")
        except requests.RequestException as e:
            logging.error(f"Authentication failed: {e}")
            raise SystemExit("Critical authentication error") from e

    def get(self, endpoint):
        """Execute authenticated GET request"""
        url = f"{self.base_url}/{endpoint}"
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logging.error(f"Request to {url} failed: {e}")
        except json.JSONDecodeError:
            logging.error(f"Invalid JSON response from {url}")
        return {}

class InventoryManager:
    """Manages device inventory processing and storage"""
    def __init__(self, api_client):
        self.api = api_client
        os.makedirs(INVENTORY_FOLDER, exist_ok=True)

    @staticmethod
    def _determine_status(last_seen):
        """Determine device status based on last activity"""
        if last_seen == 'unknown':
            return DEFAULT_STATUS
        
        try:
            # Normalize datetime format
            normalized_time = last_seen[:-1] + '+00:00' if last_seen.endswith('Z') else last_seen
            last_seen_dt = datetime.fromisoformat(normalized_time)
            time_delta = datetime.now(last_seen_dt.tzinfo) - last_seen_dt
            return "Ligado" if time_delta <= timedelta(days=30) else DEFAULT_STATUS
        except ValueError as e:
            logging.error(f"Invalid timestamp '{last_seen}': {e}")
            return DEFAULT_STATUS

    @staticmethod
    def _clean_inventory_data(data):
        """Remove internal fields from inventory data"""
        if isinstance(data, dict):
            return {
                k: InventoryManager._clean_inventory_data(v)
                for k, v in data.items()
                if k not in ['agent_id', 'scan_id', 'scan_time']
            }
        if isinstance(data, list):
            return [InventoryManager._clean_inventory_data(item) for item in data]
        return data

    def _get_agent_inventory(self, agent_id):
        """Collect inventory data for a specific agent"""
        inventory = {}
        for endpoint in ENDPOINTS:
            try:
                response = self.api.get(f"syscollector/{agent_id}/{endpoint}")
                items = response.get('data', {}).get('affected_items', [])
                inventory[endpoint] = [self._clean_inventory_data(item) for item in items]
            except Exception as e:
                logging.error(f"Error collecting {endpoint} for agent {agent_id}: {e}")
                inventory[endpoint] = []
        return inventory

    def _save_device_data(self, hostname, agent_info, inventory):
        """Save device data to JSON file"""
        hostname_upper = hostname.upper() if isinstance(hostname, str) else 'UNKNOWN'
        safe_name = "".join(c for c in hostname_upper if c.isalnum() or c in (' ', '.', '_', '-')).strip() or 'UNKNOWN'
        file_path = os.path.join(INVENTORY_FOLDER, f"{safe_name}.json")
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(
                {'agent_info': agent_info, 'inventory': inventory},
                f,
                ensure_ascii=False,
                indent=4
            )
        logging.info(f"Inventory saved for '{safe_name}'")

    def process_agents(self):
        """Process all agents and save their inventory"""
        response = self.api.get("agents?select=id,name,ip,lastKeepAlive,status,os.platform,os.name,os.version")
        agents = response.get('data', {}).get('affected_items', [])
        
        if not agents:
            logging.warning("No agents found")
            return

        for agent in agents:
            agent_id = agent['id']
            logging.info(f"Processing agent: {agent.get('name')} (ID: {agent_id})")
            
            # Enhance agent data with calculated status
            agent['calculated_status'] = self._determine_status(agent.get('lastKeepAlive', 'unknown'))
            
            # Collect and save inventory
            inventory = self._get_agent_inventory(agent_id)
            hostname = self._get_hostname(inventory, agent)
            self._save_device_data(hostname, agent, inventory)

    @staticmethod
    def _get_hostname(inventory, agent):
        """Determine best available hostname"""
        os_data = inventory.get('os', [{}])
        return os_data[0].get('hostname') if os_data else agent.get('name', 'unknown')

def main():
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # API configuration
    api = WazuhAPI(
        protocol='https',
        host='192.168.56.210',
        port='55000',
        user='wazuh-wui',
        password='ma?Pt3XvLxQzpU8.J3rIQ8.dYhxzV?pT'
    )
    api.authenticate()
    
    # Process inventory
    inventory_mgr = InventoryManager(api)
    inventory_mgr.process_agents()

if __name__ == '__main__':
    main()
