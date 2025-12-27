import os
import json
import logging
import requests
import urllib3
from dotenv import load_dotenv

# Desabilitar warnings de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WazuhGroupsAPI:
    """API específica para obter grupos do Wazuh"""
    
    def __init__(self):
        # Carregar variáveis de ambiente
        load_dotenv()
        
        self.protocol = os.getenv('WAZUH_PROTOCOL')
        self.host = os.getenv('WAZUH_HOST')
        self.port = os.getenv('WAZUH_PORT')
        self.user = os.getenv('WAZUH_USER')
        self.password = os.getenv('WAZUH_PASSWORD')
        
        self.base_url = f"{self.protocol}://{self.host}:{self.port}"
        self.session = requests.Session()
        self.session.verify = False
        self.session.auth = (self.user, self.password)
        self.token = None
        
        # Configurar logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def authenticate(self) -> bool:
        """Obtém token JWT da API"""
        url = f"{self.base_url}/security/user/authenticate?raw=true"
        try:
            resp = self.session.get(url, timeout=10)
            self.token = resp.text.strip()
            self.session.headers.update({'Authorization': f'Bearer {self.token}'})
            self.session.auth = None
            logging.info('Autenticação bem-sucedida')
            return True
        except Exception as e:
            logging.error(f'Falha na autenticação: {e}')
            return False
    
    def get_groups(self):
        """Obtém grupos do Wazuh"""
        if not self.token:
            if not self.authenticate():
                return None
        
        url = f"{self.base_url}/groups"
        params = {'pretty': 'true'}
        
        try:
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logging.error(f'Erro ao obter grupos: {e}')
                          
            return None
    
    def get_agents_in_group(self, group_name):
        """Obtém agentes de um grupo específico"""
        url = f"{self.base_url}/groups/{group_name}/agents"
        params = {
            'pretty': 'true',
            'select': 'id,name',
            'limit': 1000
        }
        
        try:
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            return data.get('data', {}).get('affected_items', [])
        except Exception as e:
            logging.error(f'Erro ao obter agentes do grupo {group_name}: {e}')
            return []
    
    def get_groups_with_agents_simple(self):
        """Obtém grupos com agentes no formato simplificado JSON"""
        grupos_data = self.get_groups()
        if not grupos_data:
            return None
        
        resultado = []
        grupos = grupos_data.get('data', {}).get('affected_items', [])
        
        for grupo in grupos:
            grupo_name = grupo.get('name')
            agentes = self.get_agents_in_group(grupo_name)
            
            # Formatar dados simplificados
            grupo_info = {
                "grupo": grupo_name,
                "quantidade_agentes": len(agentes),
                "agentes": [
                    {
                        "id": agente.get('id'),
                        "name": agente.get('name')
                    }
                    for agente in agentes
                ]
            }
            resultado.append(grupo_info)
        
        return resultado

def save_groups_json(data, filename="../data/groups/groups.json"):
    """Salva os dados em arquivo JSON na pasta ../data/groups/"""
    try:
        # Criar diretório se não existir
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        logging.info(f"Dados salvos em: {filename}")
        return True
    except Exception as e:
        logging.error(f"Erro ao salvar arquivo: {e}")
        return False

def main():
    """Função principal"""
    # Criar instância da API
    wazuh_api = WazuhGroupsAPI()
    
    # Obter grupos com agentes no formato simplificado
    grupos_simplificados = wazuh_api.get_groups_with_agents_simple()
    
    if grupos_simplificados:
        # Salvar em arquivo JSON na pasta ../data/groups/
        success = save_groups_json(grupos_simplificados)
        if success:
            logging.info("Arquivo JSON salvo com sucesso na pasta ../data/groups/")
        else:
            logging.error("Falha ao salvar arquivo JSON")
    else:
        logging.error("Falha ao obter dados dos grupos")

if __name__ == '__main__':
    main()