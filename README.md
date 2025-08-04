
<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img height="260" width= "960" src="https://github.com/Maarckz/Maarckz/blob/main/Images/Inventory.gif?raw=true"/> 
</div>

# Sistema de Inventário de Máquinas com WAZUH

Este documento descreve a arquitetura, os componentes e o funcionamento do INVENTORY, um sistema de inventário de máquinas para ambientes corporativos utilizando o Wazuh. A solução integra coleta de dados via API/script, processamento e visualização baseada na web, com ênfase em segurança e facilidade de operação. A arquitetura é modular, escalável e segue as melhores práticas de proteção de dados.

## Overview

O sistema realiza o inventário dos dispositivos com agentes Wazuh em duas camadas principais:

- **Coletor de Dados**: Responsável por se conectar à API do Wazuh e coletar informações detalhadas de cada agente monitorado, incluindo dados de hardware, sistema operacional, rede e portas abertas. As informações são processadas e armazenadas em arquivos JSON, organizados por hostname, de forma estruturada e padronizada para consumo posterior pela interface web.
- **Aplicação Web (Flask)**: Consome os arquivos JSON gerados pelo coletor e apresenta os dados por meio de uma interface web segura e interativa. A aplicação disponibiliza dashboards estatísticos, visualizações individuais por máquina, filtros dinâmicos, busca avançada e consultas personalizadas. Essa interface facilita a análise, inspeção e auditoria do inventário de forma eficiente e centralizada.

**Operation Flow**:
```
Wazuh Collector → JSON Data → Flask App → Dashboard / Panel
       │               │              │             └─→ Visualização por máquina
       │               │              └─→ Leitura e parsing dos arquivos
       │               └─→ Armazenamento estruturado por hostname
       └─→ Coleta via API: hardware, SO, rede, portas abertas
```

## Core Components

### 1. Collector Module

Interage com a API do Wazuh seguindo os passos abaixo:

- **JWT Authentication**: Obtém um token de acesso para requisições autenticadas.
- **Listagem de Agentes**: Recupera os dispositivos monitorados via API.
- **Inventory Collection**: Extrai especificações de hardware, detalhes do sistema operacional, informações de rede e portas abertas para cada agente.
- **Classificação de Status**: Marca os dispositivos de acordo com status da última sincronização, entre ativos e inativos.
- **Local Storage**: Grava arquivos JSON estruturados, nomeados de acordo com o hostname de cada dispositivo.

´´´
    Dados Coletados

    Informações Básicas
        Hostname
        Agent ID
        Sistema Operacional
        Arquitetura
        Serial da placa
        Última varredura
    Hardware
        CPU
        Núcleos
        Memória RAM
    Rede
        Interfaces de rede
        Portas de rede abertas
        Configurações de rede
    Software
        Pacotes instalados
        Processos em execução
    Classificação de Atividade
        Dispositivos classificados como ativos ou inativos conforme a última sincronização.
´´´

### 2. Web Application (Flask)

Acessível via navegador, com as seguintes funcionalidades:

- **Autenticação Segura**  
  - Senhas protegidas com hash bcrypt
  - Bloqueio de IP após tentativas falhas configuráveis
  - Expiração automática da sessão (ex: 30 minutos)
- **Statistical Dashboard**  
  - Total de máquinas cadastradas, ativas e inativas
  - Distribuição de Sistemas Operacionais
  - Tipos de processadores e memória RAM
  - Portas de Rede mais comun e Serviços
  - 
- **Painel de Máquinas**  
  - Lista completa de dispositivos com filtros avançados
- **Busca Avançada**  
  - Pesquisa por IP, sistema operacional, hardware ou outros critérios
- **Detalhes da Máquina**  
  - Visão detalhada dos dados coletados para cada host

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img height="500" width= "960" src="https://github.com/Maarckz/Maarckz/blob/main/Images/InventoryDemo.gif?raw=true"/> 
</div>


## Estrutura de Pastas

```
├── app.py
├── data
│   ├── auth
│   │   └── logins.json
│   └── inventory
│       ├── LEGION.json
│       ├── SERVER.json
│       └── SOC1.json
├── logs
│   ├── audit.log
│   ├── error.log
│   ├── get_data.log
│   ├── info.log
│   ├── security.log
│   └── warning.log
├── ssl
│   ├── cert.pem
│   └── key.pem
├── static
│   ├── css
│   │   ├── all.min.css
│   │   ├── base.css
│   │   ├── components.css
│   │   ├── dashboard.css
│   │   ├── error.css
│   │   ├── login.css
│   │   ├── machine_details.css
│   │   ├── painel.css
│   │   ├── search.css
│   │   ├── settings.css
│   │   └── styles.css
│   ├── js
│   │   ├── base.js
│   │   ├── chart.js
│   │   ├── common.js
│   │   ├── dashboard.js
│   │   ├── machine_details.js
│   │   ├── painel.js
│   │   └── search.js
│   ├── logo.svg
│   └── mlogo.svg
│   ├── favicon.png
├── templates
│   ├── base.html
│   ├── dashboard.html
│   ├── error.html
│   ├── login.html
│   ├── machine_details.html
│   ├── painel.html
│   ├── search.html
│   └── settings.html
└── utils
    ├── create_machines.py
    ├── get_data.py
    └── man_users.py
```

## Pré-requisitos

- Python 3.8+
- SIEM WAZUH + Agents Deploy
- Dependencias: `Flask`, `bcrypt`, `python-dotenv`

## Environment (`.env`)

```ini
# Configurações de segurança
SECRET_KEY=suachavesupersecreta_altere_esta_chave!
INVENTORY_DIR=data/inventory
AUTH_FILE=data/auth/logins.json
LOG_DIR=logs


# Configurações de rede
HOST=0.0.0.0
PORT=8000
DEBUG=False

# Configurações de HTTPS
USE_HTTPS=True
SSL_CERT_PATH=ssl/cert.pem
SSL_KEY_PATH=ssl/key.pem

# Proteção contra força bruta
MAX_LOGIN_ATTEMPTS=3
LOGIN_BLOCK_TIME=60

# Permitir apenas IPs de uma faixa específica
ALLOWED_IP_RANGES =192.168.0.0/16

#ARQUIVO DE IPs BLOQUEADOS
BLOCKED_IPS_FILE=${LOG_DIR}/blocked_ips.json

WAZUH_PROTOCOL=https
WAZUH_HOST=192.168.56.210
WAZUH_PORT=55000
WAZUH_USER=wazuh-wui
WAZUH_PASSWORD=ma?Pt3XvLxQzpU8.J3rIQ8.dYhxzV?pT

```

## Installation & Execution

1. Clone the repository and configure `.env` as above.
   ```bash
   https://github.com/Maarckz/Inventory.git
   ```
2. Install dependencies:
   ```bash
   pip install flask bcrypt requests python-dotenv
   ```
3. Run the collector (manually or via a button in the UI):
   ```bash
   python3 utils/get_data.py
   ```
   Here you need to configure wazuh-wui credentials.
   You can retrieve the credentials from the .tar with the command:
   ```bash
   sudo tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O
   ```
4. Set credentials on utils/get_data.py

5. Create TLS/SSL Cert:
  ```bash
  openssl req -x509 -newkey rsa:4096 -nodes -out ssl/cert.pem -keyout ssl/key.pem -days 365 
  ```
6. Start the web application:
   ```bash
   python app.py
   ```
7. Default Login and Password:
   ```bash
   Login: admin
   Password: Meuadmin123
   ```
OBS: É possivel criar e remover usuãrios pelo "./utils/man_users.py" 


## Service Configuration

1. Create a file to service
  ```bash
   sudo nano /etc/systemd/system/inventory.service
   ```
2. Paste the content:

```ini
[Unit]
Description=Flask Inventory Application
After=network.target

[Service]
Type=simple
#User=YOUR USER NAME
WorkingDirectory=/opt/Inventory
ExecStart=/usr/bin/python3 /opt/Inventory/app.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```
3. Reload System Daemon
```bash
sudo systemctl daemon-reload
```
4. Enable and Start Inventory.service

```bash
 sudo systemctl enable inventory.service && sudo systemctl start inventory.service
 ```

## Search Feature

Now is possible use tags to filter search requests:
```ìni
ports:445                 # Pesquisa por número de porta
agent_info:10.7.6.20      # Pesquisa em hostname, IP, status ou ID
inventory:os:Windows      # Pesquisa em campos do sistema operacional
inventory:hardware:i7     # Pesquisa em CPU, RAM ou serial da placa
inventory:packages:chrome # Pesquisa em pacotes instalados
inventory:processes:python # Pesquisa em processos em execução
```
## Monitoring & Maintenance

- **Recommended Routines**  
  - Daily execution of the collector  
  - Periodic audit of the user file (e.g., `users.json` or similar)  
  - Regular renewal of SSL certificates  

## Future Improvements

- **Docker**  
  - Deploy with docker image
  - Automation with docker compose (dockerfile)  
- **Collector**  
  - Externalize credentials via environment variables  
  - Parallel execution for scale  
  - Customizable SSL verification  
- **Web Application**  
  - Caching for static data  
  - Report export (PDF/CSV)  
  - REST API for external integrations  
- **Security**  
  - Multi-factor authentication (MFA)  
  - Encryption of JSON inventory files  
  - Detailed access auditing  
- **Export Relatory**  
  - Export to PDF or CSV File
  - Integration with another tool
