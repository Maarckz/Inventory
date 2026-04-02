## 1. Apresentação

O **INVENTORY** é a solução definitiva para a gestão centralizada do inventário de máquinas corporativas, desenvolvida para ambientes que exigem alta visibilidade, rastreabilidade e segurança. O sistema transforma os dados de telemetria brutos coletados pela sua plataforma **Wazuh** (via _SysCollector_) em uma **Interface Web Segura e Moderna**.


<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img height="260" width= "960" src="https://github.com/Maarckz/Inventory/blob/main/Images/I1_Inventory.gif?raw=true"/> 
</div>

O objetivo principal do INVENTORY é eliminar a "cegueira" sobre os ativos de TI, fornecendo às equipes de segurança, operações e _compliance_ uma fonte única e confiável de informação sobre o estado, _hardware_, _software_ e segurança de cada dispositivo.

A principal vantagem reside na **utilização dos agentes nativos do Wazuh**, eliminando a necessidade de instalar _softwares_ adicionais nos _endpoints_ e, consequentemente, **reduzindo a superfície de ataque** e o _overhead_ operacional.

<video width="600" controls>
  <source src=" https://www.linkedin.com/posts/marcus-dealmeida_ol%C3%A1-rede-s%C3%B3-pra-avisar-que-tem-algumas-atualiza%C3%A7%C3%B5es-activity-7377797080897011712-tYeP?utm_source=share&utm_medium=member_android&rcm=ACoAADXtQm8BWDhoje3QTZaTuswm_dJjvSClhaY"  type="video/mp4">
  Seu navegador não suporta vídeo.
</video>

    
### 1.1. Objetivos da Solução:
Os principais objetivos do sistema **INVENTORY** são:
 **Centralizar informações de inventário de TI** de dispositivos corporativos.
• **Garantir rastreabilidade e auditoria completa** dos ativos.
• **Oferecer dashboards interativos** para equipes de segurança e TI.
• **Permitir a integração com outros sistemas** corporativos (CMDB, SIEM, DLP).
• **Agrupar Informações do Host** como Processos, Serviços, Portas Abertas, Programas Instalados.
• **Suportar ambientes heterogêneos** (Linux, Windows, servidores e estações de trabalho) em empresas de pequeno e médio porte.

## 2. Arquitetura da Solução e Fluxo de Dados

A arquitetura do **INVENTORY** foi concebida em um modelo de três camadas, **coleta**, **armazenamento** e **apresentação**. Este desacoplamento permite que o coletor e a aplicação web sejam mantidos e escalados de forma independente. 
Adicionalmente, o uso de arquivos _JSON locais_ como camada de armazenamento provê um repositório de dados simples e auditável, eliminando a complexidade e as dependências associadas a um banco de dados tradicional.

1. **Coleta de Dados (Wazuh Collector):** O processo se inicia com o componente coletor, que se conecta de forma segura à API REST do Wazuh Manager. Utilizando o módulo _SysCollector_, ele extrai informações dos agentes, incluindo detalhes de hardware, sistema operacional, configurações de rede, portas abertas, pacotes de software e processos em execução.

2. **Armazenamento (JSON Data):** Os dados coletados são processados, estruturados e armazenados localmente em arquivos no formato JSON. Cada arquivo corresponde a um dispositivo específico, sendo nomeado pelo seu _hostname_, o que facilita o consumo posterior pela aplicação web e permite a fácil manutenção.

3. **Apresentação e Análise (Flask App):** A aplicação web, desenvolvida em _Flask_, consome os arquivos JSON para exibir as informações em uma interface interativa. Os dados são apresentados em dashboards estatísticos, painéis de listagem de máquinas e relatórios detalhados, permitindo que as equipes de TI e segurança analisem, inspecionem e auditem o inventário de forma centralizada.

## 3. Componentes Principais

A arquitetura  é materializada por dois componentes de software principais que trabalham em conjunto: o **Módulo Coletor** e a **Aplicação Web**. A solução adota o padrão de arquitetura _MVC (Model-View-Controller)_, uma prática recomendada de segurança que impõe a separação de interesses. Ao isolar a lógica de manipulação de dados da camada de apresentação, o padrão MVC reduz a superfície de ataque e facilita a manutenção e o desenvolvimento seguro.

### 3.1 Módulo Coletor (INVENTORY Collector)
O Coletor de Dados é o **principal** responsável pela extração de informações, atuando como a interface de comunicação entre o sistema *INVENTORY* e o ambiente _WAZUH_. Sua função é automatizar a coleta e a estruturação dos dados de inventário.


### 1. Collector Module

Interage com a API do Wazuh seguindo os passos abaixo:

- **JWT Authentication**: Obtém um token de acesso para requisições autenticadas.
- **Listagem de Agentes**: Recupera os dispositivos monitorados via API.
- **Inventory Collection**: Extrai especificações de hardware, detalhes do sistema operacional, informações de rede e portas abertas para cada agente.
- **Classificação de Status**: Marca os dispositivos de acordo com status da última sincronização, entre ativos e inativos.
- **Local Storage**: Grava arquivos JSON estruturados, nomeados de acordo com o hostname de cada dispositivo.

```
Dados Coletados:

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
Grupos do WAZUH
```



| Função                           | Detalhamento                                                                                                                                                               |
| -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Interface com a API do Wazuh** | Realiza a coleta e listagem de dados dos agentes monitorados, utilizando o módulo _SysCollector_ do Wazuh.                                                                 |
| **Autenticação**                 | Utiliza um Token JWT (JSON Web Token) para garantir o acesso seguro e autenticado à API do Wazuh.                                                                          |
| **Dados Coletados**              | Extrai informações de Hardware (CPU, RAM, disco), Software (pacotes instalados), Rede (interfaces, portas abertas), Processos e detalhes do agente (status, hostname, ID). |
| **Armazenamento**                | Organiza e armazena os dados em arquivos JSON estruturados, nomeados pelo _hostname_ de cada dispositivo.                                                                  |
| **Utilitários**                  | Inclui os scripts `get_data.py` (coletor principal) e `get_groups.py` (coletor de grupos de agentes Wazuh).                                                                |

### 3.2 Aplicação Web (Flask)
A Aplicação Web é a camada de processamento, gerenciamento, visualização e gestão da solução, fornecendo a interface com a qual os usuários interagem para analisar o inventário.


Acessível via navegador, com as seguintes funcionalidades:

- **Autenticação Segura**  
  - Senhas protegidas com hash bcrypt
  - Bloqueio de IP após tentativas falhas configuráveis
  - Expiração automática da sessão (ex: 30 minutos)
  - MFA TOTP
- **Statistical Dashboard**  
  - Total de máquinas cadastradas, ativas e inativas
  - Distribuição de Sistemas Operacionais
  - Tipos de processadores e memória RAM
  - Portas de Rede mais comun
  - Serviços
  - Processos com maior repetição
- **Painel de Máquinas**  
  - Lista completa de dispositivos com filtros avançados
- **Busca Avançada**  
  - Pesquisa por IP, sistema operacional, hardware ou outros critérios
- **Detalhes da Máquina**  
  - Visão detalhada dos dados coletados para cada host



| Função              | Detalhamento                                                                                                                                                                                                                                            |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Framework**       | A aplicação é construída sobre o micro-framework **Flask**, utilizando a linguagem **Python**, o que garante leveza e flexibilidade.                                                                                                                    |
| **Interface**       | A interface do usuário é desenvolvida com **Tríade da Web**, utilizando bibliotecas como **Chart.js** para gráficos interativos e **Font Awesome** para ícones, resultando em uma experiência de usuário moderna e intuitiva.                           |
| **Funcionalidades** | Oferece um _dashboard_ estatístico completo, um _painel_ para listagem e _detalhamento de máquinas_, um sistema de _busca avançada_ com filtros dinâmicos e a capacidade de exportar relatórios em formatos PDF e CSV (este último em desenvolvimento). |
| **Segurança**       | Implementa múltiplos mecanismos de segurança, incluindo armazenamento de senhas com **hash bcrypt**, **Autenticação Multifator (MFA) baseada em TOTP**, controle de acesso por faixas de IP e o uso de **headers de segurança HTTP**.                   |








## 4. Estrutura de Diretórios

A organização lógica do sistema se reflete em uma estrutura de diretórios clara e bem definida, projetada para separar a aplicação, os dados, os recursos estáticos e os utilitários. Essa separação facilita a manutenção, a escalabilidade e a aplicação de controles de segurança.

### 4.1. Estrutura simplificada

|Diretório/Arquivo|Função|
|---|---|
|`app.py`|Aplicação principal Flask.|
|`data/inventory/`|Arquivos JSON das máquinas (inventário).|
|`data/auth/logins.json`|Usuários e credenciais.|
|`utils/`|Utilitários de gestão (_get_data.py_, _man_users.py_, _pdf_export.py_).|
|`ssl/`|Certificados TLS/SSL para HTTPS.|

A estrutura do projeto separa a aplicação, os dados e os utilitários de gestão:

|Categoria|Função|
|---|---|
|**Núcleo da Aplicação**|Contém a lógica principal da interface web (Flask).|
|**Dados**|Diretórios para armazenar os arquivos JSON do inventário, credenciais de usuários e dados de grupos do Wazuh.|
|**Recursos Estáticos**|Arquivos de estilo (CSS), _scripts_ de interação (JS) e imagens/ícones.|
|**Templates**|Arquivos HTML da interface do usuário.|
|**Utilitários**|_Scripts_ para coleta de dados, gerenciamento de usuários e exportação de relatórios.|
|**Certificados**|Arquivos para configuração de segurança HTTPS (TLS/SSL).|
### 4.2. Estrutura completa:
```
INVENTORY/                        # Diretório raiz do projeto
├── app.py                        # Ponto de entrada principal da aplicação Flask
├── data/                         # Dados persistentes da aplicação
│   ├── auth/
│   │   └── logins.json           # Credenciais de usuários e registros de login
│   └── inventory/                # Inventário de agentes/máquinas
│       ├── agent_1.json
│       ├── agent_2.json
│       └── agent_3.json
├── ssl/                          # Certificados TLS/SSL para habilitar HTTPS
│   ├── cert.pem
│   └── key.pem
├── static/                       # Arquivos estáticos usados na interface
│   ├── css/                      # Estilos globais e específicos
│   │   ├── all.min.css
│   │   ├── base.css
│   │   ├── components.css
│   │   ├── dashboard.css
│   │   ├── error.css
│   │   ├── login.css
│   │   ├── machine_details.css
│   │   ├── painel.css
│   │   ├── search.css
│   │   ├── settings.css
│   │   └── styles.css
│   ├── favicon.png               # Ícone do site
│   ├── js/                       # Scripts JavaScript da aplicação
│   │   ├── base.js
│   │   ├── chart.js
│   │   ├── common.js
│   │   ├── dashboard.js
│   │   ├── machine_details.js
│   │   ├── painel.js
│   │   └── search.js
│   ├── logo.svg
│   └── mlogo.svg
├── templates/                     # Templates HTML renderizados pelo Flask
│   ├── base.html                  # Template base (layout principal)
│   ├── dashboard.html             # Painel principal
│   ├── error.html                 # Página de erro
│   ├── login.html                 # Tela de autenticação
│   ├── machine_details.html       # Detalhes de uma máquina/agente
│   ├── painel.html                # Painel geral das máquinas
│   ├── search.html                # Tela de busca
│   ├── settings.html              # Configurações do sistema
│   └── verify_mfa.html            # Verificação de MFA
└── utils/                         # Scripts utilitários de apoio
    ├── create_machines.py         # Criação de inventário de máquinas
    ├── get_data.py                # Coletor de dados do sistema
    ├── get_groups.py              # Manipulação de grupos de agentes
    ├── language.py                # Suporte a internacionalização/idiomas
    ├── man_users.py               # Gerenciamento de usuários
    ├── mfa_utils.py               # Funções auxiliares para MFA
    └── pdf_export.py              # Exportação de relatórios em PDF

```

## 5. Funcionalidades Detalhadas da Aplicação

A interface web do _INVENTORY_ foi desenvolvida para transformar os dados brutos coletados em inteligência acionável, fornecendo ferramentas poderosas para as equipes de TI e segurança.

### 5.1. Dashboard
O dashboard é a visão centralizada e estatística do inventário, projetado para oferecer uma compreensão imediata do ambiente de TI.

• **Métricas (KPIs):** Apresenta indicadores chave de desempenho, como o número total de máquinas, a quantidade de ativos online (ativos) e offline (inativos).

• **Gráficos Interativos:** Exibe visualizações gráficas da distribuição de sistemas operacionais, tipos de processadores, faixas de memória RAM, portas de rede mais comuns e processos com maior recorrência, além da **evolução temporal do status dos agentes**, permitindo a análise de tendências. O clique em um gráfico redireciona para a busca avançada com o filtro correspondente aplicado.

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/I2_DASHBOARD.png?raw=true"/> 
</div>

### 5.2. Painel de Máquinas e Detalhes de Ativos
Este painel fornece uma listagem de **todos os dispositivos inventariados**, exibindo informações resumidas e o status de atividade em _tempo real_. A partir desta lista, é possível navegar para uma página de detalhes completa para cada ativo, que consolida todas as informações extraídas do Wazuh, incluindo hardware, rede, software instalado e processos em execução.

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/I3_PAINEL.png?raw=true"/> 
</div>

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/I5_DETAILS.png?raw=true"/> 
</div>

### 5.3. Sistema de Busca Avançada
A funcionalidade de busca avançada é uma ferramenta para atividades de _threat hunting_, auditoria, ou até mesmo uma simples pesquisa, permitindo consultas precisas com uma sintaxe baseada em **tags**.

**Exemplos de Sintaxe de Busca:**

• `ports:445` - Localiza máquinas com uma porta específica aberta.

• `inventory:os:Windows` - Filtra dispositivos por sistema operacional.

• `inventory:packages:chrome` - Busca por máquinas com um pacote de software específico instalado.

• `agent_info:10.7.6.20` - Pesquisa por hostname, IP, status ou ID do agente.

• `inventory:processes:python` - Busca por processos em execução em um ativo.

• `ram_gb:9-12gb` - Filtra ativos por uma faixa específica de memória RAM.

• `groups:Home` - Busca pelo grupo pesquisado.

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/I4_SEARCH.png?raw=true"/> 
</div>


### 5.4. Geração de Relatórios e Sincronização
O sistema permite a _exportação de relatórios_ completos do inventário em formatos **PDF** e **CSV**, facilitando a criação de documentação para auditorias de conformidade. Adicionalmente, oferece uma funcionalidade de_ sincronização manual_, que aciona o coletor para atualizar os dados do inventário diretamente do Wazuh, garantindo que as informações estejam sempre atualizadas.

> [!NOTE]
> Devido a uma restrição de segurança da própria API do Wazuh, a sincronização pode ser lenta de acordo com a quantidade de hosts a serem sincronizados.

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img  src="https://github.com/Maarckz/Inventory/blob/main/Images/I7_CONFIG.png?raw=true"/> 
</div>

## 6. Arquitetura de Segurança

A segurança é uma prioridade no design do sistema **INVENTORY**. A arquitetura emprega uma estratégia de **"defesa em profundidade"**, com controles implementados nas camadas de autenticação, sessão, rede e transporte para proteger de forma abrangente o acesso aos dados centralizados de inventário.

### 6.1. Autenticação e Gestão de Sessões
A proteção de credenciais e o controle de acesso são realizados por meio de um conjunto robusto de medidas:

• **Hash bcrypt:** As senhas dos usuários são armazenadas utilizando o algoritmo bcrypt, um padrão forte que protege contra ataques de quebra de senha offline, como _rainbow table_ e força bruta.
• **Controle de Força Bruta:** O sistema implementa um mecanismo de bloqueio de IP após um número configurável de tentativas de login falhas.
• **Verificação de IP de Origem:** Cada login é validado contra o endereço IP de origem para mitigar o risco de sequestro de sessão ou uso de credenciais roubadas de locais não autorizados.
• **Timeout Automático:** As sessões de usuário expiram automaticamente após um período de inatividade (padrão de 15 minutos), mitigando o risco de acesso não autorizado a estações de trabalho desatendidas.

### 6.2. Autenticação Multifator (MFA)
Para reforçar a segurança do login, o sistema suporta **Autenticação Multifator (MFA)** baseada no padrão _TOTP (Time-based One-Time Password)_. Esta funcionalidade é compatível com aplicativos autenticadores populares, como o _Google Authenticator_, pode ser configurada de forma simples através da leitura de um QR code e oferece suporte a **backup de códigos de recuperação**.

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/I7_MFA.png?raw=true"/> 
</div>
    
### 6.3. Controle de Acesso à Rede
O acesso à interface web pode ser restrito a faixas de rede específicas. Essa configuração é controlada pela variável de ambiente `ALLOWED_IP_RANGES`, permitindo que apenas usuários de redes confiáveis (como a rede corporativa interna) possam acessar a aplicação.

### 6.4. Segurança da Camada de Transporte e Auditoria
A comunicação entre o cliente e o servidor é protegida com **TLS/SSL**, garantindo a criptografia de todo o tráfego via HTTPS. A aplicação também implementa **Headers de Segurança HTTP** para mitigar ataques comuns a aplicações web. Além disso, o sistema mantém logs detalhados de segurança (`security.log`) e auditoria (`audit.log`), registrando eventos relevantes para garantir a rastreabilidade completa das ações.


# 02 - Preparação


## Overview

O sistema realiza o inventário dos dispositivos com agentes Wazuh em duas camadas principais:

- **Coletor de Dados**: Responsável por se conectar à API do Wazuh e coletar informações detalhadas de cada agente monitorado, incluindo dados de hardware, sistema operacional, rede e portas abertas. As informações são processadas e armazenadas em arquivos JSON, organizados por hostname, de forma estruturada e padronizada para consumo posterior pela interface web.
- **Aplicação Web (Flask)**: Consome os arquivos JSON gerados pelo coletor e apresenta os dados por meio de uma interface web segura e interativa. A aplicação disponibiliza dashboards estatísticos, visualizações individuais por máquina, filtros dinâmicos, busca avançada e consultas personalizadas. Essa interface facilita a análise, inspeção e auditoria do inventário de forma eficiente e centralizada.

**Operation Flow**:
```
Wazuh Collector → JSON Data → Flask App → Dashboard / Panel
       │               │              │             └─ Visualização por máquina
       │               │              └─ Leitura e parsing dos arquivos
       │               └─ Armazenamento estruturado por hostname
       └─ Coleta via API: hardware, SO, rede, portas abertas, programas e processos.
```

**Criar usuários:**
```bash
# Aplicação
sudo useradd -r -s /usr/sbin/nologin inventory
```


# 8 - Instalação do Inventory

O inventory serve como uma solução para centralizar os dados de OSCollector do WAZUH.
Ao invés de acessar maquina por maquina, é possivel ter uma visão geral e abrangente dos ativos.

**Criar e configurar a pasta:**
```
cd /opt
sudo mkdir Inventory
chown -R inventory:inventory ./Inventory
```

**Clonar o repositório:**
```shell

git clone https://github.com/Maarckz/Inventory.git
```

**Criar o `.env` dentro de Inventory e colar o conteúdo abaixo**
```shell
cd Inventory && nano .env
```

## Environment (`.env`)
```bash

# Configurações de segurança
SECRET_KEY=suachavesupersecreta_altere_esta_chave!
SESSION_SALT=suachavesupersecreta_altere_esta_chave_salt!
INVENTORY_DIR=data/inventory
GROUPS_DIR=data/groups
AUTH_FILE=data/auth/logins.json
LOG_DIR=logs

# Configurações de rede
HOST=0.0.0.0
PORT=7000
DEBUG=False

# Configurações de HTTPS
USE_HTTPS=True
SSL_CERT_PATH=ssl/cert.pem
SSL_KEY_PATH=ssl/key.pem

# Permitir apenas IPs de uma faixa específica
ALLOWED_IP_RANGES=192.168.0.0/16

WAZUH_PROTOCOL=https
WAZUH_HOST=192.168.56.101
WAZUH_PORT=55000
WAZUH_USER=wazuh-wui
WAZUH_PASSWORD=ma?Pt3XvLxQzpU8.J3rIQ8.dYhxzV?pT
```

**As credenciais de API, devem ser consultadas dentro da  pasta de instalaçao do WAZUH**
```shell
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

**Instalar o PIP3:**
```
sudo apt install python3-pip python3-venv
```


**Criar o ambiente virtual e de permissões novamente**
```
sudo -u inventory python3 -m venv /opt/Inventory/venv
sudo chown -R inventory:inventory ./Inventory
```

**Abra um shell como usuário inventory**
```
sudo -u inventory -s
```

**Dentro do shell**
```
source /opt/Inventory/venv/bin/activate
```

**Instalar dependências com o usuário `Inventory`:**
```shell
pip3 install flask flask_session bcrypt requests python-dotenv qrcode pyotp reportlab --break-system-packages
```

**Rodar o coletor (via Painel do Sistema ou Manualmente):**
```shell
python3 utils/get_data.py
```

**Criar TLS/SSL Cert:**
```shell
openssl req -x509 -newkey rsa:4096 -nodes -out ssl/cert.pem -keyout ssl/key.pem -days 365 
```

**Teste da aplicação WEB:**
```shell
python3 app.py
```

**Login e Password padrão:**
```shell
Login: admin
Password: Meuadmin123
```

> [!NOTE]
> 1. É possivel criar e remover usuãrios pelo "./utils/man_users.py"
> 2. Os dados contidos inicialmente sem o SYNC,no dahsboard, são apenas DEMOS, realize o SYNC para obter os dados reais.

# 9 - Criação do serviço utilitário
Para manter os serviço disponivel mesmo após o reboot, sugiro a criação abaixo no diretório:

**/etc/systemd/system/inventory.service**
```bash
[Unit]
Description=Inventory Application
After=network.target
Wants=network-online.target

[Service]
# Exec
Type=simple
WorkingDirectory=/opt/Inventory
ExecStart=/opt/Inventory/venv/bin/python3 /opt/Inventory/app.py

# Run as unprivileged account (or use DynamicUser=yes, ver abaixo)
User=inventory
Group=inventory

# Restart policy
Restart=always
RestartSec=5

# Basic sandboxing
NoNewPrivileges=yes          # impede elevação de privilégios
PrivateTmp=yes               # /tmp isolado
PrivateDevices=yes           # sem acesso direto a /dev
ProtectSystem=full           # /usr e /boot readonly; 'full' protege /etc também
ProtectHome=yes              # /home e /root inacessíveis
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes

# Filesystem allowlist: deixa somente o que precisa escrever
ReadOnlyPaths=/
ReadWritePaths=/opt/Inventory

# Network restrictions: permita só famílias necessárias (web usa AF_INET/AF_INET6)
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

# Capabilities: remove tudo por padrão (adicione só o que for imprescindível)
CapabilityBoundingSet=
AmbientCapabilities=

# Limits
LimitNOFILE=65536
LimitNPROC=1024

# Memory exec protections
MemoryDenyWriteExecute=yes
LockPersonality=yes

# Logging
StandardOutput=journal
StandardError=journal

# Extra: make sure service cannot create new users/suid escalation
RestrictSUIDSGID=yes

[Install]
WantedBy=multi-user.target

```

**Para verificar o usuário do serviço / processo:**
```
systemctl show -p MainPID --value inventory.service 
ps -o user,pid,cmd -p <PID>
```

**Recarregue o daemon do sistema:**
```shell
sudo systemctl daemon-reload
```

**Habilite e inicie o Inventory.service:**
```shell
sudo systemctl enable inventory.service && sudo systemctl start inventory.service
```



## 7. Operação e Manutenção

Rotinas de manutenção e monitoramento são essenciais para garantir a integridade, a atualização e a segurança contínua dos dados gerenciados pelo INVENTORY.

### 7.1 Rotinas de Manutenção Recomendadas

• **Diária:** Executar o script coletor de dados (`python3 utils/get_data.py`) para garantir que o inventário de ativos permaneça atualizado.
• **Semanal:** Realizar o backup dos arquivos JSON de inventário localizados no diretório `data/inventory/`.
• **Mensal:** Conduzir uma auditoria dos usuários e acessos registrados para garantir a conformidade com as políticas de segurança.
• **Anual:** Renovar os certificados TLS/SSL para manter a segurança da comunicação HTTPS.

### 7.2 Logs do Sistema

Os logs são ferramentas críticas para o monitoramento da saúde do sistema e para a solução de problemas.

• `info.log`: Registra informações gerais sobre a execução da aplicação.
• `warning.log`: Armazena alertas e avisos que não são erros críticos, mas que podem requerer atenção.
• `error.log`: Armazena erros e exceções que ocorrem durante a operação.
• `security.log`: Registra eventos de segurança, como tentativas de login (bem-sucedidas e falhas), ativação de MFA e bloqueios de IP.
• `audit.log`: Fornece uma trilha de auditoria de acessos e atividades realizadas pelos usuários na plataforma.

### 7.3 Solução de Problemas Comuns

| Problema Comum          | Ação Recomendada                                                                                                                        |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| **Dados não atualizam** | Verifique se o coletor de dados (`get_data.py`) está sendo executado corretamente. Execute-o manualmente para forçar uma sincronização. |
| **Erro de certificado** | Confirme se os caminhos `SSL_CERT_PATH` e `SSL_KEY_PATH` no arquivo `.env` estão corretos e se os arquivos de certificado existem.      |
| **Acesso negado**       | Verifique se o endereço IP de origem do acesso está incluído nas faixas permitidas pela variável `ALLOWED_IP_RANGES`.                   |

## 8. Melhorias Futuras

O **INVENTORY** é um projeto em desenvolvimento ativo, com um _roadmap_ claro para aprimoramentos focados em escalabilidade, integração e segurança, garantindo sua relevância e robustez a longo prazo.

| Projeto                     | Descrição                                                                                                                                                                                                                                               |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Containerização**         | - Criação de uma imagem Docker oficial e uso de Docker Compose para simplificar a orquestração e a implantação do ambiente.                                                                                                                             |
| **Backend e Performance**   | - Implementação de Redis para cache de dados, visando melhorar a velocidade da interface.<br>- Criação de uma API REST para facilitar integrações com sistemas externos.<br>- Suporte a bancos de dados relacionais (SQL) para maior escalabilidade.    |
| **Frontend e UX**           | - Implementação de WebSockets para a atualização de dashboards em tempo real.<br>- Melhoria da responsividade da interface para dispositivos móveis.                                                                                                    |
| **Segurança e Integração:** | - Implementação de criptografia para os arquivos JSON de inventário em repouso.<br>- Integração com serviços de diretório (LDAP/Active Directory) para autenticação centralizada.<br>- Integração com sistemas de tickets (Jira, ServiceNow, etc.).<br> |
_Essas melhorias planejadas reforçam o compromisso do projeto com a evolução contínua._

## 9. Conclusão

O sistema **INVENTORY** preenche uma lacuna estratégica ao eliminar a cegueira sobre os ativos de TI, transformando os dados brutos de telemetria coletados pelo **Wazuh** em uma plataforma centralizada de visualização, busca e auditoria. Ele oferece uma _solução leve e segura_ que se integra de forma transparente a infraestruturas existentes, _sem a necessidade de agentes adicionais._




