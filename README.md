

https://github.com/user-attachments/assets/615c6e5c-acf0-4863-b636-b48631b17d3b


## 1. Apresentação

O **INVENTORY** é uma solução para a gestão centralizada do inventário de máquinas corporativas, desenvolvida para ambientes que exigem alta visibilidade, rastreabilidade e segurança. O sistema transforma os dados de telemetria brutos coletados pela sua plataforma **Wazuh** (via _SysCollector_) em uma **Interface Web Segura e Moderna**, complementada pelo **NetScope** um mapa de topologia que documenta também os ativos que não têm agente.

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img height="260" width="960" src="https://github.com/Maarckz/Inventory/blob/main/Images/I1_Inventory.gif?raw=true"/>
</div>

O objetivo principal do INVENTORY é eliminar a "cegueira" sobre os ativos de TI, fornecendo às equipes de segurança, operações e _compliance_ uma fonte única e confiável de informação sobre o estado, _hardware_, _software_ e segurança de cada dispositivo.

A principal vantagem reside na **utilização dos agentes nativos do Wazuh**, eliminando a necessidade de instalar _softwares_ adicionais nos _endpoints_ e, consequentemente, **reduzindo a superfície de ataque** e o _overhead_ operacional. Para os ativos que não podem receber agente (impressoras, switches, câmeras, IoT), o **NetScope** cobre a lacuna com descoberta de rede própria e ficha de documentação por dispositivo.

<video width="600" controls>
  <source src="https://github.com/user-attachments/assets/615c6e5c-acf0-4863-b636-b48631b17d3b" type="video/mp4">
  Seu navegador não suporta vídeo.
</video>


### 1.1. Objetivos da Solução

Os principais objetivos do sistema **INVENTORY** são:

- **Centralizar informações de inventário de TI** de dispositivos corporativos.
- **Garantir rastreabilidade e auditoria completa** dos ativos.
- **Oferecer dashboards interativos** para equipes de segurança e TI.
- **Permitir a integração com outros sistemas** corporativos (CMDB, SIEM, DLP).
- **Agrupar informações do host** como processos, serviços, portas abertas e programas instalados.
- **Suportar ambientes heterogêneos** (Linux, Windows, servidores e estações de trabalho) em empresas de pequeno e médio porte.
- **Documentar a topologia de rede** com o NetScope — inclusive ativos sem agente Wazuh.
- **Alertar proativamente** sobre riscos (conflitos de IP/MAC, portas de risco, SO sem suporte, agentes offline) pela Central de Notificações.

---

## 2. Arquitetura da Solução e Fluxo de Dados

A arquitetura do **INVENTORY** segue um modelo de três camadas robusto: **coleta**, **armazenamento relacional** e **apresentação**. Este desacoplamento permite que o coletor e a aplicação web sejam mantidos e escalados de forma independente. A adoção de um banco de dados **PostgreSQL** (containerizado via Docker, com cache opcional em **Redis**) como camada de persistência provê um repositório de dados confiável, estruturado e escalável, superando as limitações de performance e integridade de modelos baseados em arquivos locais.

1. **Coleta de Dados (Wazuh Collector):** o processo se inicia com o componente coletor, que se conecta de forma segura à API REST do Wazuh Manager. Utilizando o módulo _SysCollector_, ele extrai informações dos agentes, incluindo detalhes de hardware, sistema operacional, configurações de rede, portas abertas, pacotes de software e processos em execução. Em paralelo, o **NetScope** descobre e documenta os dispositivos da rede por _ping sweep_ e **ARP de baixo nível** — sem depender do Wazuh.

2. **Armazenamento (PostgreSQL Database):** os dados coletados são processados, estruturados e persistidos em um banco de dados relacional **PostgreSQL** (com `data/postgres` como volume). Essa abordagem permite transações seguras, consultas complexas rápidas e uma base sólida para dashboards em tempo real e uso multiusuário. Listas e estatísticas do dashboard passam pelo **cache Redis** (opcional, com fallback automático em memória).

3. **Apresentação e Análise (Flask App):** a aplicação web, desenvolvida em Flask, conecta-se ao banco para recuperar e exibir as informações em uma interface interativa: dashboards estatísticos com atualização automática, painéis de listagem de máquinas, mapa de topologia, busca avançada, relatórios consolidados, central de notificações e assistente de IA.

**Fluxo de operação:**

```text
Wazuh Manager (API REST / SysCollector)          Rede local (camada 2)
       │                                                │
       └─ Coleta: hardware, SO, rede, portas,           └─ Descoberta: ping sweep +
          pacotes, processos                               ARP de baixo nível (NetScope)
               │                                                │
               ▼                                                ▼
        Coletor Python  ◄────────────────────────────  NetScope Engine
       │  Normaliza e estrutura os dados               │  Deduplica, classifica e
       ▼                                               ▼  documenta os dispositivos
┌─────────────────────────────────────────────────────────────────┐
│        PostgreSQL (Docker)  +  Cache Redis (opcional)           │
└─────────────────────────────────────────────────────────────────┘
               │
               ▼
        Flask Web App (HTTPS)
       │  Consultas SQL + regras de negócio + Gateway de API
       ▼
┌─────────────────────────────────────────────────────────────────┐
│  Dashboard · Painel · Busca · NetScope · Notificações · IA · PDF │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Componentes Principais

A arquitetura é materializada por componentes que trabalham em conjunto: o **Módulo Coletor**, o **Banco de Dados PostgreSQL**, o **NetScope** e a **Aplicação Web**. A solução mantém o padrão de arquitetura _MVC (Model-View-Controller)_, prática que impõe a separação de interesses: a lógica de manipulação de dados (gerida pelo banco) fica isolada da camada de apresentação, reduzindo a superfície de ataque e facilitando a manutenção.

### 3.1. Módulo Coletor (INVENTORY Collector)

O Coletor de Dados é o responsável pela extração das informações de inventário, atuando como a interface de comunicação entre o sistema *INVENTORY* e o ambiente _Wazuh_. Sua função é automatizar a coleta e a estruturação dos dados, respeitando a paginação real da API (sem limite artificial de agentes) e operando de forma _thread-safe_.

```text
Dados Coletados:

- Informações Básicas
    - Hostname
    - Agent ID
    - Sistema Operacional (+ versão e kernel)
    - Arquitetura
    - Serial da placa
    - Última varredura
    - Grupos do Wazuh
- Hardware
    - CPU (modelo completo)
    - Núcleos
    - Memória RAM
- Rede
    - Interfaces de rede
    - Endereço MAC
    - Endereço IP
    - Portas de rede abertas
    - Configurações de rede
- Software
    - Pacotes instalados
    - Processos em execução
- Classificação de Atividade
    - Dispositivos classificados como ativos ou inativos
      conforme a última sincronização.
```

| Função | Detalhamento |
| --- | --- |
| **Interface com a API do Wazuh** | Realiza a coleta e listagem de dados dos agentes monitorados, utilizando o módulo _SysCollector_ do Wazuh, com paginação real. |
| **Autenticação** | Utiliza um Token JWT (JSON Web Token) para garantir o acesso seguro e autenticado à API do Wazuh. |
| **Listagem de Agentes** | Recupera a lista de todos os dispositivos monitorados via API. |
| **Dados Coletados** | Extrai informações de hardware (CPU, RAM), software (pacotes instalados), rede (interfaces, portas abertas), processos e detalhes do agente (status, hostname, ID, grupos). |
| **Armazenamento** | O coletor insere e atualiza os registros diretamente no **banco relacional PostgreSQL**, garantindo integridade, consistência e suporte a múltiplas sessões simultâneas. |
| **Agendamento** | A frequência da coleta é configurável na interface (5 min a 24 h) no **Painel de Sincronização** das Configurações — sem reiniciar a aplicação. |

### 3.2. NetScope (Mapeamento de Rede)

O NetScope é o módulo de **topologia e documentação de rede** que complementa o Wazuh: enquanto o coletor enxerga apenas hosts com agente, o NetScope descobre **qualquer dispositivo IP** da rede — impressoras, switches, câmeras, IoT, servidores sem agente — e permite documentá-los (responsável, departamento, local, asset tag, lacre, tipo, vínculo de switch/porta/VLAN).

| Função | Detalhamento |
| --- | --- |
| **Descoberta** | _Ping sweep_ tradicional + **varredura ARP complementar** (princípio do netdiscover, 100% Python stdlib) + **Monitor ARP** passivo entre scans. Hosts que bloqueiam ICMP entram com o selo **ARP**. |
| **Varredura de Portas** | Connect scan TCP em todas as 65.535 portas (com banner do serviço) + probe UDP, estilo nmap e sem dependências. Até **3 varreduras em paralelo**, com proteção contra esgotamento de file descriptors. |
| **Documentação** | Ficha completa por dispositivo: 16 tipos de ativo, usuário/departamento/local, asset tag, lacre, agente "não aplicável", vínculo de switch (porta + VLAN) com espelhamento bidirecional. |
| **Integridade** | Detecção de **conflitos de IP e MAC**, marcação de **duplicados** e **lixeira** com restauração — o scan nunca apaga mais nada sozinho. |
| **Integração** | Os dados alimentam o dashboard, a busca avançada, o relatório PDF, as regras de notificação e o Assistente IA. |

### 3.3. Aplicação Web (Flask)

A Aplicação Web é a camada de processamento, gerenciamento, visualização e gestão da solução. Acessível via navegador (HTTPS), conta com:

- **Autenticação e Gestão de Identidade**
  - Senhas protegidas com hash bcrypt.
  - **Gerenciador de Contas** e funcionalidade de **Troca de Senha** (com medidor de força).
  - Bloqueio de IP após tentativas falhas configuráveis.
  - Expiração automática da sessão por inatividade.
  - Autenticação Multifator (MFA TOTP) com códigos de recuperação.
- **Dashboard Estatístico (Tempo Real)**
  - Atualização automática a cada 2 minutos sem recarregar a página.
  - 19 cards (KPIs, gráficos e tabelas) com **layout arrastável** persistido por usuário.
- **Painel e Busca de Ativos**
  - Lista completa de dispositivos com filtros avançados.
  - **Busca Avançada** com sintaxe de tags (ex.: `ports:445`, `os:Windows`).
  - **Controle de Máquinas Legadas** para gestão de ativos antigos.
- **NetScope** — mapa interativo da rede com documentação por ativo (seção 5.4).
- **Central de Notificações + Assistente IA** no botão flutuante (FAB) — seções 5.5 e 5.6.
- **Internacionalização** — **8 idiomas** com interface RTL para árabe.
- **Detalhes e Relatórios** — visão detalhada por host e relatório PDF consolidado.

| Função | Detalhamento |
| --- | --- |
| **Framework** | Construída sobre o micro-framework **Flask** (Python), com **SQLAlchemy** sobre PostgreSQL e cache opcional em **Redis**. |
| **Interface** | Desenvolvida com a tríade da web, usando **ECharts/Chart.js** para gráficos interativos e **Font Awesome** para ícones — experiência moderna, responsiva e com tema claro/escuro. |
| **Funcionalidades** | Dashboard em tempo real, NetScope, multi-idioma (8), gestão de contas, MFA, busca avançada, notificações com motor de regras, assistente de IA e exportação de relatórios em PDF. |
| **Segurança** | Hash bcrypt, MFA TOTP, controle de acesso por faixas de IP, headers de segurança HTTP e **Gateway de API** que torna as rotas de API não enumeráveis (seção 7.5). |

---

## 4. Estrutura de Diretórios

A organização lógica separa a aplicação (núcleo `core/`, rotas `routes/`, serviços `services/`, utilitários `utils/`), os dados persistentes (`data/`), os logs (`logs/`) e os certificados (`ssl/`). Essa separação facilita a manutenção, o backup seletivo e o deployment.

```text
INVENTORY/                        # Diretório raiz do projeto
├── app.py                        # Ponto de entrada principal da aplicação Flask
├── models.py                     # Definição das tabelas do Banco de Dados (SQLAlchemy)
├── migrate_db.py                 # Migração de dados legados (JSON -> PostgreSQL)
├── reset_db.py                   # Script para limpar/resetar o banco de dados
├── requirements.txt              # Dependências Python
├── install.sh                    # Instalação automática (deps, usuário, venv, TLS, banco, systemd)
├── docker-compose.yml            # Orquestração do PostgreSQL (+ Redis) — lê o .env da raiz
├── .env / .env.example           # Variáveis de ambiente (seção 8.2 anota todas)
├── core/                         # Núcleo da aplicação
│   ├── app.py                    # App factory, context processors, hooks globais
│   ├── config.py                 # Configurações e APP_VERSION
│   ├── security.py               # bcrypt, bloqueio de IP, faixas permitidas, CSRF
│   ├── api_gateway.py            # Gateway /gw/<alias> — rotas de API não expostas
│   ├── i18n.py                   # Internacionalização (8 idiomas)
│   ├── bootstrap.py              # Criação do admin inicial e tabelas no boot
│   └── logging_setup.py          # Logs rotativos (info/warning/error/security/audit)
├── routes/                       # Controladores (padrão MVC)
│   ├── auth.py                   # Login, logout, MFA, sessão
│   ├── dashboard.py              # Dashboard e dados dos gráficos
│   ├── machines.py               # Painel, detalhes, legadas
│   ├── netscope.py               # Páginas e API do NetScope
│   ├── settings.py               # Configurações (sync, IA, MFA, relatório...)
│   ├── admin.py                  # Gestão de usuários
│   ├── assistant.py              # Assistente IA (chat, histórico)
│   ├── notifications.py          # Central de notificações e regras
│   └── errors.py                 # Páginas de erro
├── services/                     # Regras de negócio
│   ├── assistant.py              # Assistente IA (contexto, provedor Groq, histórico)
│   ├── notifications.py          # Motor de regras, dedup por estado, cooldown
│   ├── stats.py                  # Estatísticas do dashboard
│   ├── netscope.py               # Store principal do NetScope
│   ├── netscope_core.py          # Núcleo (conflitos, inferência, mesclagem)
│   ├── netscope_discovery.py     # Ping sweep + ARP de baixo nível
│   ├── netscope_engine.py        # Orquestração dos scans
│   ├── netscope_portscan.py      # Varredura de portas TCP/UDP (à prova de FD)
│   ├── netscope_snapshots.py     # Snapshots e comparação de topologia
│   ├── netscope_switches.py      # Portas de switch
│   └── netscope_wazuh_bridge.py  # Ponte Wazuh -> NetScope
├── utils/                        # Utilitários
│   ├── collector.py              # Coletor de dados da API do Wazuh
│   ├── machine_handler.py        # Manipulação lógica de máquinas
│   ├── language.py               # Suporte a internacionalização (8 idiomas)
│   ├── mfa_utils.py              # Funções auxiliares para MFA (TOTP)
│   └── pdf_export.py             # Exportação do relatório PDF consolidado
├── templates/                    # Templates HTML (Jinja2)
│   ├── base.html                 # Layout base (topbar, FAB, toasts, tema)
│   ├── login.html                # Login + intro animada (boot intro)
│   ├── dashboard.html            # Dashboard com cards arrastáveis
│   ├── painel.html               # Listagem de máquinas
│   ├── machine_details.html      # Detalhes do ativo
│   ├── search.html               # Busca avançada
│   ├── netscope.html             # Mapa de topologia
│   ├── settings.html             # Configurações (8 cards)
│   ├── admin_users.html          # Gestão de contas
│   ├── legacy_machines.html      # Máquinas legadas
│   ├── verify_mfa.html           # Verificação de dois fatores
│   └── error.html                # Página de erro
├── static/                       # Arquivos estáticos
│   ├── css/                      # Estilos (base, dashboard, settings, netscope...)
│   ├── js/                       # base.js, dashboard-echarts.js, graph.js, theme.js...
│   └── images/                   # Logos e favicons
├── data/                         # Dados persistentes
│   └── postgres/                 # Volume do banco (dono 999:999 — NÃO editar)
├── logs/                         # Logs de execução e segurança
│   ├── audit.log  error.log  info.log  security.log  warning.log
│   └── flask_sessions/           # Sessões ativas dos usuários
└── ssl/                          # Certificados TLS/SSL
    ├── cert.pem
    └── key.pem
```

---

## 5. Funcionalidades Detalhadas da Aplicação

A interface web do _INVENTORY_ transforma os dados brutos coletados em inteligência acionável para as equipes de TI e segurança. Esta seção descreve **cada tela, para que serve e como usar no dia a dia**.

### 5.1. Dashboard

O dashboard é a visão centralizada e estatística do inventário, projetada para oferecer uma compreensão imediata do ambiente de TI. Ao abrir o sistema, é a primeira tela apresentada — e pode ser reorganizada à vontade.

- **Métricas (KPIs):** total de máquinas, ativos online, offline, cobertura de agentes Wazuh e contagem de não suportados. Os KPIs são arrastáveis pelo próprio card.
- **Gráficos Interativos:** distribuição de sistemas operacionais (com versão e kernel), tipos de processadores, faixas de memória RAM, portas de rede mais comuns e processos com maior recorrência, além da **evolução temporal do status dos agentes**. O clique em um gráfico redireciona para a busca avançada com o filtro correspondente aplicado.
- **Layout arrastável:** os 19 cards (KPIs, gráficos e tabelas detalhadas) são reposicionáveis — pegue pelo card (KPIs) ou pela alça no cabeçalho (gráficos/tabelas) e reorganize entre todas as linhas. O layout fica salvo **no banco, por usuário**.
- **Atualização automática:** os dados se renovam a cada 2 minutos, sem recarregar a página.
- **Resiliência:** um gráfico sem dados (ex.: NetScope vazio) nunca derruba os demais — cada lote renderiza isolado.

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/I2_DASHBOARD.png?raw=true"/>
</div>

### 5.2. Painel de Máquinas e Detalhes de Ativos

O painel fornece a listagem de **todos os dispositivos inventariados**, com informações resumidas e o status de atividade em _tempo real_. É a porta de entrada para a ficha individual de cada ativo.

- A partir da lista, navegue para a **página de detalhes** do ativo, que consolida todas as informações extraídas do Wazuh: hardware, sistema operacional, interfaces de rede e endereços, portas abertas, pacotes instalados e processos em execução.
- A ficha traz também a **documentação do NetScope** (responsável, departamento, local, asset tag, lacre) e o **vínculo de switch** (nome, porta, VLAN), quando documentados.
- As seções da ficha são **colapsáveis**, para facilitar a leitura em telas menores.

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/I3_PAINEL.png?raw=true"/>
</div>

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/I5_DETAILS.png?raw=true"/>
</div>

### 5.3. Sistema de Busca Avançada

A busca avançada é a ferramenta para _threat hunting_, auditoria ou pesquisa simples, permitindo consultas precisas com uma sintaxe baseada em **tags**. Todo gráfico do dashboard clicável leva para cá com o filtro pronto — o fluxo típico é "vi algo no gráfico → clique → resultado na busca".

**Exemplos de sintaxe:**

| Consulta | O que encontra |
| --- | --- |
| `ports:445` | Máquinas com a porta 445 aberta. |
| `inventory:os:Windows` | Dispositivos por sistema operacional. |
| `inventory:packages:chrome` | Máquinas com um pacote específico instalado. |
| `agent_info:10.7.6.20` | Por hostname, IP, status ou ID do agente. |
| `inventory:processes:python` | Processos em execução em um ativo. |
| `ram_gb:9-12gb` | Faixa específica de memória RAM. |
| `groups:Home` | Pelo grupo do Wazuh. |

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/I4_SEARCH.png?raw=true"/>
</div>

### 5.4. NetScope — Topologia e Documentação de Rede

O NetScope apresenta o **mapa visual da rede** com zoom, arraste, menu de contexto e a ficha completa de cada ativo. Os dispositivos documentados aparecem com ícone do tipo, vínculo de switch (porta/VLAN) e o status descoberto pelo scan. Os dados do NetScope alimentam o dashboard, a busca e o relatório PDF — incluindo os ativos **sem agente Wazuh**.

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/NETSCOPE_MAPA.png?raw=true"/>
</div>

#### 5.4.1. Como usar no dia a dia

O fluxo operacional típico do NetScope, do zero ao mapa documentado:

1. **Configurar as redes monitoradas** — botão **`+ Rede`** na barra lateral: informe o CIDR (ex.: `192.168.0.0/24`) e o gateway. As redes configuradas aparecem na sidebar e ficam **clicáveis para edição** (o modal reabre preenchido; o × é quem remove).
2. **Escanear** — botão **Escanear** dispara o _ping sweep_ + varredura ARP das redes configuradas. Hosts que não respondem ping mas respondem ARP entram com o selo **ARP**; o toast do scan informa quantos foram achados só por ARP.
3. **Sincronizar com o Wazuh** — botão **Sincronizar** importa os hosts do inventário para o mapa (e **Ver hosts do Wazuh** lista tudo o que existe na API, inclusive o que ainda não mapeou).
4. **Documentar cada dispositivo** — duplo clique (ou menu de contexto → Editar) abre a **ficha**: tipo (16 opções: servidor, estação, laptop, firewall, switch, hypervisor, storage, VoIP, IoT...), usuário responsável, departamento, localização, asset tag, lacre, notas. Marque **"Agente não aplicável"** em impressoras/switches/câmeras para tirá-los do computo de "sem agente" — a cobertura passa a dividir só os suportados.
5. **Vincular switches** — na ficha, escolha a switch, a **porta** e a **VLAN**; o painel da switch reflete na hora (porta ocupada, contagem ajustada, vínculo antigo liberado). Também é possível associar manualmente: botão **Associar** + `Ctrl+Clique` em dois nós, ou **Inferir conexões** para o sistema sugerir por sub-rede/gateway.
6. **Investir em detalhes** — menu de contexto → **Portas TCP** abre a varredura completa (65.535 portas TCP com banner + UDP); até 3 varreduras rodam em paralelo e o resultado fica salvo no ativo, com data/hora da última varredura. Clicar num dispositivo já escaneado abre o resultado salvo — quem revarra é o botão **Reescanear**.
7. **Vigiar a integridade** — os chips **Conflitos** e **Duplicados** da sidebar acendem em âmbar quando algo exige atenção; clicar abre o modal com os grupos e localiza o dispositivo no mapa.
8. **Registrar o estado** — botão **Snapshots** cria uma fotografia da topologia; depois, **comparar** dois snapshots mostra o diff (adicionados, removidos, alterados) — base da regra de notificação "mudança de topologia".

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/NETSCOPE_FICHA.png?raw=true"/>
</div>

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/NETSCOPE_PORTSCAN.png?raw=true"/>
</div>

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/NETSCOPE_SNAPSHOTS.png?raw=true"/>
</div>

#### 5.4.2. Controles da barra lateral

| Controle | Função |
| --- | --- |
| **Sincronizar / Ver hosts** | Importa os hosts do Wazuh para o mapa / lista todos os hosts da API. |
| **`+ Rede`** | Adiciona um CIDR à descoberta (clicar numa rede existente reabre em modo edição). |
| **Escanear** | _Ping sweep_ + ARP nas redes configuradas. |
| **Inferir conexões** | Sugere vínculos de topologia por sub-rede/gateway (linhas tracejadas = inferidas; sólidas = documentadas). |
| **Atualizar lista / Associar / `+ Novo`** | Recarrega / associa dois nós com Ctrl+Clique / cadastra dispositivo manual. |
| **Tabela de Ativos** | Grade com todas as colunas **ordenáveis** (clique no cabeçalho; IP por octetos), **caixas de seleção** para exclusão em grupo e export CSV. |
| **Portas de switch** | Painel das switches com portas, labels, VLANs e dispositivo conectado por porta. |
| **Snapshots** | Criar, listar, comparar e excluir fotografias da topologia. |
| **Lixeira** | Restaurar ou excluir definitivamente; itens mesclados pelo scan aparecem com o motivo e o sobrevivente. |
| **Exportar CSV / PNG / JSON** | Ativos em CSV, imagem da topologia, dados completos. |
| **Layouts (Tree / Hierárquico / Grade)** | Estilos de visualização — ao trocar, o mapa faz **FIT automático**. |
| **Zoom + / − / Fit** | Controles de navegação do mapa. |

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/NETSCOPE_TABELA.png?raw=true"/>
</div>

#### 5.4.3. Descoberta em baixo nível e automação

- **Varredura ARP complementar:** o scan combina o _ping sweep_ tradicional com a varredura ARP — o mesmo princípio do netdiscover, implementada 100% em Python stdlib (nada é instalado no servidor). Hosts que bloqueiam ICMP entram no mapa com o selo **ARP**.
- **Monitor ARP:** entre os scans, um monitor passivo faz varreduras ARP silenciosas (sem ICMP) e **cadastra hosts novos automaticamente**. O intervalo (5 min a 6 h) e o liga/desliga ficam no **Painel de Sincronização** das Configurações, e a mudança vale a partir do salvamento, sem reiniciar.
- **Painel de Sincronização (Configurações):** reúne os três deslizadores — **Wazuh** (sincronização agendada, 5 min a 24 h), **Ping Sweep** (5 min a 6 h, com ON/OFF) e **ARP Discovery** (5 min a 6 h, com ON/OFF). O botão **Salvar Configuração** grava os três de uma vez e **acorda os loops do backend**; o botão **Sincronizar Agora** executa as 3 ações em sequência (sync + ping + ARP), com cada etapa isolando a própria falha.
- **Nada é apagado pelo scan:** a deduplicação pós-scan (mesmo IP, prefixo de MAC ou hostname) move o "duplicado" para a **lixeira** com o selo "Mesclado automaticamente" (motivo + quem sobreviveu), restaurável — o histórico do parque permanece completo. Com a mesclagem automática **desligada** (padrão), os duplicados apenas ficam marcados com selo âmbar e o chip **Duplicados** filtra a lista.
- **Escudo do agente com 3 estados:** verde = com agente, vermelho = sem agente, **cinza riscado = não suportado** (impressora, switch, câmera) — na lista, no mapa (badge do nó) e na Tabela de Ativos (pílula N/A). A **Cobertura de Agentes** calcula o % sobre os suportados, então dispositivos sem agente possível não derrubam o índice.

#### 5.4.4. Conflitos de IP e MAC

O NetScope verifica continuamente dois tipos de conflito e sinaliza em três lugares (sidebar, lista e mapa):

- **Conflito de IP:** dispositivos ativos anunciando o **mesmo endereço IP** — chip **Conflitos** na sidebar (âmbar quando existe), selo no cartão da lista, badge âmbar "!" no nó do mapa e linha no popover. Clicar num conflito localiza o dispositivo.
- **Conflito de MAC:** o **mesmo endereço MAC em 2+ IPs ao mesmo tempo** (típico de VM/imagem clonada) — detectado combinando o **ARP ao vivo do kernel** (excluindo as MACs das interfaces locais, pois IP alias não é conflito), os **hosts do sync Wazuh** e os dispositivos do NetScope. Os conflitos alimentam as regras de notificação correspondentes (seção 5.6).

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/NETSCOPE_CONFLITOS.png?raw=true"/>
</div>

### 5.5. Assistente IA (FAB)

O **Assistente IA** é o chatbot embutido no botão flutuante (FAB, canto inferior direito), que responde perguntas sobre o ambiente **lendo os dados reais do banco a cada mensagem** — Wazuh, NetScope, switches, conflitos de IP/MAC, portscans recentes e a comparação entre snapshots.

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/IA_CHAT.png?raw=true"/>
</div>

- **O que ele enxerga:** inventário sincronizado do Wazuh **por host** (hostname, IP, SO+versão, grupos, CPU, RAM, portas em escuta, processos e pacotes — com tetos de segurança), dispositivos documentados do NetScope, portas de switch, conflitos, duplicados, snapshots e varreduras de portas recentes **com a lista real de portas**.
- **Como perguntar:** "quantos hosts debian e quais?", "quem está com a porta 445 aberta?", "tem algum processo estranho no SRV-DEB?", "o que mudou entre os dois últimos snapshots?". Em parques pequenos (≤ 3 hosts), perguntas genéricas recebem o detalhe completo de todos os ativos.
- **Respostas com markdown:** o chat renderiza **tabelas** (com cabeçalho fixo e zebra), listas, negrito, `código` e links — de forma segura (todo o texto é escapado antes; links só http/https). A janela mede 540×700 (tela cheia útil no mobile) e o texto é selecionável/copiável.
- **Histórico persistente:** a conversa vive no PostgreSQL **por usuário**, aparece em todas as páginas, sobrevive a refresh/F5 e alimenta o modelo. O botão **"Nova conversa"** (pílula no topo do chat) apaga com confirmação.
- **Configuração (admin):** em **Configurações → Assistente & Notificações → aba IA**: cole a chave da Groq, escolha o **modelo real da sua conta** (datalist alimentado pela API, botão ↻ para atualizar) e use **"Testar conexão"** para validar de verdade antes de salvar. A chave pode viver no `.env` (`GROQ_API_KEY`/`GROQ_MODEL`) — nesse caso ela tem prioridade e o painel mostra a fonte.
- **Rate limit mitigado sozinho:** o servidor tenta antes de avisar — 2 retentativas com backoff (respeitando o `Retry-After`), **cadeia de modelos alternativos** da conta e **chaves extras opcionais** no `.env` (outra org = outra cota). Se ainda assim limitar, o aviso mostra o tempo de espera estimado.
- **Endpoint alternativo:** `GROQ_BASE_URL` no `.env` aceita qualquer serviço OpenAI-compatible (LM Studio, Ollama, vLLM) para redes que bloqueiam a Groq ou para rodar 100% local.
- **Privacidade do modelo:** o modelo não é exposto no chat nem no `/status` — só o admin vê, nas Configurações.

### 5.6. Central de Notificações

O FAB é uma **central com duas abas** — **Notificações** e **Assistente IA** — com badge de não lidas no próprio botão. O motor de notificações foi desenhado com base em boas práticas de cybersecurity, gestão de parque e compliance (OpUtils/Bitsight/ISO 27001) e avalia o ambiente **automaticamente**, com persistência em PostgreSQL.

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/NOTIFICACOES_CENTRAL.png?raw=true"/>
</div>

**As 11 regras nativas:**

| # | Regra | Categoria | O que alerta |
| --- | --- | --- | --- |
| 1 | **Novo dispositivo** | Parque | Um dispositivo nunca visto entrou na rede (nome + IP). |
| 2 | **Dispositivo ausente** | Parque | Ativo não é visto há **7+ dias** (pode ter sido desligado, roubado ou mudado de lugar). |
| 3 | **Conflito de IP** | Segurança | O mesmo IP anunciado por **2+ dispositivos** ao mesmo tempo. |
| 4 | **Conflito de MAC** | Segurança | A mesma MAC aparecendo em **2+ IPs** simultaneamente (VM/imagem clonada). |
| 5 | **Portas de risco** | Segurança | Exposição de portas perigosas — **Telnet, FTP, NetBIOS, SMB, RDP** — descobertas pelo portscan. |
| 6 | **Agente Wazuh offline** | Segurança | Agente parado de reportar (status visível na mensagem). |
| 7 | **SO sem suporte (EOL)** | Compliance | Sistema operacional em fim de vida (sem patches de segurança). |
| 8 | **Duplicados** | Parque | Dispositivos duplicados detectados no NetScope (mesmo IP/hostname/fabricante). |
| 9 | **Mudança de topologia** | Sistema | Diff entre snapshots: novos, removidos e alterados. |
| 10 | **Cobertura de agentes** | Compliance | Cobertura de agentes Wazuh abaixo do mínimo configurado. |
| 11 | **Sem responsável** | Compliance | Dispositivos **sem responsável documentado** na ficha do NetScope (com % do parque). |

**Regras personalizadas (admin):** na aba **Regras** (Configurações → Assistente & Notificações → Central), o admin cria condições próprias sobre os dispositivos do NetScope — campo (nome, IP, MAC, tipo, SO, responsável, departamento, status, portas abertas) × operador (contém, igual, diferente, começa com, termina com) × valor, com gravidade e **cooldown próprio (1–720 h)**, teto de 20 regras. O motor avalia junto das nativas, com a mesma deduplicação.

**Anti-spam por dedup de estado:** ler/excluir **não traz o mesmo alerta de volta** — o motor mantém a impressão digital do último estado emitido de cada evento: estado igual ⇒ nunca re-notifica; estado diferente ⇒ é evento novo (com cooldown anti-flapping); evento que deixa de existir vira **RESOLVIDO** (se voltar, é alerta novo de verdade). Na primeira verificação após atualizar, o estado atual vira linha de base **sem recriar nada**.

**Ações da central:** **Verificar agora** (força uma avaliação), **Marcar todas como lidas**, **Excluir lidas** (admin) e **lixeira individual** no hover de cada notificação — tudo com confirmação e badge sincronizado.

### 5.7. Geração de Relatórios (PDF Consolidado)

O relatório PDF é **um único documento com o máximo de dados do sistema**, sem repetições: cada ativo aparece uma única vez. Gerado em **Configurações → Exportar Relatório**, no idioma da sessão.

- **Capa "print do dashboard":** KPIs (total, agentes online/offline, sem agente) e donuts de cobertura, status e sistemas operacionais.
- **Inventário Consolidado:** uma tabela única por ativo — hostname, **MAC**, IP, tipo, sistema (nome + versão), status do agente, **fabricante/modelo**, **documentação do NetScope** (usuário, departamento, local, asset tag, lacre) e **vínculo de switch** (nome, porta, VLAN).
- **Rankings do Inventário:** processos, pacotes, portas, uso de RAM, sistemas operacionais **com versão e kernel**, modelos de CPU completos, faixas de RAM, grupos do Wazuh e a tabela **Agentes Wazuh — Status e Atualização** (status bruto + idade do keepalive).
- **Topologia da Rede:** árvore radial vetorial (página própria) com a mesma paleta da tela — linha sólida: vínculo documentado; tracejada: inferido pela sub-rede.
- **Configuração de Switches:** tabelas de portas configuradas (Porta | Label | VLAN | Dispositivo conectado).
- **Detalhamento Técnico:** fichas dos hosts **com agente** — inventário do syscollector (hardware, sistema, interfaces, endereços IP, portas abertas) + documentação do NetScope. Dispositivos sem agente aparecem na tabela consolidada — não há fichas "soltas" só com IP.

> [!NOTE]
> Devido a uma restrição de segurança da própria API do Wazuh, a sincronização pode ser lenta de acordo com a quantidade de hosts a serem sincronizados.

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://raw.githubusercontent.com/Maarckz/Inventory/refs/heads/main/Images/X5_SYNC.png"/>
</div>

### 5.8. Sincronização Automática e Manual

A área de configuração permite definir a **ingestão dos dados em períodos específicos** (sincronização automática) ou disparar uma **sincronização manual** sempre que necessário, garantindo que as informações estejam sempre atualizadas.

- **Onde configurar:** Configurações → **SYNC com Wazuh** → botão **Configurar Sync** (Painel de Sincronização com os 3 deslizadores — Wazuh, Ping Sweep, ARP Discovery — e o toggle de mesclagem automática).
- **Sincronizar Agora:** executa na hora as 3 ações (sync Wazuh + ping sweep + ARP discovery); redes não configuradas pulam ping/ARP.
- **Pós-sync:** a página do NetScope **recarrega sozinha** quando as 3 ações terminam (polling de status no servidor).

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://raw.githubusercontent.com/Maarckz/Inventory/refs/heads/main/Images/X5_SYNC.png"/>
</div>

### 5.9. Idiomas, Tema e Intro do Login

- **8 idiomas:** Português (BR), Inglês, Espanhol, Hindi, **Russo, Mandarim (中文), Árabe (interface RTL) e Francês** — no seletor do topo (presente também no login). As notificações, toasts e a busca traduzem no idioma da sessão; o relatório PDF dos idiomas novos sai em inglês (limitação de fontes do gerador).
- **Tema claro/escuro:** toggle no topo, respeitando a preferência do sistema e persistindo por usuário. Todos os componentes (mapa, modais, toasts, chat, tabelas) têm variante própria para o escuro.
- **Intro do login (boot intro):** ao abrir o sistema, uma animação de abertura apresenta a identidade visual — com brilho que percorre **dentro dos glifos da logo**. Ela toca **1× por navegador a cada nova versão** (nada de replay a cada login), é **pulável** (clique ou qualquer tecla), respeita o "reduzir animação" do sistema (`prefers-reduced-motion`) e tem fail-safe: mesmo sem JavaScript o overlay some e o login fica acessível.
- **Login com fundo animado:** o fundo da tela de login é um SVG animado servido **offline**, com variante própria para o tema escuro — e o "Credenciais inválidas" aparece como toast no padrão do sistema, traduzido no idioma selecionado.

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/TEMA_ESCURO.png?raw=true"/>
</div>

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/LOGIN_INTRO.png?raw=true"/>
</div>

---

## 6. Onde Configurar o Quê

Toda a configuração operacional mora na página **Configurações** (menu do topo). A página admin tem **8 cards** — a tabela abaixo diz o que cada um faz e a qual seção deste README corresponde:

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/CONFIG_WHERE.png?raw=true"/>
</div>

| # | Card | Botão | O que configura | Onde no README |
| --- | --- | --- | --- | --- |
| 1 | **SYNC com Wazuh** | `Configurar Sync` | Credenciais da API do Wazuh, **Painel de Sincronização** (3 deslizadores: Wazuh 5 min–24 h · Ping Sweep 5 min–6 h · ARP Discovery 5 min–6 h, com ON/OFF), toggle de **mesclagem automática** e **Sincronizar Agora** (executa as 3 ações). | §5.8, §5.4.3 |
| 2 | **Assistente & Notificações** | `Configurar` | Modal com 3 abas: **IA** (chave Groq, modelo real da conta com ↻, testar conexão), **Central** (preferências por categoria, mínimo de cobertura, dias de ausência) e **Regras** (regras personalizadas do admin, até 20, cooldown 1–720 h). | §5.5, §5.6 |
| 3 | **Exportar Relatório** | `Exportar PDF` | Gera o **relatório PDF consolidado** do parque completo, no idioma da sessão. | §5.7 |
| 4 | **Segurança** | `Configurar MFA` | Ativa/desativa a **MFA TOTP** da conta, com QR code e códigos de recuperação. | §7.2 |
| 5 | **Alterar Senha** | `Alterar Minha Senha` | Troca a própria senha, com medidor de força e regras de complexidade. | §7.1 |
| 6 | **Gestão de Usuários** (admin) | `Gerenciar Usuários` | Cria/exclui usuários, define papel (**comum = observador** / **admin**), exige troca de senha no 1º acesso. | §7.3 |
| 7 | **Máquinas Legadas** | `Gerenciar` | Cadastra/edita/remove registros de ativos antigos que não sincronizam mais via Wazuh. | §1, §5.2 |
| 8 | **Apoie o projeto** | link | Apoia o desenvolvimento do INVENTORY. | — |

> [!TIP]
> Usuário **comum (observador)** vê uma página reduzida: Assistente & Notificações, Exportar Relatório, Alterar Senha — os demais cards são exclusivos de admin.

**Configurações que moram fora da página de Configurações:**

| O quê | Onde |
| --- | --- |
| Idioma da sessão | Seletor no topo (globo), também na tela de login. |
| Tema claro/escuro | Toggle no topo da barra. |
| Redes monitoradas (CIDR) | NetScope → botão `+ Rede` (clicar numa rede reabre em modo edição). |
| Credenciais Wazuh / banco / HTTPS / faixas de IP / Groq / Gateway | Arquivo **`.env`** da raiz (seção 8.2). |
| Serviço, porta e sandbox | `inventory.service` do systemd (seção 9). |

---

## 7. Arquitetura de Segurança

A segurança emprega uma estratégia de **"defesa em profundidade"**, com controles nas camadas de autenticação, sessão, rede, API e transporte.

### 7.1. Autenticação e Gestão de Sessões

- **Hash bcrypt:** as senhas são armazenadas com bcrypt, protegendo contra _rainbow table_ e força bruta offline.
- **Controle de força bruta:** bloqueio de IP após um número configurável de tentativas de login falhas.
- **Verificação de IP de origem:** cada requisição valida o IP da sessão, mitigando sequestro de sessão.
- **Timeout automático:** as sessões expiram por inatividade — e qualquer fetch que bater num endpoint protegido com sessão expirada **leva o navegador ao login** com o toast "Sua sessão expirou" (inclusive no NetScope).
- **CSRF e cookie Secure:** proteção CSRF nos formulários e cookie de sessão marcado Secure em HTTPS.
- **Troca de senha obrigatória:** possível exigir que o usuário troque a senha no primeiro acesso (flag por usuário na Gestão de Usuários).

### 7.2. Autenticação Multifator (MFA)

Suporte a **MFA baseada em TOTP**, compatível com aplicativos como o _Google Authenticator_, configurada por leitura de QR code e com **códigos de recuperação** (backup). A ativação/desativação fica em Configurações → Segurança.

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/MFA.png?raw=true"/>
</div>

### 7.3. Gerenciamento de Contas

Área de contas de usuários para descentralizar as atividades dos analistas: é possível criar **usuários comuns (observadores)** ou **administradores**, com troca de senha obrigatória no primeiro acesso quando desejado. A auditoria das ações dos usuários fica no `audit.log`.

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/X3_CONTAS.png?raw=true"/>
</div>

<div align="left">
  <a href="https://github.com/maarckz/Inventory" target="_blank"><img src="https://github.com/Maarckz/Inventory/blob/main/Images/X4_SENHA.png?raw=true"/>
</div>

### 7.4. Controle de Acesso à Rede

O acesso à interface web pode ser restrito a faixas de rede específicas pela variável `ALLOWED_IP_RANGES` (lista de CIDRs separados por vírgula), permitindo que apenas usuários de redes confiáveis (como a rede corporativa interna) acessem a aplicação. Atrás de proxy reverso, use `TRUST_PROXY=1` para que allowlist, rate limit e logs enxerguem o **IP real do cliente** em vez do IP do proxy.

### 7.5. Gateway de API — rotas não expostas

As rotas de API (`/netscope/api/*` e `/get_chart_data`) **não respondem diretamente**: um _hook_ global as derruba com **404 genérico** — o mesmo corpo de uma página inexistente —, então não há como descobrir/enumerar endpoints por tentativa e erro. O frontend autenticado fala pela rota única **`/gw/<alias>`**, um proxy de transmissão interno (**usuário → gateway → aplicação**):

- o `<alias>` é um **HMAC-SHA256 de 12 dígitos** derivado do segredo do boot — muda a cada reinício, não pode ser recomputado offline e não carrega nenhum pedaço do caminho real;
- o caminho verdadeiro viaja no **header `X-GW-Path`** — nunca aparece na URL (aba de rede, histórico do navegador, logs de proxy);
- o wrapper global de `fetch` (base.js) reescreve as chamadas automaticamente: os call sites não mudaram uma linha;
- o subrequest sai **por loopback** com assinatura HMAC própria e exige sessão válida — sem sessão, `/gw/*` também devolve 404 genérico;
- liga/desliga por **`API_LOCK`** no `.env` (padrão `1`). Com `API_LOCK=0` as rotas reais voltam a responder e o frontend nem recebe aliases.

### 7.6. Segurança da Camada de Transporte e Auditoria

A comunicação é protegida com **TLS/SSL** (HTTPS). A aplicação também implementa **headers de segurança HTTP** e mantém logs detalhados de segurança (`security.log`) e auditoria (`audit.log`), registrando os eventos relevantes para rastreabilidade completa.

---

## 8. Instalação

> **OBS:** instalação validada em **Ubuntu 22.04/24.04** (Debian e derivados). O `install.sh` faz tudo — e **cada passo dele está descrito manualmente na seção 8.3**, para quem prefere (ou precisa) controlar cada comando.

### 8.1. Instalação Automática — `install.sh` (recomendado)

Um único comando prepara **tudo**: dependências do sistema, usuário da aplicação, venv, dependências Python, `.env`, certificados TLS, pasta do banco (dono 999:999), containers Docker e o serviço systemd:

```shell
# extraia o projeto e rode (como root):
cd Inventory
sudo bash install.sh
```

O script executa, na ordem:

| Passo | O que faz |
| --- | --- |
| **1. Dependências** | Instala `docker.io`, `docker-compose-v2`, `python3-venv`, `python3-pip` e `openssl` (só o que faltar) e ativa o daemon do Docker. |
| **2. Usuário da aplicação** | Cria o usuário de sistema `inventory` (sem shell de login) — a aplicação NUNCA roda como root. |
| **3. Pasta** | Instala em `/opt/Inventory` (ou na própria pasta com `--here`; use `APP_DIR=` para escolher outro caminho) e ajusta o dono. |
| **4. .env** | Cria o `.env` a partir do `.env.example` com `SECRET_KEY`/`SESSION_SALT` **gerados por instalação** (um `.env` existente é preservado). |
| **5. TLS** | Gera certificado self-signed (`ssl/cert.pem` + `ssl/key.pem`) se não existirem. |
| **6. Banco** | Cria `data/postgres` com dono **999:999** (usuário postgres do container) — o ajuste que antes era manual. |
| **7. venv** | Cria `.venv` e instala o `requirements.txt` como usuário `inventory`. |
| **8. Docker** | `docker compose up -d` (PostgreSQL + Redis) e aguarda os healthchecks ficarem saudáveis. |
| **9. Serviço** | Cria e habilita o `inventory.service` (systemd, com sandbox) e inicia a aplicação. Com `--no-service`, imprime o comando manual. |

**Opções:** `sudo bash install.sh --here` (instala na pasta atual) · `sudo bash install.sh --no-service` (pula o systemd) · `sudo APP_DIR=/srv/Inventory bash install.sh`.

O script é **idempotente**: rodar novamente sobre uma instalação existente apenas atualiza dependências e reinicia o serviço — os dados do banco (`data/postgres`) não são tocados.

### 8.2. Configuração — Environment (`.env`)

Todas as variáveis aceitas, com a anotação de cada uma (o `.env.example` do projeto traz o mesmo conteúdo comentado — o `install.sh` o copia para `.env`):

```shell
###########################################
## CONFIGURAÇÕES DE SEGURANÇA E AMBIENTE ##
###########################################

# Chave de assinatura das sessões/cookies — TROQUE por um valor longo e
# aleatório (o install.sh gera uma por instalação)
SECRET_KEY=MINHACHAVE

# Sal usado na derivação do sid de sessão — troque também
SESSION_SALT=supersecreta_altere_esta_chave_salt!

# Diretório de logs (info/warning/error/security/audit)
LOG_DIR=logs

###########################
## CONFIGURAÇÕES DE REDE ##
###########################

# Endereço e porta onde a aplicação escuta
HOST=0.0.0.0
PORT=8000
DEBUG=False

############################
## CONFIGURAÇÕES DE HTTPS ##
############################

# USE_HTTPS=true exige os certificados abaixo. Sem eles o app SOBE EM
# HTTP (com aviso nos logs) e o cookie Secure fica DESLIGADO
# automaticamente para o login funcionar — veja SESSION_COOKIE_SECURE.
USE_HTTPS=True
SSL_CERT_PATH=ssl/cert.pem
SSL_KEY_PATH=ssl/key.pem

######################################
## PERMITIR IPS DE FAIXA ESPECÍFICA ##
######################################

# Lista de redes CIDR autorizadas a acessar o sistema (separadas por vírgula)
ALLOWED_IP_RANGES=0.0.0.0/0

#####################################
## PROXY REVERSO (nginx, caddy...) ##
#####################################

# 0 = o app é acessado DIRETO pelo cliente (padrão).
# 1 (ou mais) = existem N proxies confiáveis na frente do app — o
# remote_addr passa a vir do X-Forwarded-For e rate limit / allowlist
# de IP / logs de auditoria passam a enxergar o IP do CLIENTE.
TRUST_PROXY=0

# Override manual do cookie Secure (opcional — vazio = automático):
#   true  = força Secure (obrigatório atrás de proxy HTTPS)
#   false = nunca Secure (ambiente interno puro HTTP)
#SESSION_COOKIE_SECURE=

#############################
## API DO WAZUH (manager)  ##
#############################

# O Inventory coleta o inventário (syscollector) destas credenciais.
WAZUH_PROTOCOL=https
WAZUH_HOST=192.168.0.26
WAZUH_PORT=55000
WAZUH_USER=wazuh-wui
WAZUH_PASSWORD=troque_a_senha_do_wazuh_aqui

###############################
## BANCO DE DADOS POSTGRESQL ##
###############################

# Deve casar com o docker-compose.yml da RAIZ do projeto (serviço "db").
# Suba os containers com: docker compose up -d (a partir da raiz)
DB_USER=inventorydb
DB_PASS=senhadoinventorydb
DB_HOST=localhost
DB_PORT=5432
DB_NAME=inventory_db

#######################################
## CACHE REDIS (opcional)            ##
#######################################

# Banco intermediário de CACHE (container "cache" do docker-compose.yml).
# Guarda as listas do dashboard JÁ PROCESSADAS, compartilhadas entre os
# workers, com invalidação automática a cada sync do Wazuh. Se ficar
# vazio/indisponível a aplicação CONTINUA funcionando (fallback em
# memória do próprio processo).
REDIS_URL=redis://localhost:6379/0

# Validade (segundos) do cache — rede de segurança: a invalidação real
# acontece no fim de cada sync do Wazuh.
#REDIS_TTL_MACHINES=3600
#REDIS_TTL_STATS=40

########################################
## ADMIN INICIAL (só com banco vazio) ##
########################################

# O sistema NUNCA redefine a senha de um admin que já existe.
# Com o banco vazio:
#   ADMIN_PASSWORD vazio  → gera senha forte, grava no .env e exige
#                           troca no 1º login (comportamento seguro).
#   ADMIN_PASSWORD=X      → usa X como senha inicial.
ADMIN_PASSWORD=Meuadmin123

# true  = obriga trocar a senha no 1º login
# false = entra direto com a senha acima
# vazio = força troca apenas quando a senha foi gerada automaticamente
ADMIN_MUST_CHANGE_PASSWORD=

############################################################
## GATEWAY DE API — rotas de API não expostas             ##
############################################################

# Ligado (padrão): o acesso DIRETO às rotas de API (/netscope/api/*,
# /get_chart_data) responde 404 genérico — as rotas não podem ser
# enumeradas de fora. O frontend autenticado fala pela rota única
# /gw/<alias> (proxy interno usuário > gateway > aplicação); o alias é
# um HMAC que muda a cada boot e o caminho real nunca aparece na URL.
# Desligue (API_LOCK=0) só para depurar integrações externas.
API_LOCK=1

############################################################
## ASSISTENTE IA — GROQ                                   ##
############################################################

# Chave da API da Groq para o Assistente IA (FAB). Tendo esta variável
# no .env, ela TEM PRIORIDADE sobre a chave salva no painel de
# Configurações → Assistente IA (que continua funcionando sem .env).
# Deixe vazia para usar apenas o painel.
GROQ_API_KEY=

# Modelo do provedor (default do painel: openai/gpt-oss-20b).
# Modelos populares da Groq (docs: https://console.groq.com/docs/models):
#   openai/gpt-oss-20b · openai/gpt-oss-120b · llama-3.1-8b-instant
#   qwen/qwen3-32b · moonshotai/kimi-k2-instruct
# O painel busca a lista REAL de modelos da sua conta (campo Modelo →
# botão ↻), então não há mais erro de digitação 404.
GROQ_MODEL=

# Endpoint alternativo (OPCIONAL): use apenas se o seu servidor não
# alcança a API da Groq (firewall/proxy corporativo) ou se quiser um
# LLM local OpenAI-compatible (ex.: http://localhost:1234 — LM Studio,
# http://localhost:11434/v1 — Ollama). Vazio = endpoint oficial Groq.
# Aceita com ou sem o sufixo /openai/v1 (é adicionado automaticamente).
GROQ_BASE_URL=

# ── MITIGAÇÃO DE RATE LIMIT ────────────────────────────────────────
# O servidor já TENTA sozinho: 2 retentativas com backoff (respeitando
# o Retry-After da Groq) + modelos alternativos da conta (limites
# independentes por modelo). Para aguentar picos de uso, cadastre
# CHAVES EXTRAS de outra org/projeto da Groq (cada org tem cota
# própria). Elas entram na cadeia por último, só quando a principal
# seguir limitada:
#   GROQ_API_KEY_2=gsk_outra                (separadas por vírgula)
#   GROQ_API_KEY_3=gsk_outra                (ou individualmente)
GROQ_API_KEY_2=
GROQ_API_KEY_3=
```

**As credenciais da API devem ser consultadas dentro da pasta de instalação do WAZUH:**

```shell
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt
```

> **Importante:** as variáveis `DB_USER`/`DB_PASS`/`DB_NAME` do `.env` alimentam **tanto a aplicação quanto o container** (o `docker-compose.yml` lê o `.env` da raiz). Se trocar a senha do banco, remova `data/postgres` antes do primeiro `docker compose up` para recriar o banco com a nova credencial.

### 8.3. Instalação Manual (sem o script)

Para ambientes em que prefira controlar cada passo — os comandos abaixo **espelham os 9 passos do `install.sh`**:

```shell
# 1. Dependências e usuário da aplicação
sudo apt install -y docker.io docker-compose-v2 python3-pip python3-venv
sudo useradd -r -s /usr/sbin/nologin inventory

# 2. Pasta da aplicação
cd /opt && sudo mkdir Inventory && sudo chown -R inventory:inventory ./Inventory
# (extraia/copie o projeto para /opt/Inventory)

# 3. .env (copie de .env.example e edite — seção 8.2)
cd /opt/Inventory && sudo -u inventory cp .env.example .env
sudo -u inventory nano .env

# 4. Certificados TLS (self-signed válido por 1 ano)
sudo -u inventory openssl req -x509 -newkey rsa:4096 -nodes \
  -out ssl/cert.pem -keyout ssl/key.pem -days 365 -subj "/CN=inventory"

# 5. Pasta do banco com o dono correto (usuário postgres do container)
sudo mkdir -p data/postgres && sudo chown -R 999:999 data/postgres

# 6. venv + dependências Python (como usuário inventory)
sudo -u inventory python3 -m venv .venv
sudo -u inventory .venv/bin/pip install -r requirements.txt

# 7. Subir o banco (PostgreSQL + Redis) e a aplicação
sudo docker compose up -d
sudo -u inventory bash -c "source .venv/bin/activate && python3 app.py"
```

**Login e senha padrão** (criados no primeiro acesso a partir do `.env`):

```shell
Login: admin
Password: Meuadmin123
```

> **Migração de instalação antiga (JSON → PostgreSQL):** copie os dados antigos e rode o migrador:
>
> ```shell
> cp -a <diretorio_inventory_antigo>/data/. /opt/Inventory/data/
> sudo chown -R inventory:inventory /opt/Inventory
> sudo -u inventory bash -c "cd /opt/Inventory && source .venv/bin/activate && python3 migrate_db.py"
> # REINICIE A APLICAÇÃO OU SINCRONIZE
> ```

### 8.4. Teste da Aplicação Web

Com o serviço ativo (ou o `app.py` manual), acesse:

```text
https://IP-DO-SERVIDOR:8000
```

Ao entrar, a **intro animada** toca uma vez (clique ou tecla pula) e o login aparece. No primeiro acesso com `ADMIN_MUST_CHANGE_PASSWORD` ativo, a troca de senha é exigida.

---

## 9. Serviço (systemd)

O `install.sh` cria o serviço automaticamente (passo 9). Para conferir ou criar manualmente, o arquivo fica em `/etc/systemd/system/inventory.service`:

```ini
[Unit]
Description=Inventory Application
After=network.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/Inventory
ExecStart=/opt/Inventory/.venv/bin/python3 /opt/Inventory/app.py
User=inventory
Group=inventory
Restart=always
RestartSec=5

# Sandbox básico — a app roda sem privilégios e sem enxergar o resto do sistema
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=full
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ReadOnlyPaths=/
ReadWritePaths=/opt/Inventory
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
AmbientCapabilities=
LimitNOFILE=65536
LimitNPROC=1024
MemoryDenyWriteExecute=yes
LockPersonality=yes
RestrictSUIDSGID=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

**Comandos do dia a dia:**

```shell
sudo systemctl status inventory          # estado do serviço
sudo systemctl restart inventory         # reiniciar
sudo systemctl stop inventory            # parar
sudo systemctl enable inventory          # iniciar junto com o servidor
journalctl -u inventory -f               # logs do serviço em tempo real
```

> O `LimitNOFILE=65536` é importante para o **portscan** do NetScope: o número de workers da varredura se ajusta ao `RLIMIT_NOFILE` real do processo, e hosts com milhares de portas abertas não derrubam mais o servidor ("Too many open files").

---

## 10. Atualização de Versão

O procedimento padrão, seguro e rápido:

```shell
# 1. Backup (banco + configuração + certificados)
docker exec -t inventory_postgres pg_dump -U inventorydb inventory_db > backup_$(date +%Y%m%d).sql
sudo cp /opt/Inventory/.env /root/backup.env
sudo cp -r /opt/Inventory/ssl /root/backup-ssl

# 2. Substituir os arquivos da aplicação (mantendo .env, ssl/ e data/)
cd /opt/Inventory
sudo -u inventory git pull          # ou extraia o zip da nova versão por cima

# 3. Dependências (se o requirements.txt mudou)
sudo -u inventory .venv/bin/pip install -r requirements.txt

# 4. Reiniciar
sudo systemctl restart inventory
```

**Ou simplesmente rode o `install.sh` de novo** — ele é idempotente: atualiza dependências e reinicia o serviço **sem tocar em `data/postgres`, `.env` nem `ssl/`** existentes.

Notas importantes:

- As **tabelas novas** (ex.: `chat_messages`, `netscope_scan_history`, notificações) são criadas automaticamente no boot — não há migração manual entre versões.
- A **intro do login** toca 1× por navegador **a cada nova versão** (o marcador usa o `APP_VERSION`) — é o comportamento esperado após atualizar, não um bug.
- Se mudou a senha do banco no `.env`, remova `data/postgres` antes do primeiro `docker compose up` (seção 8.2).
- Limpe o cache do navegador (Ctrl+F5) se a interface parecer desatualizada após o restart.

---

## 11. Operação e Manutenção

### 11.1. Rotinas Recomendadas

- **Diária:** verificação dos logs em `logs/` (`audit.log`, `error.log`, `info.log`, `security.log`, `warning.log`) — podem indicar anomalias na aplicação.
- **Semanal:** backup do banco PostgreSQL:

```shell
docker exec -t inventory_postgres pg_dump -U inventorydb inventory_db > backup_inventario_$(date +%Y%m%d).sql
```

- **Mensal:** auditoria dos usuários e acessos registrados para conformidade com as políticas de segurança.
- **Anual:** renovação dos certificados TLS/SSL (`ssl/cert.pem` e `ssl/key.pem`).

### 11.2. Logs do Sistema

- `info.log`: informações gerais sobre a execução da aplicação.
- `warning.log`: alertas e avisos que não são erros críticos.
- `error.log`: erros e exceções da operação.
- `security.log`: eventos de segurança — logins (sucessos e falhas), ativação de MFA e bloqueios de IP.
- `audit.log`: trilha de auditoria das ações realizadas pelos usuários na plataforma.

### 11.3. Solução de Problemas Comuns

| Problema Comum | Ação Recomendada |
| --- | --- |
| **Dados não atualizam** | Dispare uma **Sincronização manual** em Configurações e verifique `WAZUH_HOST`/`WAZUH_USER`/`WAZUH_PASSWORD` no `.env`. |
| **Erro de certificado** | Confirme `SSL_CERT_PATH` e `SSL_KEY_PATH` no `.env` e se os arquivos existem em `ssl/`. |
| **Acesso negado** | Verifique se o IP de origem está em `ALLOWED_IP_RANGES`. |
| **Container não sobe** | `docker compose ps` e `docker compose logs db` a partir da raiz. Banco novo exige `data/postgres` com dono `999:999`. |
| **Permissão do banco** | `sudo chown -R 999:999 data/postgres` (usuário postgres do container). |
| **Esqueci a senha do admin** | Limpe a tabela `users` do banco — o bootstrap recria o admin com as credenciais do `.env` (`ADMIN_PASSWORD`). |
| **Chat IA avisa rate limit** | Cadastre chaves extras no `.env` (`GROQ_API_KEYS`/`GROQ_API_KEY_2`) — outra org = outra cota (seção 8.2). |
| **Sessão cai ao navegar** | Verifique `TRUST_PROXY` atrás de proxy reverso e o relógio do servidor (sessões dependem de hora correta). |

---


## 12. Melhorias Futuras

O **INVENTORY** é um projeto em desenvolvimento ativo, com um _roadmap_ claro para aprimoramentos focados em escalabilidade, integração e segurança.

| Projeto | Descrição |
| --- | --- |
| **Containerização** | Criação de uma imagem Docker oficial da aplicação (além do banco) para simplificar ainda mais a implantação. |
| **Backend e Performance** | API REST pública para integrações com CMDB/SIEM/DLP; expansão do cache Redis para novas listagens. |
| **Frontend e UX** | WebSockets para atualização dos dashboards e do NetScope em tempo real; melhorias de responsividade para dispositivos móveis. |
| **Segurança e Integração** | Criptografia adicional de dados em repouso; integração com LDAP/Active Directory para autenticação centralizada; integração com sistemas de tickets (Jira, ServiceNow). |
| **Relatórios** | Fontes embutidas no gerador de PDF para suporte completo a Russo/中文/العربية no documento. |

---

## 13. Conclusão

O sistema **INVENTORY** preenche uma lacuna estratégica ao eliminar a cegueira sobre os ativos de TI, transformando os dados brutos de telemetria coletados pelo **Wazuh** e a topologia mapeada pelo **NetScope** em uma plataforma centralizada de visualização, busca, documentação e auditoria. Ele oferece uma _solução leve e segura_ que se integra de forma transparente à infraestrutura existente, _sem a necessidade de agentes adicionais_ — e, com o `install.sh`, vai do servidor limpo ao sistema no ar em um único comando.
