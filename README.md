<div align="center">

# L-Vault

**LocalVault Backup Manager**

Um cofre local para preservar, organizar, verificar e consultar backups do Gmail e do Google Takeout.

[![Status](https://img.shields.io/badge/status-desenvolvimento%20ativo-orange)](#estado-do-projeto)
[![Versão](https://img.shields.io/badge/versão-0.2.0-blue)](#estado-do-projeto)
[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB)](#requisitos)
[![Plataforma](https://img.shields.io/badge/plataforma-Windows-0078D4)](#requisitos)
[![Modelo](https://img.shields.io/badge/dados-local--first-blueviolet)](#segurança-e-privacidade)

O L-Vault transforma exportações espalhadas, e-mails e arquivos de mídia em um acervo local pesquisável, deduplicado, verificável e acessível por um painel protegido no próprio computador.

</div>

> [!IMPORTANT]
> O L-Vault preserva cópias locais. Ele **não substitui uma estratégia completa de backup** enquanto o cofre existir em apenas um disco. Para proteção real contra falha física, mantenha ao menos uma segunda cópia independente e testada.

## Fluxo visual

```text
      ┌──────────────────────┐       ┌────────────────────────┐
      │ Gmail API oficial   │       │ Google Takeout         │
      │ backup incremental  │       │ ZIPs de fotos e vídeos │
      └──────────┬───────────┘       └───────────┬────────────┘
                 │                               │
                 └──────────────┬────────────────┘
                                │
                      ┌─────────▼──────────┐
                      │ Caixa de entrada  │
                      │ sync de fontes    │
                      └─────────┬──────────┘
                                │
                      ┌─────────▼──────────┐
                      │ Processamento     │
                      │ ingestão · hash   │
                      │ dedupe · reparo   │
                      └──────┬───────┬─────┘
                             │       │
                  arquivos   │       │ metadados
                             │       │
                ┌────────────▼──┐ ┌──▼────────────────┐
                │ Cofre local   │ │ Índice SQLite     │
                │ e-mails       │ │ mensagens · mídia │
                │ fotos · vídeos│ │ execuções · hashes│
                └────────────┬──┘ └──┬────────────────┘
                             │       │
                             └───┬───┘
                                 │
                       ┌─────────▼──────────┐
                       │ Painel local      │
                       │ busca · leitura   │
                       │ relatórios · ações│
                       └────────────────────┘
```

## O que o projeto faz

- backup incremental do Gmail pela API oficial;
- importação de fotos e vídeos exportados pelo Google Takeout;
- cópia automática de ZIPs reconhecidos para a caixa de entrada do cofre;
- deduplicação por identificadores e SHA-256;
- organização de e-mails em arquivos `.eml` com nomes legíveis;
- indexação de metadados em SQLite;
- verificação de integridade e relatórios de duplicidade;
- reparo de execuções incompletas do Gmail;
- painel local protegido por senha;
- sessão assinada com expiração de oito horas;
- proteção CSRF nas ações que alteram dados;
- sanitização de HTML em mensagens de e-mail;
- tarefas automáticas pelo Agendador do Windows;
- atalho de desktop para abrir o visualizador.

## Estado do projeto

A versão atual do pacote é **0.2.0**.

- [x] backup do Gmail pela API;
- [x] importação de Google Takeout;
- [x] painel local autenticado;
- [x] deduplicação e auditoria;
- [x] verificação de integridade;
- [x] automação diária no Windows;
- [x] indexação SQLite;
- [x] sanitização do leitor de e-mails;
- [ ] TLS próprio para uso fora do loopback;
- [ ] experiência guiada de configuração inicial;
- [ ] estratégia integrada de cópia externa do cofre;
- [ ] restauração assistida e testes de recuperação mais completos.

## Requisitos

- Windows;
- Python 3.12 ou mais recente;
- PowerShell;
- espaço em disco suficiente para as cópias locais;
- credenciais OAuth próprias para usar a API oficial do Gmail;
- exportações do Google Takeout para fotos e vídeos completos.

## Início rápido

Escolha uma pasta privada para o cofre e substitua `<VAULT_ROOT>` nos exemplos.

### 1. Instale o projeto

```powershell
cd <VAULT_ROOT>
.\install.ps1
```

### 2. Defina a senha do painel

```powershell
python -m localvault auth-set-password --root <VAULT_ROOT>
```

Executar o comando novamente troca a senha e invalida as sessões existentes.

### 3. Inicie o painel local

```powershell
python -m localvault serve --root <VAULT_ROOT>
```

Acesse:

```text
http://127.0.0.1:8787
```

### 4. Crie o atalho de desktop

```powershell
python -m localvault viewer-shortcut --root <VAULT_ROOT>
```

O atalho **Abrir LocalVault** inicia o painel em segundo plano e abre o navegador.

Para uma preparação mais detalhada, leia [SETUP_WINDOWS.md](SETUP_WINDOWS.md).

## Importação de fotos e vídeos

O fluxo oficial usa o Google Takeout:

1. Exporte o Google Fotos pelo Takeout.
2. Baixe os arquivos `.zip`.
3. Coloque os ZIPs em:

```text
<VAULT_ROOT>\inbox\google_takeout
```

4. Execute:

```powershell
python -m localvault photos-ingest-takeout --root <VAULT_ROOT>
```

Também é possível usar `ingest-all` ou o botão **Importar Takeout/Fotos** no painel.

Os arquivos são organizados em:

```text
<VAULT_ROOT>\vault\fotos\imagens
<VAULT_ROOT>\vault\fotos\videos
```

O sistema preserva o que já foi importado, calcula SHA-256 para evitar duplicação e registra metadados em SQLite.

## Backup do Gmail

```powershell
python -m localvault backup-gmail-api --root <VAULT_ROOT>
```

Depois do primeiro índice, o backup passa a buscar apenas mensagens recentes com uma margem de segurança. E-mails já salvos são ignorados por `gmail_id` ou pelo hash SHA-256.

Os arquivos `.eml` usam o padrão:

```text
data_remetente_assunto_id.eml
```

Para renomear arquivos antigos:

```powershell
python -m localvault rename-gmail-files --root <VAULT_ROOT>
```

## Comandos principais

| Comando | Função |
|---|---|
| `init` | Inicializa a estrutura do cofre |
| `sync-sources` | Copia exportações reconhecidas para a caixa de entrada |
| `ingest-all` | Processa todas as fontes disponíveis |
| `photos-ingest-takeout` | Importa fotos e vídeos do Takeout |
| `backup-gmail-api` | Executa o backup incremental do Gmail |
| `gmail-dedupe-audit` | Audita duplicações reais no backup de e-mails |
| `gmail-repair-runs` | Repara execuções incompletas do Gmail |
| `daily-backup` | Executa o fluxo diário principal |
| `rename-gmail-files` | Renomeia arquivos `.eml` antigos |
| `dedupe` | Executa deduplicação do cofre |
| `verify` | Verifica integridade e consistência |
| `schedule` | Exibe ou gerencia o agendamento |
| `schedule-install` | Instala as tarefas no Windows |
| `serve` | Inicia o painel local |

Exemplo geral:

```powershell
python -m localvault <comando> --root <VAULT_ROOT>
```

## Automação

A agenda padrão é:

```text
01:30  Importação automática de Takeout
02:00  Backup diário principal
Domingo 04:00  Verificação do cofre
```

O backup diário reúne:

- Gmail API;
- sincronização de fontes;
- importação de Takeout;
- relatório de duplicados.

Instale as tarefas com:

```powershell
python -m localvault schedule-install --root <VAULT_ROOT>
```

Se o computador estiver desligado no horário, o Windows executa a tarefa assim que possível depois que ele ligar.

## Painel local

Todas as rotas do painel exigem autenticação, incluindo:

- arquivos;
- Gmail;
- fotos e vídeos;
- relatórios;
- ações de backup;
- abertura, reparo e exclusão de itens.

Formulários que alteram o estado também exigem token CSRF vinculado à sessão.

O leitor de e-mails:

- sanitiza HTML por allowlist;
- bloqueia scripts e manipuladores de evento;
- bloqueia imagens remotas;
- mantém o conteúdo dentro de um `iframe` com sandbox.

## Segurança e privacidade

> [!CAUTION]
> O painel usa `127.0.0.1` por padrão. Ativar `viewer.allow_lan: true` disponibiliza o serviço na rede local, mas o tráfego continua em HTTP sem criptografia. Use essa opção apenas em uma rede confiável até existir TLS.

O modelo de segurança atual depende de limites claros:

- o cofre deve ficar em uma pasta privada;
- senhas, tokens OAuth, bancos SQLite, backups e arquivos pessoais não pertencem ao Git;
- a API do Gmail usa autorização oficial e não captura credenciais da conta;
- o projeto não apaga dados remotos;
- sessões assinadas expiram após oito horas;
- ações sensíveis exigem autenticação e CSRF;
- hashes ajudam a detectar duplicados e corrupção, mas não protegem contra perda do disco;
- expor o painel à LAN aumenta o limite de confiança;
- uma segunda cópia independente é necessária para tolerar falha física do armazenamento.

## Estrutura do repositório

```text
L-vault/
├── src/                      Pacote Python `localvault`
├── tests/                    Testes automatizados
├── config/                   Configurações de exemplo
├── install.ps1               Instalação no Windows
├── run_viewer.ps1            Inicialização manual do painel
├── start_viewer_hidden.ps1   Inicialização em segundo plano
├── create_desktop_shortcut.ps1
├── SETUP_WINDOWS.md
├── pyproject.toml
└── README.md
```

## Desenvolvimento e testes

Instale o pacote com as dependências de teste:

```powershell
python -m pip install -e ".[test]"
```

Execute:

```powershell
pytest
```

## Limites honestos

- o Gmail pode ser automatizado pela API oficial;
- fotos e vídeos completos dependem do Google Takeout;
- o painel não oferece TLS próprio atualmente;
- o projeto não elimina a necessidade de uma segunda cópia do cofre;
- autenticação local reduz acesso acidental, mas não protege um computador já comprometido;
- integridade verificada não é o mesmo que recuperação testada.

## Roadmap

- [ ] Adicionar configuração inicial guiada
- [ ] Melhorar relatórios de integridade e capacidade
- [ ] Criar fluxo assistido de restauração
- [ ] Aumentar a cobertura de testes de recuperação
- [ ] Adicionar suporte seguro a HTTPS/TLS
- [ ] Facilitar cópias independentes do cofre
- [ ] Refinar a interface do painel local

## Aviso

L-Vault é um projeto independente de backup local. Não é afiliado, mantido ou endossado pelo Google. Gmail, Google Fotos e Google Takeout são marcas de seus respectivos proprietários.