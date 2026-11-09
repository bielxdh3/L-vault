<div align="center">

# L-Vault

**LocalVault Backup Manager**

Um cofre local para preservar, organizar, verificar e consultar backups do Gmail e do Google Takeout.

[![Status](https://img.shields.io/badge/status-desenvolvimento%20ativo-orange)](#estado-do-projeto)
[![CI](https://github.com/bielxdh3/L-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/bielxdh3/L-vault/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![Versão](https://img.shields.io/badge/versão-0.2.0-blue)](#estado-do-projeto)
[![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB)](#requisitos)
[![Plataforma](https://img.shields.io/badge/plataforma-Windows-0078D4)](#requisitos)
[![Modelo](https://img.shields.io/badge/dados-local--first-blueviolet)](#limites-seguros)

O L-Vault transforma exportações espalhadas, e-mails e arquivos de mídia em um acervo local pesquisável, deduplicado, verificável e acessível por um painel protegido no próprio computador.

</div>

> [!IMPORTANT]
> O L-Vault preserva cópias locais. Ele **não substitui uma estratégia completa de backup** enquanto o cofre existir em apenas um disco. Para proteção real contra falha física, mantenha ao menos uma segunda cópia independente e testada.

## Fluxo visual

```text
      ┌──────────────────────┐       ┌────────────────────────┐
      │ Gmail API oficial    │       │ Google Takeout         │
      │ backup incremental   │       │ ZIPs de fotos e vídeos │
      └──────────┬───────────┘       └───────────┬────────────┘
                 │                               │
                 └──────────────┬────────────────┘
                                │
                      ┌─────────▼──────────┐
                      │ Caixa de entrada   │
                      │ sync de fontes     │
                      └─────────┬──────────┘
                                │
                      ┌─────────▼──────────┐
                      │ Processamento      │
                      │ ingestão · hash    │
                      │ dedupe · reparo    │
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
                       │ Painel local       │
                       │ busca · leitura    │
                       │ relatórios · ações │
                       └────────────────────┘
```

**Operações independentes da ingestão de Gmail/Takeout:**

```text
Cofre + índice SQLite ──► plano / verificação ──► restauração em outro destino
           │
           └───────────────► réplica incremental em destino explícito

Clone de dados Windows (fluxo independente e destrutivo):
origem física autorizada (leitura) ── VSS / worker protegido ──► alvo autorizado
                                                            (pode ser apagado)
                                   outro disco protegido fica fora do clone
                         saída: cópia de dados, NÃO disco inicializável
```

O clone Windows exige confirmação explícita e revalidação da identidade dos discos antes de apagar o alvo. A existência do código não comprova um clone físico validado em hardware real. O protótipo Clonezilla é histórico e permanece desativado por padrão.

## O que o projeto faz

- backup incremental do Gmail pela API oficial;
- importação de fotos e vídeos exportados pelo Google Takeout;
- cópia automática de ZIPs reconhecidos para a caixa de entrada do cofre;
- deduplicação por identificadores e SHA-256;
- organização de e-mails em arquivos `.eml` com nomes legíveis;
- indexação de metadados em SQLite;
- verificação de integridade e relatórios de duplicidade;
- restauração assistida e réplica incremental com destino independente e explícito;
- clone de dados Windows first-party, separado do cofre e do protótipo Clonezilla, com validações de identidade e confirmação;
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
- [x] restauração assistida por plano e réplica de arquivos em outro destino;
- [x] fluxo de clone de dados Windows com worker protegido (aceitação física não presumida);
- [x] automação diária no Windows;
- [x] indexação SQLite;
- [x] sanitização do leitor de e-mails;
- [ ] validação operacional ampliada do acesso em LAN com TLS e da política de rede;
- [ ] experiência guiada de configuração inicial;
- [ ] estratégia integrada de cópia externa do cofre;
- [ ] testes ampliados de restauração e recuperação em ambiente real;

## Requisitos

- Windows;
- Python 3.12 ou mais recente;
- PowerShell;
- espaço em disco suficiente para as cópias locais;
- credenciais OAuth próprias para usar a API oficial do Gmail;
- exportações do Google Takeout para fotos e vídeos completos.

## Uso Rapido

```powershell
cd <VAULT_ROOT>
.\install.ps1
python -m localvault viewer-shortcut --root <VAULT_ROOT>
```

Painel local:

```text
http://127.0.0.1:8787
```

Antes de iniciar o painel, defina a senha local (repita para trocar a senha e invalidar sessoes existentes):

```powershell
python -m localvault auth-set-password --root <VAULT_ROOT>
python -m localvault serve --root <VAULT_ROOT>
```

Todas as rotas do painel, incluindo arquivos, Gmail, fotos, relatorios e acoes de backup, exigem login. A sessao assinada expira apos oito horas. Formularios que iniciam, reparam, abrem ou apagam algo tambem exigem um token CSRF ligado a sessao.

O painel usa `127.0.0.1` por padrao. Para LAN, configure `viewer.allow_lan: true`, senha e TLS valido (`tls_enabled`, `tls_certfile`, `tls_keyfile`); exposicao nao-loopback sem TLS e recusada. O leitor de e-mails sanitiza HTML com allowlist, bloqueando scripts, manipuladores de evento e imagens remotas; o iframe continua sandboxed.

O segredo do painel fica em `config/auth.json`; nao versionar esse arquivo, tokens OAuth, client secrets, banco, logs ou backups. O setup e idempotente e nao instala tarefas nem inicia autorizacao Gmail:

```powershell
python -m localvault setup --root <VAULT_ROOT> --non-interactive
python -m localvault setup --root <VAULT_ROOT> --password-stdin
```

Use o atalho `Abrir LocalVault` na area de trabalho. Ele inicia o painel em segundo plano e abre o navegador.

## Comandos

```powershell
python -m localvault init --root <VAULT_ROOT>
python -m localvault sync-sources --root <VAULT_ROOT>
python -m localvault ingest-all --root <VAULT_ROOT>
python -m localvault photos-ingest-takeout --root <VAULT_ROOT>
python -m localvault backup-gmail-api --root <VAULT_ROOT>
python -m localvault gmail-dedupe-audit --root <VAULT_ROOT>
python -m localvault gmail-repair-runs --root <VAULT_ROOT>
python -m localvault daily-backup --root <VAULT_ROOT>
python -m localvault rename-gmail-files --root <VAULT_ROOT>
python -m localvault dedupe --root <VAULT_ROOT>
python -m localvault verify --root <VAULT_ROOT>
python -m localvault health-check --root <VAULT_ROOT> --json
python -m localvault recovery-test
python -m localvault restore-plan --root <VAULT_ROOT> --destination <RESTORE_ROOT>
python -m localvault restore --root <VAULT_ROOT> --destination <RESTORE_ROOT> --dry-run
python -m localvault replica-plan --root <VAULT_ROOT> --destination <REPLICA_ROOT>
python -m localvault replica --root <VAULT_ROOT> --destination <REPLICA_ROOT> --dry-run
python -m localvault schedule --root <VAULT_ROOT>
python -m localvault disk-clone-status --root <VAULT_ROOT>
python -m localvault disk-clone-check --root <VAULT_ROOT>
python -m localvault disk-clone-simulate --root <VAULT_ROOT>
python -m localvault disk-clone-artifact-status --cache <PRIVATE_ARTIFACT_CACHE>
python -m localvault disk-clone-artifacts-verify --cache <PRIVATE_ARTIFACT_CACHE> --gpg <ABSOLUTE_HOST_GPG> --gpgv <ABSOLUTE_HOST_GPGV>
```

## Fotos Por Takeout

Para fotos e videos, o fluxo oficial agora e Google Takeout:

1. Exporte Fotos no Google Takeout.
2. Baixe os arquivos `.zip`.
3. Coloque os `.zip` em:

```text
<VAULT_ROOT>\inbox\google_takeout
```

4. Rode `photos-ingest-takeout`, `ingest-all` ou use o botao `Importar Takeout/Fotos` no painel.

Os arquivos sao copiados para:

```text
<VAULT_ROOT>\vault\fotos\imagens
<VAULT_ROOT>\vault\fotos\videos
```

O LocalVault preserva os arquivos ja importados, usa SHA-256 para evitar duplicados e indexa metadados em SQLite.

## Automacao

O `sync-sources` copia automaticamente exports de Google Takeout encontrados no diretorio configurado como `<DOWNLOADS_DIRECTORY>` para o inbox do LocalVault. O filtro valida o conteudo do ZIP para ignorar arquivos comuns.

O agendador diario padrao:

- Daily Backup: 02:00; Gmail API, sync de fontes, importacao de Takeout e relatorio de duplicados
- Weekly Takeout Import: 03:00 aos domingos; importa Takeout reconhecido
- Verify Weekly: 04:00 aos domingos; verifica o cofre
- Legacy Bootable Disk Clone: disabled in new installs; historical offline prototype only

Se o PC estiver desligado no horario marcado, as tarefas comuns podem seguir o comportamento de catch-up existente. A tarefa de clone e diferente: ela nao usa `StartWhenAvailable` e nunca inicia durante o dia.

Instalar tarefas:

```powershell
python -m localvault schedule-install --root <VAULT_ROOT>
```

`auto-takeout` preserva as fontes por padrao (`safety.never_delete_sources: true`) e copia somente ZIPs validos; apenas `false` habilita move apos verificacao. Restore exige destino separado, conflitos sao `skip` por padrao e replica usa staging, promocao atomica, hash e nunca remove itens do destino por desaparecimento na origem.

`health-check --json` fornece metricas limitadas de espaco, indice, crescimento, duplicatas, erros, locks, temporarios e execucoes. `recovery-test` usa somente dados sinteticos temporarios e nao representa clone fisico.

## Clone de dados do Windows

O clone normal foi implementado como uma operação de dados controlada pelo próprio L-vault. Ele não depende de DiskGenius, Clonezilla, mídia USB ou menus de firmware, e não cria uma unidade inicializável. A página identifica o Kingston autorizado como origem somente leitura, o Seagate autorizado como destino a apagar e o HGST do repositório como protegido.

Na primeira operação, o próprio L-vault prepara o runtime em segundo plano e pede a permissão padrão do Windows. O instalador grava o trabalhador e o helper em uma pasta protegida, fixa seus hashes SHA-256 em um manifesto vinculado ao SID do proprietário e só então inicia o clone. A assinatura Authenticode é validada quando uma chave de publicador estiver configurada para a distribuição; ela não é um requisito para o uso local. O Seagate autorizado é apagado somente após nova validação das três identidades físicas.

O fluxo legado DiskGenius e o protótipo Clonezilla estão documentados apenas como histórico em [`docs/diskgenius-normal-clone.md`](docs/diskgenius-normal-clone.md) e [`docs/disk-clone-offline.md`](docs/disk-clone-offline.md).

O protótipo de clone de disco inteiro via Clonezilla é um **experimento legado**, diferente do clone normal de dados Windows e desativado por padrão. Seu contrato e as evidências estáticas foram preservados no [arquivo histórico do protótipo Clonezilla](docs/validation/readme-clonezilla-historical-prototype.md). Simulação, atestação e análise de artefatos não constituem prova de clone físico, boot ou autorização para apagar um disco.

## Limites Seguros

Gmail pode ser automatico via API oficial. Fotos e videos completos dependem de Google Takeout. O sistema nao rouba credenciais e nao apaga dados remotos.

Os arquivos `.eml` do Gmail sao salvos com nomes legiveis no padrao `data_remetente_assunto_id.eml`. Para renomear e-mails antigos ja baixados:

```powershell
python -m localvault rename-gmail-files --root <VAULT_ROOT>
```

Para conferir se existe duplicacao real no backup do Gmail, rode:

```powershell
python -m localvault gmail-dedupe-audit --root <VAULT_ROOT>
```

O backup Gmail API e incremental: depois do primeiro indice, ele busca somente mensagens recentes com uma pequena margem de seguranca e pula e-mails ja salvos por `gmail_id` ou hash SHA-256.


## Comunidade e contribuição

- [Como contribuir](CONTRIBUTING.md)
- [Suporte](SUPPORT.md)
- [Política de segurança](SECURITY.md)
- [Código de conduta](CODE_OF_CONDUCT.md)
- [Governança](GOVERNANCE.md)

## Licença

O L-Vault é distribuído sob a [Apache License 2.0](LICENSE).

É permitido usar, modificar, redistribuir, incorporar e vender o software, inclusive em produtos comerciais ou de código fechado, respeitando os termos da Apache-2.0. Redistribuições devem preservar os avisos aplicáveis de licença, copyright e atribuição, incluindo o [NOTICE](NOTICE) quando exigido.

**Copyright 2026 bielxdh3.**
