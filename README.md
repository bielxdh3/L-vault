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
- Bootable Disk Clone: 03:00 quando explicitamente habilitado; permanece fail-closed e fora do catch-up comum

Se o PC estiver desligado no horario marcado, as tarefas comuns podem seguir o comportamento de catch-up existente. A tarefa de clone e diferente: ela nao usa `StartWhenAvailable` e nunca inicia durante o dia.

Instalar tarefas:

```powershell
python -m localvault schedule-install --root <VAULT_ROOT>
```

`auto-takeout` preserva as fontes por padrao (`safety.never_delete_sources: true`) e copia somente ZIPs validos; apenas `false` habilita move apos verificacao. Restore exige destino separado, conflitos sao `skip` por padrao e replica usa staging, promocao atomica, hash e nunca remove itens do destino por desaparecimento na origem.

`health-check --json` fornece metricas limitadas de espaco, indice, crescimento, duplicatas, erros, locks, temporarios e execucoes. `recovery-test` usa somente dados sinteticos temporarios e nao representa clone fisico.

## Clone offline open-source do disco

O L-vault nao exige software pago. O Windows prepara um pacote de job assinado; uma futura sessao Clonezilla Live executara a clonagem somente com a origem desmontada e fora do Windows. O status e os comandos de clone permanecem disponiveis, mas a execucao fisica continua gated: nenhum boot, reboot ou escrita em disco e autorizado nesta fase. O clone físico permanece desativado por padrão e fail-closed.

O motor escolhido para integracao e Clonezilla Live `3.3.3-15`, usando `ocs-onthefly` para clone local de disco inteiro e Partclone como dependencia interna. O resolver nunca passa `SERIALNO=` para `ocs-onthefly`: ele compara fingerprints persistentes novamente no Linux e passa somente os nodes `/dev/...` atuais. Nomes de device, numero de disco, ponto de montagem e GUID copiado nao sao identidade persistente.

O prototipo fake-only implementa schema versionado, assinatura destacada por interface, nonce de uso unico, expiracao, inventario Linux normalizado, resolver fail-closed, renderer argv sem shell, pacote de resultado e consumo com `boot_tested=false`. A assinatura protege a integridade de transporte, mas o consumidor tambem exige o job verificado e o hash do plano de comando confiavel; engine, release, labels, fases, timestamps, hashes, destino offline e texto de erro sao validados semanticamente. A simulacao pode ser executada com:

```powershell
python -m localvault disk-clone-simulate --root <VAULT_ROOT>
python -m localvault disk-clone-runtime-validate --root <VAULT_ROOT>
python -m localvault disk-clone-virtual-roundtrip --root <VAULT_ROOT>
```

O comando acima usa somente inventario e pacotes temporarios falsos. A fase `fake_engine_rendered_only` e consumida apenas pelo perfil de simulacao e retorna `offline_simulation_completed`; ela nao e evidencia de clone concluido nem de verificacao estrutural. Uma futura fase de producao devera usar `clone_completed_structurally_verified` com `confirmed_offline`, campos vinculados ao job/plano confiavel e `boot_tested=false`; somente entao o resultado podera ser `offline_clone_structurally_verified`. Com clone desativado, `disk-clone-run` retorna `blocked_configuration`; se explicitamente habilitado, permanece em `offline_boot_not_configured` e nao inicia provedor Windows. A tela mostra que o boot offline nao esta configurado, oferece apenas prontidao e simulacao, e nao apresenta uma acao de clone imediato.

O handoff escolhido e um USB Clonezilla Live dedicado com selecao manual de boot. Ele evita alterar permanentemente a ordem de boot e exige uma acao humana; nenhum BCD, UEFI NVRAM, BootNext, USB, particao ou PXE foi alterado. A fase atual separa a verificacao `gpgv` oficial do DRBL da atestacao local L-vault, com o fingerprint DRBL `54C0821A48715DAFD61BFCAF667857D045599AFD` e o SHA-256 oficial `482518ea32af3b82ed15d09e2e7714806775deb62aeed81491e534f6cc6bbc47` do ISO `clonezilla-live-3.3.3-15-amd64.iso` fixados no contrato de producao. Esses valores nao podem ser redefinidos por CLI, configuracao, manifesto ou construtor; overrides de digest existem somente na fabrica explicita de testes sinteticos. A atestacao local L-vault permanece um trust root separado e nunca e proveniencia oficial Clonezilla/DRBL. O binding criptografico entre ISO verificado e inventario completo da arvore extraida, a inspeÃ§Ã£o estatica de ferramentas sem execucao, o canal de retorno virtual duravel e o runner virtual somente-simulacao continuam ativos. Como nao havia ISO oficial, arvore extraida ou stack de VM segura presente, o status honesto continua `offline_runtime_blocked`; nenhum boot de VM ocorreu.

O canal virtual usa somente diretorios temporarios e dispositivos sinteticos. Os estados `pending`, `running`, `result`, `failed` e `consumed` sao monotÃ´nicos; publicacao parcial, resultado duplicado, conflito, replay, truncamento ou crash nunca vira sucesso. A UI continua afirmando que nenhum clone fisico foi executado, nenhum boot fisico foi testado, a execucao real esta desativada, e validacao estatica/virtual nao equivale a validacao no hardware do usuario.

AOMEI e DiskGenius permanecem alternativas historicas rejeitadas, nao recomendacoes. Nao houve inscricao real, selecao de disco, clone, formatacao, reparticionamento, `Set-Disk`, montagem, desmontagem, provider launch, tarefa destrutiva, reboot ou boot test.

Fontes oficiais e aplicabilidade estao em [`docs/disk-clone-offline.md`](docs/disk-clone-offline.md).

### Validacao estatica do artefato real

O fluxo separado de artefato real baixa ou revalida somente o Clonezilla Live `3.3.3-15` amd64 fixado, verifica `CHECKSUMS.TXT` e sua assinatura DRBL com `54C0821A48715DAFD61BFCAF667857D045599AFD`, e confirma o ISO `clonezilla-live-3.3.3-15-amd64.iso` pelo SHA-256 `482518ea32af3b82ed15d09e2e7714806775deb62aeed81491e534f6cc6bbc47`. O cache privado fica fora do repositorio; o modo offline apenas revalida arquivos existentes.

```powershell
python -m localvault disk-clone-artifacts-verify --cache <PRIVATE_ARTIFACT_CACHE> --gpg <ABSOLUTE_HOST_GPG> --gpgv <ABSOLUTE_HOST_GPGV>
python -m localvault disk-clone-artifact-status --cache <PRIVATE_ARTIFACT_CACHE>
python -m localvault disk-clone-attestor-status --gpg <ABSOLUTE_HOST_GPG> --gnupg-home <PRIVATE_ATTESTOR_HOME> --public-keyring <PUBLIC_ATTESTOR_KEYRING>
```

A verificacao oficial do publicador e a assinatura local de extracao sao trust roots separados. A arvore real, quando extraida por ferramenta local explicitamente permitida, e inventariada sem seguir links para o host; `gpg`, `gpgv`, `sha256sum`, `lsblk`, `blkid`, `udevadm`, `findmnt` e `ocs-onthefly` sao apenas inspecionados e marcados `present_unexecuted`. Nenhum comando extrai executaveis para rodar, monta ISO, acessa disco/USB, cria VM, inicializa, reinicia ou executa clone. Validacao estatica nao prova bootabilidade, Secure Boot ou corretude de clone.

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
