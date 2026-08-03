# LocalVault Backup Manager

LocalVault e um cofre local para Gmail e Google Takeout.

Raiz padrao:

```text
E:\LocalVault
```

## Uso Rapido

```powershell
cd E:\LocalVault
.\install.ps1
python -m localvault viewer-shortcut --root E:\LocalVault
```

Painel local:

```text
http://127.0.0.1:8787
```

Antes de iniciar o painel, defina a senha local (repita para trocar a senha e invalidar sessoes existentes):

```powershell
python -m localvault auth-set-password --root E:\LocalVault
python -m localvault serve --root E:\LocalVault
```

Todas as rotas do painel, incluindo arquivos, Gmail, fotos, relatorios e acoes de backup, exigem login. A sessao assinada expira apos oito horas. Formularios que iniciam, reparam, abrem ou apagam algo tambem exigem um token CSRF ligado a sessao.

O painel usa `127.0.0.1` por padrao. Para LAN, configure `viewer.allow_lan: true` e uma senha; isso ainda usa HTTP sem criptografia, portanto use somente uma rede confiavel ate adicionar TLS. O leitor de e-mails sanitiza HTML com allowlist, bloqueando scripts, manipuladores de evento e imagens remotas; o iframe continua sandboxed.

Use o atalho `Abrir LocalVault` na area de trabalho. Ele inicia o painel em segundo plano e abre o navegador.

## Comandos

```powershell
python -m localvault init --root E:\LocalVault
python -m localvault sync-sources --root E:\LocalVault
python -m localvault ingest-all --root E:\LocalVault
python -m localvault photos-ingest-takeout --root E:\LocalVault
python -m localvault backup-gmail-api --root E:\LocalVault
python -m localvault gmail-dedupe-audit --root E:\LocalVault
python -m localvault gmail-repair-runs --root E:\LocalVault
python -m localvault daily-backup --root E:\LocalVault
python -m localvault rename-gmail-files --root E:\LocalVault
python -m localvault dedupe --root E:\LocalVault
python -m localvault verify --root E:\LocalVault
python -m localvault schedule --root E:\LocalVault
python -m localvault disk-clone-status --root E:\LocalVault
python -m localvault disk-clone-check --root E:\LocalVault
python -m localvault disk-clone-simulate --root E:\LocalVault
```

## Fotos Por Takeout

Para fotos e videos, o fluxo oficial agora e Google Takeout:

1. Exporte Fotos no Google Takeout.
2. Baixe os arquivos `.zip`.
3. Coloque os `.zip` em:

```text
E:\LocalVault\inbox\google_takeout
```

4. Rode `photos-ingest-takeout`, `ingest-all` ou use o botao `Importar Takeout/Fotos` no painel.

Os arquivos sao copiados para:

```text
E:\LocalVault\vault\fotos\imagens
E:\LocalVault\vault\fotos\videos
```

O LocalVault preserva os arquivos ja importados, usa SHA-256 para evitar duplicados e indexa metadados em SQLite.

## Automacao

O `sync-sources` copia automaticamente exports de Google Takeout detectados em `C:\Users\bielx\Downloads` para o inbox do LocalVault. O filtro valida o conteudo do ZIP para ignorar arquivos comuns.

O agendador diario padrao:

- 02:00 Backup diario principal: Gmail API, sync de fontes, importacao de Takeout e relatorio de duplicados
- 01:30 Importacao automatica de Takeout: move ZIPs reconhecidos do Downloads para o Vault
- Domingo 04:00 Verificacao

Se o PC estiver desligado no horario marcado, as tarefas comuns podem seguir o comportamento de catch-up existente. A tarefa de clone e diferente: ela nao usa `StartWhenAvailable` e nunca inicia durante o dia.

Instalar tarefas:

```powershell
python -m localvault schedule-install --root E:\LocalVault
```

## Clone offline open-source do disco

O L-vault nao exige software pago. O Windows prepara um pacote de job assinado; uma futura sessao Clonezilla Live executara a clonagem somente com a origem desmontada e fora do Windows. O recurso continua desativado e nenhum boot, reboot ou escrita em disco e autorizado nesta fase.

O motor escolhido para integracao e Clonezilla Live `3.3.3-15`, usando `ocs-onthefly` para clone local de disco inteiro e Partclone como dependencia interna. O resolver nunca passa `SERIALNO=` para `ocs-onthefly`: ele compara fingerprints persistentes novamente no Linux e passa somente os nodes `/dev/...` atuais. Nomes de device, numero de disco, ponto de montagem e GUID copiado nao sao identidade persistente.

O prototipo fake-only implementa schema versionado, assinatura destacada por interface, nonce de uso unico, expiracao, inventario Linux normalizado, resolver fail-closed, renderer argv sem shell, pacote de resultado e consumo com `boot_tested=false`. A assinatura protege a integridade de transporte, mas o consumidor tambem exige o job verificado e o hash do plano de comando confiavel; engine, release, labels, fases, timestamps, hashes, destino offline e texto de erro sao validados semanticamente. A simulacao pode ser executada com:

```powershell
python -m localvault disk-clone-simulate --root <vault-root>
python -m localvault disk-clone-runtime-validate --root <vault-root>
python -m localvault disk-clone-virtual-roundtrip --root <vault-root>
```

O comando acima usa somente inventario e pacotes temporarios falsos. A fase `fake_engine_rendered_only` e consumida apenas pelo perfil de simulacao e retorna `offline_simulation_completed`; ela nao e evidencia de clone concluido nem de verificacao estrutural. Uma futura fase de producao devera usar `clone_completed_structurally_verified` com `confirmed_offline`, campos vinculados ao job/plano confiavel e `boot_tested=false`; somente entao o resultado podera ser `offline_clone_structurally_verified`. `disk-clone-run` fica em `offline_boot_not_configured` e nao inicia provedor Windows. A tela mostra que o boot offline nao esta configurado, oferece apenas prontidao e simulacao, e nao apresenta uma acao de clone imediato.

O handoff escolhido e um USB Clonezilla Live dedicado com selecao manual de boot. Ele evita alterar permanentemente a ordem de boot e exige uma acao humana; nenhum BCD, UEFI NVRAM, BootNext, USB, particao ou PXE foi alterado. A fase atual separa a verificacao `gpgv` oficial do DRBL da atestacao local L-vault, com fingerprints e keyrings derivados distintos, manifest canonico assinado, binding criptografico entre ISO verificado e inventario completo da arvore extraida, inspeção estatica de ferramentas sem execucao, canal de retorno virtual duravel e runner virtual somente-simulacao. A assinatura local atesta somente o workflow local confiavel; nao e assinatura oficial Clonezilla/DRBL nem prova de extracao arbitraria correta. Como nao havia ISO oficial, arvore extraida ou stack de VM segura presente, o status honesto continua `offline_runtime_blocked`; nenhum boot de VM ocorreu.

O canal virtual usa somente diretorios temporarios e dispositivos sinteticos. Os estados `pending`, `running`, `result`, `failed` e `consumed` sao monotônicos; publicacao parcial, resultado duplicado, conflito, replay, truncamento ou crash nunca vira sucesso. A UI continua afirmando que nenhum clone fisico foi executado, nenhum boot fisico foi testado, a execucao real esta desativada, e validacao estatica/virtual nao equivale a validacao no hardware do usuario.

AOMEI e DiskGenius permanecem alternativas historicas rejeitadas, nao recomendacoes. Nao houve inscricao real, selecao de disco, clone, formatacao, reparticionamento, `Set-Disk`, montagem, desmontagem, provider launch, tarefa destrutiva, reboot ou boot test.

Fontes oficiais e aplicabilidade estao em [`docs/disk-clone-offline.md`](docs/disk-clone-offline.md).

## Limites Seguros

Gmail pode ser automatico via API oficial. Fotos e videos completos dependem de Google Takeout. O sistema nao rouba credenciais e nao apaga dados remotos.

Os arquivos `.eml` do Gmail sao salvos com nomes legiveis no padrao `data_remetente_assunto_id.eml`. Para renomear e-mails antigos ja baixados:

```powershell
python -m localvault rename-gmail-files --root E:\LocalVault
```

Para conferir se existe duplicacao real no backup do Gmail, rode:

```powershell
python -m localvault gmail-dedupe-audit --root E:\LocalVault
```

O backup Gmail API e incremental: depois do primeiro indice, ele busca somente mensagens recentes com uma pequena margem de seguranca e pula e-mails ja salvos por `gmail_id` ou hash SHA-256.
