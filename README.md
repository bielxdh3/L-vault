# LocalVault Backup Manager

LocalVault e um cofre local para Gmail e Google Takeout.

Escolha uma raiz privada para o cofre e substitua `<VAULT_ROOT>` nos exemplos.

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

O painel usa `127.0.0.1` por padrao. Para LAN, configure `viewer.allow_lan: true` e uma senha; isso ainda usa HTTP sem criptografia, portanto use somente uma rede confiavel ate adicionar TLS. O leitor de e-mails sanitiza HTML com allowlist, bloqueando scripts, manipuladores de evento e imagens remotas; o iframe continua sandboxed.

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
python -m localvault schedule --root <VAULT_ROOT>
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

- 02:00 Backup diario principal: Gmail API, sync de fontes, importacao de Takeout e relatorio de duplicados
- 01:30 Importacao automatica de Takeout: move ZIPs reconhecidos do diretorio configurado para o Vault
- Domingo 04:00 Verificacao

Se o PC estiver desligado no horario marcado, o Windows roda a tarefa assim que possivel quando o computador ligar novamente.

Instalar tarefas:

```powershell
python -m localvault schedule-install --root <VAULT_ROOT>
```

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
