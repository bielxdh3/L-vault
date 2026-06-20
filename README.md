# LocalVault Backup Manager

LocalVault e um cofre local para Gmail, Fotos via Google Takeout e exports do WhatsApp.

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

O `sync-sources` copia automaticamente exports detectados em `Downloads` para as pastas de inbox do LocalVault.

O agendador diario padrao:

- 02:00 Backup diario principal: Gmail API, sync de fontes, importacao de Takeout/WhatsApp e relatorio de duplicados
- Domingo 04:00 Verificacao

Se o PC estiver desligado no horario marcado, o Windows roda a tarefa assim que possivel quando o computador ligar novamente.

Instalar tarefas:

```powershell
python -m localvault schedule-install --root E:\LocalVault
```

## Limites Seguros

Gmail pode ser automatico via API oficial. Fotos completas dependem de Google Takeout. WhatsApp chats dependem de export oficial ou midia acessivel. O sistema nao rouba credenciais, nao descriptografa bancos do WhatsApp e nao apaga dados remotos.

Os arquivos `.eml` do Gmail sao salvos com nomes legiveis no padrao `data_remetente_assunto_id.eml`. Para renomear e-mails antigos ja baixados:

```powershell
python -m localvault rename-gmail-files --root E:\LocalVault
```

Para conferir se existe duplicacao real no backup do Gmail, rode:

```powershell
python -m localvault gmail-dedupe-audit --root E:\LocalVault
```

O backup Gmail API e incremental: depois do primeiro indice, ele busca somente mensagens recentes com uma pequena margem de seguranca e pula e-mails ja salvos por `gmail_id` ou hash SHA-256.
