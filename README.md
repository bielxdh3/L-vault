# LocalVault Backup Manager

LocalVault e um cofre local para Gmail, Google Photos via Takeout e exports do WhatsApp.

Este projeto foi recriado em:

```text
E:\LocalVault
```

## Uso Rapido

```powershell
cd E:\LocalVault
.\install.ps1
python -m localvault viewer-shortcut --root E:\LocalVault
```

Viewer:

```text
http://127.0.0.1:8787
```

Depois disso, use o atalho `Abrir LocalVault` na area de trabalho. Ele inicia o painel em segundo plano e abre o navegador, sem deixar uma janela do PowerShell aberta.

## Comandos

```powershell
python -m localvault init --root E:\LocalVault
python -m localvault sync-sources --root E:\LocalVault
python -m localvault ingest-all --root E:\LocalVault
python -m localvault backup-gmail-api --root E:\LocalVault
python -m localvault daily-backup --root E:\LocalVault
python -m localvault rename-gmail-files --root E:\LocalVault
python -m localvault dedupe --root E:\LocalVault
python -m localvault verify --root E:\LocalVault
python -m localvault schedule --root E:\LocalVault
```

## Automacao

O `sync-sources` copia automaticamente arquivos detectados em `Downloads` para as pastas do LocalVault.

O agendador diario padrao:

- 02:00 Backup diario principal: Gmail API, sync de fontes, importacao de Google Takeout/WhatsApp e relatorio de duplicados
- Domingo 04:00 Verificacao

Se o PC estiver desligado no horario marcado, o Windows roda a tarefa assim que possivel quando o computador ligar novamente.

Instalar tarefas:

```powershell
python -m localvault schedule-install --root E:\LocalVault
```

## Limites Seguros

Gmail pode ser automatico via API oficial. Google Photos completo deve usar Takeout; WhatsApp chats dependem de export oficial ou midia acessivel. O sistema nao rouba credenciais, nao descriptografa bancos do WhatsApp e nao apaga dados remotos.

Os arquivos `.eml` do Gmail sao salvos com nomes legiveis no padrao `data_remetente_assunto_id.eml`. Para renomear e-mails antigos ja baixados:

```powershell
python -m localvault rename-gmail-files --root E:\LocalVault
```
