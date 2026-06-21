# Setup Windows

1. Instale Python 3.12+.
2. Abra PowerShell:

```powershell
cd E:\LocalVault
.\install.ps1
```

3. Coloque exports em:

```text
E:\LocalVault\inbox\google_takeout
```

4. Rode:

```powershell
python -m localvault ingest-all --root E:\LocalVault
```

5. Viewer:

```powershell
python -m localvault viewer-shortcut --root E:\LocalVault
```

Depois clique em `Abrir LocalVault` na area de trabalho. O painel abre em `http://127.0.0.1:8787` sem manter uma janela do PowerShell visivel.

6. Backup automatico diario:

```powershell
python -m localvault schedule --root E:\LocalVault
python -m localvault schedule-install --root E:\LocalVault
```

Digite `YES` quando o instalador do agendamento pedir confirmacao. Se o PC estiver desligado no horario marcado, a tarefa roda quando o Windows ligar novamente.
