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

Digite `YES` quando o instalador do agendamento pedir confirmacao. Se o PC estiver desligado no horario marcado, as tarefas comuns podem rodar quando o Windows ligar novamente; a tarefa de clone nao usa catch-up e espera a proxima janela 03:00–04:00.

## Clone inicializavel

O clone fisico vem desativado e nunca deve ser testado contra discos reais. Primeiro descubra o provedor sem mutar armazenamento:

```powershell
python -m localvault disk-clone-status --root E:\LocalVault
python -m localvault disk-clone-check --root E:\LocalVault
python -m localvault disk-clone-simulate --root E:\LocalVault
```

Somente depois de validar o provedor local e confirmar que o destino dedicado pode ser apagado, execute a inscricao administrativa. Ela grava um manifesto HMAC com identidade estavel, deixa o destino offline e nao inicia um clone:

```powershell
python -m localvault disk-clone-enroll --root E:\LocalVault
```

O intervalo padrao e 30 dias (configuravel entre 1 e 3650), a amostragem de atividade usa limite de 70%, e cada tentativa mostra cinco minutos de aviso. O destino deve permanecer offline entre execucoes. O painel `Clone do disco` mostra o historico, a verificacao estrutural e o aviso permanente de que nenhum boot test foi realizado.
