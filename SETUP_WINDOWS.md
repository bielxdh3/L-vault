# Setup Windows

## Setup idempotente e seguro

Instale Python 3.12+ e execute `setup` para criar diretorios, configuracao e banco sem instalar scheduler ou iniciar OAuth:

```powershell
python -m localvault setup --root <VAULT_ROOT> --non-interactive
python -m localvault setup --root <VAULT_ROOT> --password-stdin
```

A senha nao deve ser argumento. `config/auth.json`, tokens, client secrets, banco, logs e backups ficam fora do versionamento. A senha e configuracao existentes sao preservadas em execucoes repetidas. O painel exige autenticacao, CSRF e Origin; LAN exige `allow_lan: true` e TLS valido.

```powershell
python -m localvault health-check --root <VAULT_ROOT> --json
python -m localvault verify --root <VAULT_ROOT>
python -m localvault recovery-test
```

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

## Restore e replica

Restore exige destino separado e nao altera o cofre. Use primeiro o plano; conflitos sao `skip` por padrao:

```powershell
python -m localvault restore-plan --root <VAULT_ROOT> --destination <RESTORE_ROOT>
python -m localvault restore --root <VAULT_ROOT> --destination <RESTORE_ROOT> --dry-run
python -m localvault restore --root <VAULT_ROOT> --destination <RESTORE_ROOT>
```

Replica e desabilitada sem destino explicito, usa staging, promocao atomica, hashes, copia incremental e snapshot consistente do SQLite. Itens ausentes na origem nao sao removidos do destino.

```powershell
python -m localvault replica-plan --root <VAULT_ROOT> --destination <REPLICA_ROOT>
python -m localvault replica --root <VAULT_ROOT> --destination <REPLICA_ROOT>
```

Os nomes e horarios padrao do scheduler sao: Daily Backup 02:00, Weekly Takeout Import 03:00 aos domingos, Verify Weekly 04:00 aos domingos e Bootable Disk Clone 03:00 quando habilitado. O clone continua desativado e fail-closed por padrao.

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

O intervalo padrao e 30 dias (configuravel entre 1 e 3650), a janela 03:00-04:00 usa o horario local do Windows, e timestamps persistentes usam UTC. A amostragem de atividade usa limite de 70%, e cada tentativa mostra cinco minutos de aviso. Revalidacao de identidade, resolucao de caminhos protegidos por disco fisico e inventario pos-provedor sao obrigatorios; qualquer ambiguidade bloqueia. O destino deve permanecer offline entre execucoes. O painel `Clone do disco` mostra estado, progresso honesto, atividade, historico, verificacao estrutural, limpeza offline e o aviso permanente de que nenhum boot test foi realizado.

O cadastro de hardware e a ativacao do provedor sao fail-closed. O provedor selecionado vem de `disk_clone.provider`; nao ha fallback silencioso de um provedor configurado. DiskGenius permanece sem contrato CLI seguro validado. AOMEI ausente ou com edicao/capacidades nao validadas permanece bloqueado. A execucao real tambem continua desativada enquanto `allow_real_provider_execution` for falso.
