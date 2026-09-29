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

Os nomes e horários padrão do agendador são: Daily Backup 02:00, Weekly Takeout Import 03:00 aos domingos e Verify Weekly 04:00 aos domingos. A tarefa Legacy Bootable Disk Clone é legada, desabilitada em novas instalações e não define o clone normal de dados.

## Clone de dados do Windows

O clone normal é um clone de dados não inicializável controlado pelo próprio L-vault. Ao clicar em Clone, o L-vault prepara o runtime first-party se necessário, pede a permissão padrão do Windows e inicia a cópia. O runtime protegido registra os hashes exatos dos binários e o SID proprietário; uma assinatura Authenticode só é exigida quando um publicador estiver configurado. Não é necessário abrir outro programa nem alterar opções de inicialização.

Os papéis físicos autorizados são KINGSTON SNV2S1000G / `****775.` como origem somente leitura; ST1000VM002-1CT162 / `****4EM2` como destino que será apagado; e HGST HTS541010A9E680 / `****91NS` como disco protegido do repositório. O L-vault valida novamente esses discos por identidade persistente antes de apagar o alvo. Se alguma identidade ou proteção não puder ser confirmada, o clone para sem iniciar a gravação.

Os comandos `disk-clone-*`, o fluxo DiskGenius e o protótipo Clonezilla são caminhos legados/históricos e não definem o clone normal de dados.
