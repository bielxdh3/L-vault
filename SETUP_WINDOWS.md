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

Os nomes e horarios padrao do scheduler sao: Daily Backup 02:00, Weekly Takeout Import 03:00 aos domingos, Verify Weekly 04:00 aos domingos e Bootable Disk Clone 03:00 quando habilitado. Essa última tarefa é o executor offline legado e permanece fail-closed; ela não controla a ação manual Clone do sistema descrita abaixo.

## Clone do sistema Windows

Abra **L-vault → Clone do sistema** e escolha **Clone now**. O caminho normal usa DiskGenius 6.1.1 em **Tools → System Migration → Hot Migration**. Não exige Clonezilla, USB, menu BIOS/UEFI ou comandos Linux; não altere a sequência de boot.

O papel autorizado da origem é KINGSTON SNV2S1000G / `****775.` (Windows atual, somente leitura). O destino autorizado é ST1000VM002-1CT162 / `****4EM2` e será apagado. O HGST HTS541010A9E680 / `****91NS` contém `E:\LocalVault`; nunca selecione esse disco no DiskGenius. A página mostra os números de disco e volumes atuais após uma inventarização fresca e pede confirmação visual da origem e destino; L-vault repete a validação das identidades persistentes antes da confirmação destrutiva.

No assistente DiskGenius, mantenha selecionadas as partições padrão de sistema/boot: a ESP Kingston ativa auditada é a partição 2 (100 MiB), e as partições 3–5 são ESPs históricas. Confirme visualmente Kingston como origem e Seagate como destino; deixe desmarcada qualquer opção para alterar a sequência de boot; escolha Hot Migration. Depois da conclusão exibida pelo DiskGenius, feche-o e use **Verificar resultado** em L-vault.

L-vault verifica GPT, uma ESP FAT32, partição Windows NTFS, Windows, arquivos EFI/BCD e o vínculo entre BCD e o Windows migrado. Essa verificação é estrutural e não inicia o Windows clonado. O estado BitLocker da origem é exibido quando o Windows permite consultá-lo; se aparecer como desconhecido, confirme-o no Windows antes de aceitar a gravação. Mantenha a chave de recuperação disponível se o Kingston estiver criptografado.

O modo assistido não lê as linhas selecionadas no DiskGenius. A seleção visual do proprietário e o relato de conclusão do fornecedor permanecem entradas confiáveis. Se a janela de revalidação expirar antes do início, não aceite o aviso de sobrescrita: feche DiskGenius sem iniciar a gravação, registre o cancelamento seguro no L-vault e comece uma sessão nova. Uma falha ou interrupção não é repetida automaticamente.

Os comandos CLI `disk-clone-*` e a tarefa agendada Bootable Disk Clone pertencem ao antigo fluxo offline Clonezilla e continuam separados desta ação manual. Sua opção `disk_clone.enabled` controla apenas o executor legado; não habilita Clonezilla nem altera o fluxo DiskGenius do proprietário. Veja [a implementação e seus limites](docs/diskgenius-normal-clone.md) e [o protótipo offline](docs/disk-clone-offline.md).
