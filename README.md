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

## Clone fisico inicializavel do disco

O recurso `Clone do disco` e exclusivo do Windows, vem desativado e apaga completamente o HD de destino. Ele nao cria apenas um arquivo de imagem: o objetivo e copiar o disco fisico com EFI, Windows e particoes necessarias para uma substituicao inicializavel.

Antes do primeiro uso, confirme que o provedor e a edicao estao validados localmente e rode a inscricao administrativa:

```powershell
python -m localvault disk-clone-enroll --root E:\LocalVault
```

A inscricao grava um manifesto HMAC em `config`, usando serial, modelo, capacidade exata e identificadores fisicos. Numero de disco, letra e ponto de montagem sao apenas observacoes momentaneas. O destino nao pode conter `E:\LocalVault`, o banco, logs, configuracao, fontes ou qualquer caminho protegido do L-vault.

O agendamento verifica diariamente as 03:00 no fuso horario local do Windows, mas so pode iniciar entre 03:00 (inclusive) e 04:00 (exclusive). Timestamps, historico e vencimentos sao armazenados em UTC. Uma execucao perdida fica para a noite seguinte. O intervalo padrao e 30 dias e aceita de 1 a 3650 dias. Antes de qualquer provedor destrutivo ha uma contagem regressiva visivel de cinco minutos, com confirmacao antecipada, ocultar/restaurar e cancelamento explicito. Fechar a janela apenas oculta.

Durante os cinco minutos anteriores, o L-vault mede a atividade media do disco de origem. Media de 70% ou mais posterga para a proxima noite. O destino fica offline entre execucoes e e devolvido ao estado offline apos sucesso, falha, cancelamento ou interrupcao sempre que for seguro.

O progresso e rotulado como exato, estimado ou indisponivel. A saida bem-sucedida do provedor nao e suficiente: o L-vault re-inventaria o destino por identidade fisica estavel, classifica GPT por GUID e MBR por seus proprios flags, verifica a estrutura de particoes separadamente e nunca afirma que o clone foi inicializado. Caminhos protegidos sao resolvidos do volume ativo ao disco fisico; uma resolucao ambigua bloqueia a execucao mesmo quando o destino esta offline. A interface sempre mostra `boot test nao testado manualmente` ate uma confirmacao humana posterior.

No ambiente de desenvolvimento desta funcionalidade, o AOMEI Backupper nao esta instalado e o DiskGenius instalado nao oferece um contrato CLI nao interativo validado para selecao segura. AOMEI presente sem edicao/capacidades/cancelamento/progresso validados tambem permanece bloqueado. Portanto a execucao real permanece bloqueada; `disk-clone-simulate` usa somente inventario, provedor, relogio, resolucao de caminhos e progresso falsos, com revalidacao e verificacao pos-provedor frescas. Nenhum comando de clone, formatacao, reparticionamento, `Set-Disk`, overwrite ou mutacao de disco deve ser usado em testes. Nenhum boot test ocorreu.

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
