# L-Vault — registro histórico do protótipo Clonezilla offline

> [!NOTE]
> Registro técnico do README da `main` (blob `0cfc4c4e2cf5389a111fcf711e5cf939e3b017ad`), preservado em 2026-11-09. **Testes estáticos e sintéticos não comprovam clone físico nem autorizam qualquer escrita em disco.** O fluxo atual de dados Windows é independente: [worker first-party](../clone-worker-runtime.md) · [protótipo offline](../disk-clone-offline.md).

## Histórico: protótipo Clonezilla offline

O L-vault nao exige software pago. O Windows prepara um pacote de job assinado; uma futura sessao Clonezilla Live executara a clonagem somente com a origem desmontada e fora do Windows. O status e os comandos de clone permanecem disponiveis, mas a execucao fisica continua gated: nenhum boot, reboot ou escrita em disco e autorizado nesta fase. O clone físico permanece desativado por padrão e fail-closed.

O motor escolhido para integracao e Clonezilla Live `3.3.3-15`, usando `ocs-onthefly` para clone local de disco inteiro e Partclone como dependencia interna. O resolver nunca passa `SERIALNO=` para `ocs-onthefly`: ele compara fingerprints persistentes novamente no Linux e passa somente os nodes `/dev/...` atuais. Nomes de device, numero de disco, ponto de montagem e GUID copiado nao sao identidade persistente.

O prototipo fake-only implementa schema versionado, assinatura destacada por interface, nonce de uso unico, expiracao, inventario Linux normalizado, resolver fail-closed, renderer argv sem shell, pacote de resultado e consumo com `boot_tested=false`. A assinatura protege a integridade de transporte, mas o consumidor tambem exige o job verificado e o hash do plano de comando confiavel; engine, release, labels, fases, timestamps, hashes, destino offline e texto de erro sao validados semanticamente. A simulacao pode ser executada com:

```powershell
python -m localvault disk-clone-simulate --root <VAULT_ROOT>
python -m localvault disk-clone-runtime-validate --root <VAULT_ROOT>
python -m localvault disk-clone-virtual-roundtrip --root <VAULT_ROOT>
```

O comando acima usa somente inventario e pacotes temporarios falsos. A fase `fake_engine_rendered_only` e consumida apenas pelo perfil de simulacao e retorna `offline_simulation_completed`; ela nao e evidencia de clone concluido nem de verificacao estrutural. Uma futura fase de producao devera usar `clone_completed_structurally_verified` com `confirmed_offline`, campos vinculados ao job/plano confiavel e `boot_tested=false`; somente entao o resultado podera ser `offline_clone_structurally_verified`. Com clone desativado, `disk-clone-run` retorna `blocked_configuration`; se explicitamente habilitado, permanece em `offline_boot_not_configured` e nao inicia provedor Windows. A tela mostra que o boot offline nao esta configurado, oferece apenas prontidao e simulacao, e nao apresenta uma acao de clone imediato.

O handoff escolhido e um USB Clonezilla Live dedicado com selecao manual de boot. Ele evita alterar permanentemente a ordem de boot e exige uma acao humana; nenhum BCD, UEFI NVRAM, BootNext, USB, particao ou PXE foi alterado. A fase atual separa a verificacao `gpgv` oficial do DRBL da atestacao local L-vault, com o fingerprint DRBL `54C0821A48715DAFD61BFCAF667857D045599AFD` e o SHA-256 oficial `482518ea32af3b82ed15d09e2e7714806775deb62aeed81491e534f6cc6bbc47` do ISO `clonezilla-live-3.3.3-15-amd64.iso` fixados no contrato de producao. Esses valores nao podem ser redefinidos por CLI, configuracao, manifesto ou construtor; overrides de digest existem somente na fabrica explicita de testes sinteticos. A atestacao local L-vault permanece um trust root separado e nunca e proveniencia oficial Clonezilla/DRBL. O binding criptografico entre ISO verificado e inventario completo da arvore extraida, a inspeÃ§Ã£o estatica de ferramentas sem execucao, o canal de retorno virtual duravel e o runner virtual somente-simulacao continuam ativos. Como nao havia ISO oficial, arvore extraida ou stack de VM segura presente, o status honesto continua `offline_runtime_blocked`; nenhum boot de VM ocorreu.

O canal virtual do protótipo antigo usa somente diretórios temporários e dispositivos sintéticos. Seus estados monotônicos impedem que publicação parcial, replay, truncamento ou crash virem sucesso. Essas afirmações descrevem apenas o protótipo Clonezilla; ele não é usado pelo fluxo normal de clone de dados.

AOMEI, DiskGenius e Clonezilla descrevem experimentos ou protótipos anteriores; nenhum deles é o backend do caminho normal de clone de dados.

Fontes oficiais e aplicabilidade estao em [`docs/disk-clone-offline.md`](../disk-clone-offline.md).

### Histórico do protótipo: validação estática do artefato Clonezilla

O fluxo separado de artefato real baixa ou revalida somente o Clonezilla Live `3.3.3-15` amd64 fixado, verifica `CHECKSUMS.TXT` e sua assinatura DRBL com `54C0821A48715DAFD61BFCAF667857D045599AFD`, e confirma o ISO `clonezilla-live-3.3.3-15-amd64.iso` pelo SHA-256 `482518ea32af3b82ed15d09e2e7714806775deb62aeed81491e534f6cc6bbc47`. O cache privado fica fora do repositorio; o modo offline apenas revalida arquivos existentes.

```powershell
python -m localvault disk-clone-artifacts-verify --cache <PRIVATE_ARTIFACT_CACHE> --gpg <ABSOLUTE_HOST_GPG> --gpgv <ABSOLUTE_HOST_GPGV>
python -m localvault disk-clone-artifact-status --cache <PRIVATE_ARTIFACT_CACHE>
python -m localvault disk-clone-attestor-status --gpg <ABSOLUTE_HOST_GPG> --gnupg-home <PRIVATE_ATTESTOR_HOME> --public-keyring <PUBLIC_ATTESTOR_KEYRING>
```

A verificacao oficial do publicador e a assinatura local de extracao sao trust roots separados. A arvore real, quando extraida por ferramenta local explicitamente permitida, e inventariada sem seguir links para o host; `gpg`, `sha256sum`, `lsblk`, `blkid`, `udevadm`, `findmnt`, `ocs-onthefly` e os binarios `partclone.*` fixados sao apenas inspecionados e marcados `present_unexecuted`. O `gpgv` e o verificador oficial no host, nao uma ferramenta exigida pelo rootfs Live. Nenhum comando extrai executaveis para rodar, monta ISO, acessa disco/USB, cria VM, inicializa, reinicia ou executa clone. Validacao estatica nao prova bootabilidade, Secure Boot ou corretude de clone.
