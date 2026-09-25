# Backlog: Segurança da cadeia de dependências

Plano de trabalho para colocar e manter em produção o scan de vulnerabilidades e o SBOM das dependências.

**Convenções**

- IDs locais (`E1`, `E1-S1`, `E1-S1-T1`) para referência cruzada; trocar pelos IDs do Jira (REV-XXX) ao criar.
- Estimativa das stories em story points (Fibonacci); tasks em horas.
- Status inicial: `Done` para o que já está no PR, `To Do` para o restante.

## Visão geral

| Épico | Objetivo | Stories | Pontos | Prioridade |
|---|---|---|---|---|
| **E1** | Scanner de dependências e SBOM no CI | 5 | 16 | Highest |
| **E2** | Triagem e remediação do baseline | 4 | 13 | Highest |
| **E3** | Operação contínua e governança | 5 | 13 | High |
| **E4** | Ampliação da cobertura (frontend e containers) | 3 | 13 | Medium |
| | **Total** | **17** | **55** | |

**Dependências entre épicos:** E1 → E2 → E3 (S3 depende do baseline limpo). E4 pode começar em paralelo a E2.

---

## E1 · Scanner de dependências e SBOM no CI

**Objetivo:** ter um gate automático que impeça a entrada de dependências Python vulneráveis ou maliciosas e gere um inventário (SBOM) a cada execução.

**Critério de sucesso do épico:** todo PR que altera dependências roda o scan; achados `HIGH`/`CRITICAL` bloqueiam o merge; SBOM disponível como artefato.

### E1-S1 · Gerar SBOM das dependências Python · 3 pts · `Done`

> Como engenheiro, quero um SBOM padronizado das dependências do backend para saber exatamente o que roda no sistema e responder auditorias.

**Critérios de aceite**

- [x] Gera `sbom.cdx.json` no formato CycloneDX 1.5
- [x] Cada componente tem `name`, `version` e `purl` (`pkg:pypi/...`)
- [x] Lê `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements.txt` e o ambiente instalado
- [x] `--sbom-only` funciona sem acesso à rede

| ID | Task | Estimativa | Status |
|---|---|---|---|
| E1-S1-T1 | Parser de `requirements.txt` (pins, extras, markers, `--hash`, `-r` recursivo) | 2h | Done |
| E1-S1-T2 | Parsers de `poetry.lock`, `uv.lock` e `Pipfile.lock` | 2h | Done |
| E1-S1-T3 | Coleta do ambiente instalado (`--env`) | 1h | Done |
| E1-S1-T4 | Normalização de nomes (PEP 503) e deduplicação de pacotes | 1h | Done |
| E1-S1-T5 | Montagem do documento CycloneDX | 2h | Done |

### E1-S2 · Consultar bases de vulnerabilidades · 5 pts · `Done`

> Como engenheiro, quero cruzar cada dependência com bases públicas para saber se alguma versão que usamos é vulnerável ou maliciosa.

**Critérios de aceite**

- [x] Consulta OSV.dev em lote
- [x] Consulta GitHub Advisory Database quando há `GITHUB_TOKEN`
- [x] Enriquece CVEs com CVSS e status do NVD
- [x] Relatório linka o registro no CVE.org
- [x] Mesma vulnerabilidade vinda de fontes diferentes aparece uma vez só
- [x] Pacotes maliciosos (`MAL-*`) classificados como `CRITICAL`
- [x] Retry com backoff em rate limit e erros 5xx

| ID | Task | Estimativa | Status |
|---|---|---|---|
| E1-S2-T1 | Cliente OSV (querybatch + detalhes em paralelo) | 3h | Done |
| E1-S2-T2 | Cliente GitHub Advisories (`affects=pacote@versão`) | 2h | Done |
| E1-S2-T3 | Enriquecimento NVD com controle de taxa | 2h | Done |
| E1-S2-T4 | Deduplicação por aliases (CVE / GHSA / PYSEC) | 2h | Done |
| E1-S2-T5 | Extração da versão corrigida (`fixed in`) | 1h | Done |
| E1-S2-T6 | Cliente HTTP com retry, timeout e backoff | 1h | Done |

### E1-S3 · Gate no CI · 3 pts · `In Review`

> Como tech lead, quero que o CI bloqueie PRs que introduzam vulnerabilidades graves para que elas não cheguem à `main`.

**Critérios de aceite**

- [x] Workflow roda em PRs que alteram arquivos de dependência, em push na `main`, agendado e manual
- [x] `--fail-on` configurável; padrão `high`
- [x] Exit `2` quando nenhuma fonte responde (fail closed)
- [x] Resumo no job summary e artefato `sbom-report` com retenção de 30 dias
- [ ] Workflow executado com sucesso no repositório real

| ID | Task | Estimativa | Status |
|---|---|---|---|
| E1-S3-T1 | Criar `.github/workflows/dependency-scan.yml` | 1h | Done |
| E1-S3-T2 | Ajustar o caminho do scan se o backend estiver em subpasta | 0,5h | To Do |
| E1-S3-T3 | Validar execução no PR e conferir o artefato | 1h | To Do |
| E1-S3-T4 | Alinhar com o time o `--fail-on` inicial (`high` ou `critical`) | 0,5h | To Do |

### E1-S4 · Mecanismo de exceções · 2 pts · `Done`

> Como engenheiro, quero registrar exceções justificadas para que um falso positivo ou uma vulnerabilidade não explorável não trave o time.

**Critérios de aceite**

- [x] `.vulnignore` com um ID por linha e comentários
- [x] Flag `--ignore` repetível
- [x] Log informa quantos achados foram ignorados

| ID | Task | Estimativa | Status |
|---|---|---|---|
| E1-S4-T1 | Leitura do `.vulnignore` e do `--ignore` | 1h | Done |
| E1-S4-T2 | Template do arquivo com o formato exigido (motivo, responsável, data) | 0,5h | Done |

### E1-S5 · Documentação e merge · 3 pts · `In Review`

> Como membro do time, quero saber como rodar o scan localmente e interpretar o resultado.

**Critérios de aceite**

- [x] README com uso, flags, variáveis de ambiente e códigos de saída
- [ ] PR aprovado e mergeado
- [ ] Time avisado no canal de engenharia sobre o novo check

| ID | Task | Estimativa | Status |
|---|---|---|---|
| E1-S5-T1 | Escrever README | 1h | Done |
| E1-S5-T2 | Adicionar `sbom-report/` ao `.gitignore` | 0,25h | To Do |
| E1-S5-T3 | Code review e merge | 1h | To Do |
| E1-S5-T4 | Comunicar o time (como rodar local, o que fazer quando o check falha) | 0,5h | To Do |

---

## E2 · Triagem e remediação do baseline

**Objetivo:** zerar as vulnerabilidades `CRITICAL` e `HIGH` já existentes para o gate poder operar em `high` sem exceções permanentes.

**Critério de sucesso do épico:** scan da `main` sem achados `HIGH`/`CRITICAL` fora do `.vulnignore`, e toda exceção com justificativa e data de revisão.

### E2-S1 · Scan inicial e triagem · 3 pts · `To Do`

> Como tech lead, quero a lista priorizada das vulnerabilidades atuais para planejar a correção.

**Critérios de aceite**

- [ ] Relatório inicial da `main` anexado ao épico
- [ ] Cada achado classificado: corrigir, aceitar risco (com justificativa) ou falso positivo
- [ ] Um ticket de remediação por pacote afetado

| ID | Task | Estimativa | Status |
|---|---|---|---|
| E2-S1-T1 | Rodar o scan na `main` com `--env` dentro do venv (cobre transitivas) | 0,5h | To Do |
| E2-S1-T2 | Avaliar se o código afetado é alcançável em cada achado | 3h | To Do |
| E2-S1-T3 | Criar tickets de remediação por pacote | 1h | To Do |

### E2-S2 · Corrigir vulnerabilidades CRITICAL · 5 pts · `To Do`

> Como engenheiro, quero atualizar os pacotes com vulnerabilidade crítica para eliminar o risco mais grave primeiro.

**Critérios de aceite**

- [ ] Nenhum achado `CRITICAL` na `main`
- [ ] Testes (unitários e E2E) passando após os upgrades
- [ ] Upgrades de major version com changelog revisado

| ID | Task | Estimativa | Status |
|---|---|---|---|
| E2-S2-T1 | Atualizar pacotes críticos para a versão corrigida | 3h | To Do |
| E2-S2-T2 | Revisar breaking changes (Django, DRF, Celery e libs de integração) | 2h | To Do |
| E2-S2-T3 | Rodar a suíte completa e testar os fluxos principais da aplicação | 3h | To Do |
| E2-S2-T4 | Deploy em staging e smoke test | 1h | To Do |

### E2-S3 · Corrigir vulnerabilidades HIGH · 3 pts · `To Do`

**Critérios de aceite**

- [ ] Nenhum achado `HIGH` na `main` fora do `.vulnignore`
- [ ] Exceções com motivo, responsável e data de revisão

| ID | Task | Estimativa | Status |
|---|---|---|---|
| E2-S3-T1 | Atualizar pacotes com severidade `HIGH` | 3h | To Do |
| E2-S3-T2 | Registrar exceções aprovadas no `.vulnignore` | 0,5h | To Do |
| E2-S3-T3 | Subir o gate para `--fail-on high`, caso tenha começado em `critical` | 0,25h | To Do |

### E2-S4 · Fixar todas as versões · 2 pts · `To Do`

> Como engenheiro, quero todas as dependências fixadas (incluindo transitivas) para o scan cobrir 100% do que vai para produção.

**Critérios de aceite**

- [ ] Nenhuma linha "unpinned" no aviso do scanner
- [ ] Transitivas fixadas via lock file (`uv`, `poetry` ou `pip-compile`)

| ID | Task | Estimativa | Status |
|---|---|---|---|
| E2-S4-T1 | Escolher a ferramenta de lock com o time | 0,5h | To Do |
| E2-S4-T2 | Gerar o lock file e ajustar Dockerfile/CI para instalar a partir dele | 2h | To Do |
| E2-S4-T3 | Confirmar que o scanner detecta o lock automaticamente | 0,5h | To Do |

---

## E3 · Operação contínua e governança

**Objetivo:** garantir que o controle continue funcionando depois do merge e que vulnerabilidades novas em dependências antigas sejam percebidas rapidamente.

### E3-S1 · Alerta do scan agendado · 3 pts · `To Do`

> Como time, quero ser avisado quando o scan diário encontrar uma vulnerabilidade nova, sem precisar abrir o Actions.

**Critérios de aceite**

- [ ] Falha do job agendado notifica o canal de engenharia (Slack) com link para o relatório
- [ ] Execuções bem-sucedidas não geram notificação

| ID | Task | Estimativa | Status |
|---|---|---|---|
| E3-S1-T1 | Criar webhook do Slack e secret no repositório | 0,5h | To Do |
| E3-S1-T2 | Step de notificação condicional (`if: failure() && github.event_name == 'schedule'`) | 1h | To Do |
| E3-S1-T3 | Testar via `workflow_dispatch` com um pin vulnerável em branch de teste | 0,5h | To Do |

### E3-S2 · Chave da API do NVD · 1 pt · `To Do`

| ID | Task | Estimativa | Status |
|---|---|---|---|
| E3-S2-T1 | Solicitar a API key do NVD com e-mail do time | 0,25h | To Do |
| E3-S2-T2 | Cadastrar o secret `NVD_API_KEY` no repositório | 0,25h | To Do |

### E3-S3 · Check obrigatório na `main` · 1 pt · `To Do`

> Depende de E2-S3.

**Critérios de aceite**

- [ ] Branch protection da `main` exige o check **Dependency scan**

| ID | Task | Estimativa | Status |
|---|---|---|---|
| E3-S3-T1 | Configurar branch protection (admin do repo) | 0,25h | To Do |

### E3-S4 · Política de exceções e SLA de correção · 3 pts · `To Do`

> Como tech lead, quero regras claras para aceitar risco e prazos de correção por severidade, para o `.vulnignore` não virar um lugar de esquecer problemas.

**Critérios de aceite**

- [ ] Política documentada: quem aprova exceção, prazo máximo, revisão periódica
- [ ] SLA de correção por severidade definido e aprovado
- [ ] Mudanças no `.vulnignore` exigem aprovação de um responsável (CODEOWNERS)

| ID | Task | Estimativa | Status |
|---|---|---|---|
| E3-S4-T1 | Redigir a política e o SLA e aprovar com o gestor | 2h | To Do |
| E3-S4-T2 | Adicionar `.vulnignore` ao `CODEOWNERS` | 0,25h | To Do |
| E3-S4-T3 | Agendar revisão mensal das exceções | 0,25h | To Do |

### E3-S5 · SBOM versionado por release · 5 pts · `To Do`

> Como responsável por compliance, quero o SBOM de cada versão em produção guardado, para responder a qualquer momento se uma release específica estava exposta a uma CVE.

**Critérios de aceite**

- [ ] SBOM gerado a cada tag/release e anexado à release
- [ ] Cópia armazenada em bucket S3 com retenção definida
- [ ] Runbook: "como verificar se a produção está exposta à CVE X"

| ID | Task | Estimativa | Status |
|---|---|---|---|
| E3-S5-T1 | Workflow disparado em `release` gerando o SBOM | 1h | To Do |
| E3-S5-T2 | Upload para S3 (bucket, IAM e retenção) | 2h | To Do |
| E3-S5-T3 | Escrever o runbook de consulta | 1h | To Do |

---

## E4 · Ampliação da cobertura

**Objetivo:** cobrir as partes do sistema que ficaram fora do escopo inicial.

### E4-S1 · Dependências do frontend React · 5 pts · `To Do`

> Como engenheiro, quero o mesmo controle para os pacotes npm do frontend.

**Critérios de aceite**

- [ ] Scanner lê `package-lock.json` (ou `yarn.lock` / `pnpm-lock.yaml`)
- [ ] Consulta OSV com ecossistema `npm`
- [ ] SBOM unificado ou um SBOM por aplicação
- [ ] Workflow dispara em mudanças nos lock files do frontend

| ID | Task | Estimativa | Status |
|---|---|---|---|
| E4-S1-T1 | Parser de `package-lock.json` | 2h | To Do |
| E4-S1-T2 | Generalizar o ecossistema nos clientes OSV/GitHub (`PyPI` / `npm`) | 2h | To Do |
| E4-S1-T3 | Ajustar `purl` no SBOM (`pkg:npm/...`) | 1h | To Do |
| E4-S1-T4 | Atualizar workflow e README | 1h | To Do |
| E4-S1-T5 | Triagem do baseline do frontend | 2h | To Do |

### E4-S2 · Imagens Docker · 5 pts · `To Do`

> Como engenheiro, quero saber se os pacotes do sistema operacional das imagens base têm vulnerabilidades.

**Critérios de aceite**

- [ ] Ferramenta de scan de imagem avaliada e escolhida
- [ ] Scan das imagens roda no CI antes do push para o registry
- [ ] Gate com a mesma política de severidade

| ID | Task | Estimativa | Status |
|---|---|---|---|
| E4-S2-T1 | Avaliar ferramentas de scan de container (open source vs. nativas da AWS) | 2h | To Do |
| E4-S2-T2 | Integrar o scan de imagem ao pipeline de build | 3h | To Do |
| E4-S2-T3 | Triagem do baseline das imagens | 2h | To Do |

### E4-S3 · Atualizações automáticas de dependências · 3 pts · `To Do`

> Como time, quero PRs automáticos de upgrade para as correções chegarem sem depender de alguém lembrar.

**Critérios de aceite**

- [ ] Dependabot ou Renovate configurado para pip e npm
- [ ] Agrupamento de atualizações menores para reduzir ruído
- [ ] PRs de segurança priorizados

| ID | Task | Estimativa | Status |
|---|---|---|---|
| E4-S3-T1 | Escolher e configurar a ferramenta | 1h | To Do |
| E4-S3-T2 | Definir agrupamento e frequência | 0,5h | To Do |
| E4-S3-T3 | Documentar o fluxo de revisão desses PRs | 0,5h | To Do |

---

## Definition of Done (válida para todas as stories)

- Código revisado e aprovado em PR
- CI verde, incluindo o próprio Dependency scan
- Documentação atualizada quando o comportamento muda
- Critérios de aceite verificados por alguém além de quem implementou
