# Vitrix

Detection-as-Code sem depender de um SIEM. Você escreve regras em [Sigma](https://sigmahq.io), e o motor **valida**, **converte** para vários SIEMs e **testa** cada regra contra eventos de exemplo, tudo local e dentro do seu CI.

> Versão 0.1.0, alfa. Nome escolhido: Vitrix (domínio e marca ainda por verificar).

## Começando

```bash
pip install -e .          # na raiz do repositório
vitrix check            # lint + conversão + testes
```

Comandos:

| Comando | O que faz |
|---|---|
| `vitrix lint [--strict]` | Valida schema, condição e metadados. `--strict` faz avisos falharem. |
| `vitrix convert [-t alvo] [--stdout]` | Converte para os alvos do `vitrix.yml` e grava em `dist/` (com `manifest.json`). |
| `vitrix test` | Roda os casos de `cases/` contra o avaliador local. |
| `vitrix check [--markdown ARQ]` | Os três acima, para o CI. Com `--markdown "$GITHUB_STEP_SUMMARY"` publica o resumo na execução. |
| `vitrix targets` | Lista os SIEMs disponíveis. |
| `vitrix serve [--port N]` | Sobe a API local para a interface (precisa de `pip install -e ".[api]"`). |

Saída `0` = tudo certo, `1` = falha nas regras, `2` = erro de uso ou de configuração.

## Interface web

`vitrix serve` abre a API e a interface em `http://127.0.0.1:8000`. A interface já vem compilada dentro do pacote, então não precisa de Node para usar.

| Grupo | Telas |
|---|---|
| Visão | **Operacional** (pipeline, fluxo até a publicação, pendências, cobertura, CI e PRs) e **Executivo** (cobertura ATT&CK, regras publicáveis, testes, tempo até o merge, lacunas) |
| Detecções | **Regras**, **Editor** (validação ao vivo, trilha do fluxo, PR) e **Regex Workbench** |
| Validação | **Test Suites**, **Log Replay**, **MITRE Coverage**, **Quality Gate** e **Reports** |
| Sistema | **Conexões** (GitHub e SIEMs) e **Configurações** (edita o `vitrix.yml` com validação e abre PR) |

Números de CI e de PRs só aparecem com o GitHub conectado; sem conexão, a tela diz o que falta em vez de mostrar dado inventado.

### Salvar uma regra: pull request

O botão **Abrir pull request** do Editor manda a regra e os casos de teste para um branch novo no GitHub, em um único commit, e abre o PR contra o branch base. Nada é gravado no disco local; o CI do repositório valida o PR como qualquer outro. Regras reprovadas (erros de lint, conversão ou testes) não viram PR.

```yaml
# vitrix.yml
github:
  repo: minha-org/deteccoes
  base: main      # padrão: main
  path: ""        # pasta deste projeto dentro do repositório, se não for a raiz
```

O token vem do ambiente do `vitrix serve`, nunca do `vitrix.yml`:

```bash
export VITRIX_GITHUB_TOKEN=github_pat_...   # ou GITHUB_TOKEN
vitrix serve
```

Um token *fine-grained* restrito ao repositório basta, com permissão de escrita em **Contents** e **Pull requests**.

Para mexer na interface (React + TypeScript + Tailwind, em `web/`):

```bash
cd web && npm install
npm run dev      # http://localhost:5173, com proxy para a API em :8000
npm run build    # compila para src/vitrix/ui/ (commitar o resultado)
```

## Estrutura

```
vitrix.yml                 configuração do projeto
rules/                  regras Sigma (fonte da verdade)
cases/                  casos de teste, no mesmo caminho da regra
dist/                   queries compiladas (gerado, não editar)
.github/workflows/      pipeline de CI
src/vitrix/                o motor, a API e a interface compilada (ui/)
web/                    código-fonte da interface
tests/                  testes do próprio motor
```

## Casos de teste

Para `rules/windows/x.yml` o motor lê `cases/windows/x.yml`:

```yaml
cases:
  - name: Positivo · powershell -enc
    expect: match            # ou no_match
    event:
      Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
      CommandLine: 'powershell.exe -enc JABz'
```

Com `require_cases: true` (padrão) toda regra precisa de ao menos um caso `match` e um `no_match`. Os eventos usam os nomes de campo da própria regra Sigma, antes do mapeamento de cada SIEM.

Cada caso pode dizer o que representa com `kind`:

| `kind` | O que é | `expect` |
|---|---|---|
| `positive` | o comportamento malicioso (padrão para `match`) | `match` |
| `negative` | evento comum (padrão para `no_match`) | `no_match` |
| `false_positive` | atividade legítima parecida com o ataque: admin, conta de serviço, ferramenta de TI | `no_match` |
| `edge` | caso de borda: campo ausente ou nulo, maiúsculas, valor no limite | qualquer |

Se a regra tem exclusão (`filter_*` ou seleção negada na condição), o motor verifica se algum caso `no_match` **só não disparou por causa da exclusão**, ou seja, se a exceção está testada.

## O fluxo: do rascunho à publicação

**Escrever → Validar → Testar → Replay → Analisar → Quality gate → Deploy**

| Etapa | O que verifica |
|---|---|
| Validar | YAML, schema e tipos, modificadores, regex inválida ou com backtracking catastrófico, complexidade, tags ATT&CK, lógica duplicada entre regras, conversão para a linguagem final |
| Testar | casos positivos, negativos e de borda; qualidade dos casos (evento repetido, evento sem nenhum campo da regra) |
| Replay | logs de `datasets/` contra todas as regras, com tempo por regra e contagens esperadas (regressão) |
| Analisar | caso de falso positivo, exclusão testada, técnica ATT&CK, `falsepositives` documentado |
| Quality gate | todas as verificações bloqueantes passam: responde "a regra está pronta para ser publicada?" |
| Deploy | merge do PR; o CI gera o `dist/` (envio direto ao SIEM ainda não existe) |

```bash
vitrix gate                       # o fluxo regra a regra
vitrix check --strict --gate      # o que o CI roda
vitrix replay                     # todos os datasets; ou: vitrix replay simulacao_windows.jsonl
vitrix replay -f eventos.jsonl    # um arquivo avulso
vitrix report -o relatorio.md     # quality gate, testes, cobertura e replay (ou --format json)
```

Critérios do gate no `vitrix.yml` (valores padrão):

```yaml
quality_gate:
  min_positive: 1
  min_negative: 1
  false_positive_levels: [high, critical]   # esses levels exigem um caso kind: false_positive
  require_filter_test: true                 # regra com filter_* precisa de um caso que prove a exclusão
  require_mitre: true
  allow_warnings: true                      # false: qualquer aviso de lint bloqueia
  blocked_status: [deprecated, unsupported]
  require_replay: false                     # true: a regra precisa de expectativa em algum dataset
```

### Replay de logs

Um dataset é um arquivo em `datasets/` (JSON, JSON Lines ou YAML). Ao lado, `<nome>.expect.yml` diz quantos eventos cada regra deve pegar; se uma alteração mudar esse número, o replay e o gate acusam:

```yaml
expect:
  windows/powershell_encoded.yml: 2       # exatamente 2
  windows/schtasks_system.yml: {min: 1}   # ao menos 1
others: 0                                 # nenhuma outra regra deve disparar
```

O repositório de exemplo traz `datasets/simulacao_windows.jsonl`: uma simulação de ataque (PowerShell codificado, persistência por tarefa agendada, dump do LSASS) misturada com atividade legítima.

### Regex Workbench

Na interface, um laboratório para escrever e otimizar regex com o mesmo motor dos testes locais: destaque dos trechos, grupos, tempo por amostra, dicas (quantificador aninhado, `.*` desnecessário, barra de caminho do Windows sem escape, quando `contains` basta) e o trecho pronto para a regra Sigma. Cada execução roda em um processo separado com tempo limite.

## Linguagem final de cada regra

Cada regra sai em uma linguagem de SIEM. O motor decide assim, da mais específica para a mais geral:

1. **Na própria regra**, com `vitrix.target` (um nome ou uma lista):

   ```yaml
   title: Regra de exemplo
   # ...
   vitrix:
     target: kql
   ```

2. **Por rota** no `vitrix.yml`: a primeira cujo `match` casa com o caminho dentro de `rules/` (`*` também atravessa pastas).

   ```yaml
   routes:
     - match: "azure/*"
       target: kql
   ```

3. **`default_target`** do `vitrix.yml`.
4. Sem nenhum dos três, a regra é convertida para todos os `targets` ativos.

`vitrix convert -t NOME` ignora tudo isso e força um alvo para todas as regras. O `dist/manifest.json` registra, por regra, os alvos e de onde veio a escolha (`target_source`). Trocar a linguagem de uma regra apaga a saída antiga no próximo `convert`.

O lint acusa alvo desconhecido e bloco `vitrix` mal formado. Uma regra com a conversão da linguagem final falhando aparece como reprovada; a pré-visualização em outros SIEMs no Editor não reprova nada.

## Alvos embutidos

`splunk` (SPL), `kql` (Defender/Sentinel), `elastic-eql`, `elastic-lucene`. Para o mapeamento de campos do seu ambiente, aponte pipelines do pySigma em `extra_pipelines` no `vitrix.yml`; eles rodam antes do mapeamento padrão do SIEM.

### Plugins

Para adicionar um SIEM sem mexer no motor, publique um pacote com um entry point:

```toml
[project.entry-points."vitrix.targets"]
meu-siem = "meu_pacote.alvo:target"
```

`target` é um `vitrix.backends.Target` (nome, rótulo, extensão e uma fábrica que devolve um backend do pySigma).

## API

`vitrix serve` abre uma API HTTP em `127.0.0.1:8000` (documentação interativa em `/docs`). Ela reaproveita o mesmo motor da CLI, então os números da interface são os do `vitrix check`.

| Rota | O que devolve |
|---|---|
| `GET /api/stats` | Números dos dashboards: regras por status, severidade, tática MITRE e linguagem final, cobertura, lint, testes e falhas de conversão. |
| `GET /api/rules` | Cada regra com estado (`ok`, `warn`, `fail`), táticas, técnicas, contagem de testes e linguagem final (`targets`, `target_source`, `conversion`). |
| `GET /api/rules/{id}` | A regra, o lint, a query por SIEM e os resultados dos testes. O `id` é o caminho dentro de `rules/` (ex.: `windows/powershell_encoded.yml`); `sigma_id` é o UUID. |
| `POST /api/validate` | Valida uma regra ainda não salva: `{"rule": "<yaml>", "cases": "<yaml opcional>", "targets": [...]}`. |
| `GET /api/github` | Repositório e branch configurados e se há token no ambiente (o token nunca sai do servidor). |
| `POST /api/pull-requests` | Abre um PR: `{"path": "windows/x.yml", "rule": "<yaml>", "cases": "<yaml opcional>", "title": "opcional"}`. `path` é o caminho dentro de `rules/`. |
| `GET /api/github/activity` | PRs abertos, execuções do CI e tempo até o merge (conector de leitura, cache de 60 s). |
| `GET /api/quality[/{id}]` | O fluxo e o quality gate, regra a regra. `POST /api/validate` também devolve o gate da regra em edição. |
| `GET /api/tests`, `/api/coverage` | Test suites por tipo de caso; matriz ATT&CK. |
| `GET /api/datasets`, `/api/datasets/{nome}/replay`, `POST /api/replay` | Replay de datasets ou de eventos colados. |
| `POST /api/regex` | Regex Workbench. |
| `GET /api/report?format=md\|json` | Relatório consolidado. |
| `GET /api/config`, `POST /api/config/validate`, `POST /api/config/pull-requests` | Lê, valida e propõe (por PR) mudanças no `vitrix.yml`. |
| `GET /api/config`, `/api/targets`, `/api/health` | Configuração ativa, alvos e saúde. |

Limites da API:
- **Nada é gravado em disco local.** A única escrita é o pull request no GitHub, com o token do ambiente. Essa rota só aceita JSON vindo do próprio localhost: confere os cabeçalhos `Host` e `Origin` contra CSRF e DNS rebinding (`VITRIX_ALLOWED_HOSTS` libera outros hosts).
- **Sem autenticação.** Por isso escuta só em localhost; `vitrix serve --host` com outro endereço imprime um aviso. Não exponha na rede sem um proxy com autenticação na frente.
- **Só dados do repositório.** Execuções do pipeline, tempo até o merge e PRs abertos vêm do CI e do Git, e precisam de um conector (ainda não existe). Por isso `/api/stats` não traz esses números.
- CORS desligado. Para uma interface em outra origem, defina `VITRIX_CORS_ORIGINS=http://localhost:5173`.

## Limites desta versão

- **Validação sintática por alvo:** a conversão pelo pySigma é a validação. O motor ainda não confere a query com o parser de cada SIEM.
- **Avaliador local:** cobre um subconjunto do Sigma (veja o cabeçalho de `src/vitrix/evaluator.py`). Modificadores como `windash`, `base64`, `cidr` e condições de agregação **falham de forma explícita**, não passam em silêncio. O lint avisa quando uma regra está fora desse subconjunto.
- **Deploy:** ainda não há adaptadores para enviar as regras a um SIEM. O resultado é o `dist/` versionado.

## Desenvolvimento

```bash
pip install -e ".[dev]"
pytest
```
