# Apache2 Log Analyzer

Ferramenta em Python 3 para analisar logs de acesso do Apache2, gerar
estatísticas e gráficos e identificar indicadores heurísticos de
requisições potencialmente suspeitas.

> **Aviso:** este projeto é uma ferramenta auxiliar de análise. Os
> indicadores encontrados não comprovam, isoladamente, uma invasão ou
> exploração bem-sucedida. Revise os eventos e correlacione-os com
> outras fontes antes de tomar medidas, como bloquear endereços IP.

## Funcionalidades

O projeto contempla dois níveis de análise:

### 1. Análise geral (`log.py`)

O analisador geral foi desenvolvido para resumir o tráfego HTTP
registrado no arquivo de acesso do Apache. Conforme a versão do script,
pode gerar:

-   Contagem de requisições e distribuição de códigos HTTP;
-   Ranking de endereços IP;
-   URLs e métodos HTTP mais requisitados;
-   Distribuição de requisições por horário;
-   Relatórios e gráficos para facilitar a interpretação dos registros.

### 2. Análise de segurança (`security_analyzer.py`)

O analisador de segurança examina os registros dos últimos sete dias e
procura indicadores como:

-   Tentativas de acesso a arquivos e caminhos sensíveis, por exemplo
    `.env`, `.git` e arquivos de backup;
-   Padrões em URLs associados a possíveis tentativas de SQL Injection,
    XSS, Path Traversal e Command Injection;
-   User-Agents que mencionam ferramentas de varredura conhecidas;
-   Volume elevado de requisições por endereço IP em um intervalo de um
    minuto;
-   Proporção elevada de respostas HTTP 4xx e 5xx por IP.

A ferramenta calcula uma pontuação heurística por IP e classifica os
resultados como `BAIXO`, `MODERADO`, `ALTO` ou `CRITICO`. Essa pontuação
é um mecanismo de triagem, não uma probabilidade de ataque.

## Tecnologias utilizadas

-   Python 3
-   Pandas
-   Matplotlib
-   Biblioteca padrão do Python: `argparse`, `re`, `gzip`, `datetime`,
    `pathlib`, `collections` e `urllib`

## Requisitos

-   Linux com Apache2 ou acesso a arquivos de log Apache compatíveis;
-   Python 3;
-   Permissão de leitura dos arquivos de log;
-   Ambiente virtual Python recomendado.

Instale o Apache2 (se necessário):

``` bash
sudo apt update
sudo apt install apache2 python3 python3-venv python3-pip
```

## Instalação

Clone o repositório:

``` bash
git clone https://github.com/SEU-USUARIO/SEU-REPOSITORIO.git
cd SEU-REPOSITORIO
```

Crie e ative um ambiente virtual:

``` bash
python3 -m venv bin
source bin/activate
```

Instale as dependências:

``` bash
python -m pip install --upgrade pip
python -m pip install pandas matplotlib
```

Opcionalmente, crie um `requirements.txt`:

``` bash
python -m pip freeze > requirements.txt
```

Em uma instalação limpa, as dependências podem ser instaladas com:

``` bash
python -m pip install -r requirements.txt
```

## Permissão de leitura dos logs

Em Debian e Ubuntu, os logs do Apache normalmente ficam em
`/var/log/apache2/`. Em muitas instalações, o grupo `adm` possui
permissão de leitura.

Adicione seu usuário ao grupo, se isso estiver de acordo com a política
de acesso do servidor:

``` bash
sudo usermod -aG adm "$USER"
```

Encerre e abra novamente a sessão para atualizar os grupos. Depois
confirme:

``` bash
groups
ls -l /var/log/apache2/access.log
```

Teste a leitura:

``` bash
head /var/log/apache2/access.log
```

Não é recomendado executar o analisador com `sudo` apenas para contornar
permissões. Isso pode fazer o comando usar o Python global, em vez do
interpretador do ambiente virtual. Se o acesso ao log for concedido ao
usuário, execute os scripts sem `sudo`.

## Utilização

### Análise geral

Se o script `log.py` estiver configurado para receber os argumentos `-f`
e `-o`:

``` bash
python log.py -f /var/log/apache2/access.log -o resultados
```

Consulte as opções disponíveis na versão instalada:

``` bash
python log.py --help
```

### Análise de segurança dos últimos sete dias

Salve o analisador de segurança como `security_analyzer.py` e execute:

``` bash
python security_analyzer.py \
  -f /var/log/apache2/access.log \
  -o resultados_seguranca
```

Consulte as opções:

``` bash
python security_analyzer.py --help
```

O analisador de segurança procura o arquivo informado e arquivos de
rotação no mesmo diretório, como `access.log.1` e `access.log.2.gz`. Ele
lê os registros disponíveis e filtra aqueles cujo timestamp esteja
dentro da janela móvel dos últimos sete dias, usando UTC.

> O nome do script pode ser diferente no seu repositório. Se você salvou
> o código como `log1.py`, substitua `security_analyzer.py` por
> `log1.py` nos comandos acima. O script apresentado requer o argumento
> `-f`.

## Resultados da análise de segurança

A execução do analisador de segurança cria o diretório
`resultados_seguranca/` com arquivos semelhantes a estes:

  -----------------------------------------------------------------------
  Arquivo                             Conteúdo
  ----------------------------------- -----------------------------------
  `relatorio_seguranca.txt`           Resumo textual, indicadores e
                                      ranking de IPs

  `requisicoes_suspeitas.csv`         Requisições que corresponderam a
                                      pelo menos uma regra

  `analise_ips.csv`                   Métricas e pontuação heurística por
                                      IP

  `picos_requisicoes.csv`             Intervalos por IP que atingiram o
                                      limite de volume

  `logs_ultimos_7_dias.csv`           Registros válidos dentro da janela
                                      analisada

  `01_suspeitas_tempo.png`            Requisições suspeitas por hora

  `02_ips_risco.png`                  Ranking de IPs por pontuação

  `03_indicadores.png`                Quantidade por categoria de
                                      indicador

  `04_suspeitas_dia.png`              Requisições suspeitas por dia

  `05_status_suspeitas.png`           Códigos HTTP das requisições
                                      suspeitas

  `06_volume_ips.png`                 Maior volume por minuto entre os
                                      IPs
  -----------------------------------------------------------------------

Os nomes e arquivos gerados dependem da versão do script utilizada.

## Como interpretar os resultados

-   **Requisição suspeita:** registro que correspondeu a uma regra de
    detecção. Pode ser uma varredura, um teste autorizado ou uma
    requisição legítima que coincidiu com o padrão.
-   **HTTP 200:** o servidor respondeu com sucesso à requisição. Isso
    não significa que uma tentativa de exploração foi bem-sucedida.
-   **HTTP 403:** o servidor negou o acesso.
-   **HTTP 404:** o recurso solicitado não foi encontrado. Muitos 404
    podem ocorrer por varreduras, links quebrados ou URLs inexistentes.
-   **Pontuação de risco:** soma de indicadores configurados no script.
    Deve ser usada para priorizar revisão manual, não como veredito.
-   **Pico de requisições:** maior quantidade observada para um IP em um
    intervalo de um minuto, conforme a regra implementada.

Comece revisando `relatorio_seguranca.txt`, depois investigue os IPs no
arquivo `analise_ips.csv` e confira as linhas correspondentes em
`requisicoes_suspeitas.csv`.

## Formato dos logs

O analisador de segurança foi escrito para o formato de log Apache
Common/Combined, com campos de data, requisição, status e bytes, e
campos opcionais de Referer e User-Agent.

O formato Combined padrão pode ser configurado no Apache, por exemplo:

``` apache
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" combined
CustomLog ${APACHE_LOG_DIR}/access.log combined
```

Se o servidor utilizar um `LogFormat` personalizado, valide se os campos
correspondem ao padrão esperado pelo parser antes de confiar nos
resultados.

## Limitações e considerações de segurança

-   A detecção é baseada em padrões e limites fixos; pode gerar falsos
    positivos e falsos negativos.
-   A análise de URL e User-Agent não inspeciona o corpo de requisições
    POST.
-   O User-Agent é fornecido pelo cliente e pode ser falsificado.
-   Um endereço IP pode representar NAT, proxy, CDN ou vários usuários.
-   A pontuação não representa probabilidade de comprometimento.
-   O analisador não bloqueia IPs, não altera regras do firewall e não
    corrige vulnerabilidades.
-   A janela de sete dias depende de os arquivos de log necessários
    ainda existirem e estarem legíveis.
-   A análise converte os timestamps para UTC; considere o fuso ao
    comparar os resultados com outros sistemas.
-   O parser deve ser validado para o formato real de log e para
    eventuais particularidades de proxy reverso.

Antes de bloquear um IP ou classificar um evento como incidente,
correlacione horário, endpoint, método, status, User-Agent, logs de erro
do Apache, logs da aplicação e, quando aplicável, registros do firewall
ou WAF.

## Boas práticas

1.  Preserve os logs originais e restrinja o acesso a eles.
2.  Não publique logs reais, endereços IP de clientes, tokens, cookies,
    URLs privadas ou dados pessoais no GitHub.
3.  Utilize dados anonimizados ou sintéticos em exemplos e testes.
4.  Mantenha as dependências em um ambiente virtual.
5.  Teste regras em modo de observação antes de automatizar bloqueios.
6.  Ajuste os limites de detecção ao tráfego legítimo da sua aplicação.
7.  Faça backup dos logs e defina uma política de retenção.

## Publicação no GitHub

Antes de enviar o projeto, confira se arquivos de logs e relatórios
reais não serão publicados. Uma sugestão de `.gitignore`:

``` gitignore
bin/
venv/
__pycache__/
*.py[cod]
.env
resultados/
resultados_seguranca/
*.log
*.log.*
```

Revise a lista de arquivos:

``` bash
git status
```

Adicione e envie os arquivos do projeto:

``` bash
git add README.md .gitignore *.py requirements.txt
git commit -m "Adiciona analisador de logs Apache2"
git push origin main
```

Ajuste os nomes dos arquivos e a branch conforme a estrutura do seu
repositório.

## Licença

Defina uma licença antes de distribuir o projeto. Se ainda não houver
uma, não presuma que terceiros têm autorização para reutilizar,
modificar ou redistribuir o código.

------------------------------------------------------------------------

**Projeto:** Apache2 Log Analyzer\
**Linguagem:** Python 3\
**Finalidade:** análise de tráfego HTTP e triagem de indicadores de
segurança em logs Apache2.
