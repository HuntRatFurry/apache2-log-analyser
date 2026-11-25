
#!/usr/bin/env python3

import re
import gzip
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from urllib.parse import unquote, urlsplit
from collections import Counter

import pandas as pd
import matplotlib.pyplot as plt


# ==================================================
# CONFIGURACOES
# ==================================================

WINDOW_DAYS = 7

# Limite inicial para sinalizar volume elevado
REQUESTS_PER_MINUTE_LIMIT = 60

# Quantidade minima para avaliar proporcao de erros
MIN_REQUESTS_FOR_ERROR_RATE = 20

COMMON_METHODS = {
    "GET", "POST", "HEAD", "OPTIONS",
    "PUT", "PATCH", "DELETE"
}

# Formato Apache Combined / Common
LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) '
    r'(?P<bytes>\S+)'
    r'(?: "(?P<referrer>[^"]*)" '
    r'"(?P<ua>[^"]*)")?'
)

# Caminhos frequentemente procurados por scanners
SENSITIVE_PATTERNS = [
    r'(^|/)\.env(?:[./]|$)',
    r'(^|/)\.git(?:/|$)',
    r'(^|/)\.svn(?:/|$)',
    r'wp-admin',
    r'wp-login\.php',
    r'phpmyadmin',
    r'adminer',
    r'config\.php',
    r'backup(?:\.zip|\.tar|\.sql)?',
    r'database\.sql',
    r'app_dev\.php',
    r'phpinfo\.php',
    r'\.bak(?:$|[/?])',
    r'\.old(?:$|[/?])',
]

# Indicadores de tentativas de exploracao
EXPLOIT_PATTERNS = {
    "SQL Injection": [
        r'union.{0,20}select',
        r'(\bor\b|\band\b).{0,15}[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+',
        r'information_schema',
        r'sleep\s*\(',
        r'benchmark\s*\(',
        r'waitfor\s+delay',
    ],

    "XSS": [
        r'<script',
        r'javascript:',
        r'onerror\s*=',
        r'onload\s*=',
    ],

    "Path Traversal": [
        r'\.\./',
        r'\.\.\\',
        r'%2e%2e',
    ],

    "Command Injection": [
        r';\s*(cat|wget|curl|id|whoami|uname)\b',
        r'\|\s*(cat|wget|curl|sh|bash)\b',
        r'/bin/(sh|bash)',
    ],
}

SCANNER_AGENTS = re.compile(
    r'nmap|sqlmap|nikto|masscan|zgrab|'
    r'gobuster|dirbuster|ffuf|wpscan|acunetix|'
    r'nuclei|nessus|openvas|whatweb',
    re.IGNORECASE
)

SENSITIVE_REGEX = [
    re.compile(p, re.IGNORECASE)
    for p in SENSITIVE_PATTERNS
]

EXPLOIT_REGEX = {
    category: [
        re.compile(p, re.IGNORECASE)
        for p in patterns
    ]
    for category, patterns in EXPLOIT_PATTERNS.items()
}


# ==================================================
# LEITURA DOS LOGS
# ==================================================

def discover_logs(log_file):

    log_file = Path(log_file)

    if not log_file.is_file():
        raise FileNotFoundError(
            f"Arquivo nao encontrado: {log_file}"
        )

    # Inclui access.log e suas rotacoes
    files = sorted(
        log_file.parent.glob(log_file.name + "*")
    )

    files = [
        f for f in files
        if f.is_file() and
        (f.name == log_file.name or
         f.name.startswith(log_file.name + "."))
        and (
            f.name.endswith(".gz")
            or re.search(r'\.\d+$', f.name)
            or f.name == log_file.name
        )
    ]

    if not files:
        raise FileNotFoundError("Nenhum log encontrado.")

    return files


def read_log_file(file_path):

    if str(file_path).endswith(".gz"):
        return gzip.open(
            file_path,
            "rt",
            encoding="utf-8",
            errors="replace"
        )

    return open(
        file_path,
        "r",
        encoding="utf-8",
        errors="replace"
    )


# ==================================================
# IDENTIFICACAO DE INDICADORES
# ==================================================

def inspect_request(target, user_agent):

    decoded = unquote(target).lower()

    findings = []

    for pattern in SENSITIVE_REGEX:
        if pattern.search(decoded):
            findings.append("Arquivo/caminho sensivel")

    for category, patterns in EXPLOIT_REGEX.items():
        for pattern in patterns:
            if pattern.search(decoded):
                findings.append(category)
                break

    if SCANNER_AGENTS.search(user_agent or ""):
        findings.append("User-Agent de scanner")

    return sorted(set(findings))


# ==================================================
# PROCESSAMENTO DOS LOGS
# ==================================================

def parse_logs(files):

    records = []
    invalid = 0

    for file_path in files:

        print(f"Lendo: {file_path}")

        with read_log_file(file_path) as file:

            for line in file:

                match = LOG_PATTERN.match(line.strip())

                if not match:
                    invalid += 1
                    continue

                data = match.groupdict()

                try:

                    timestamp = datetime.strptime(
                        data["time"],
                        "%d/%b/%Y:%H:%M:%S %z"
                    )

                    request_parts = data["request"].split()

                    if len(request_parts) < 2:
                        invalid += 1
                        continue

                    method = request_parts[0].upper()
                    target = request_parts[1]

                    path = urlsplit(target).path

                    status = int(data["status"])

                    size = (
                        int(data["bytes"])
                        if data["bytes"].isdigit()
                        else 0
                    )

                    ua = data["ua"] or "-"
                    referrer = data["referrer"] or "-"

                    findings = inspect_request(
                        target,
                        ua
                    )

                    records.append({
                        "ip": data["ip"],
                        "timestamp": pd.Timestamp(timestamp),
                        "method": method,
                        "path": path,
                        "target": target,
                        "status": status,
                        "bytes": size,
                        "user_agent": ua,
                        "referrer": referrer,
                        "findings": findings,
                        "suspicious": bool(findings)
                    })

                except (ValueError, TypeError, IndexError):
                    invalid += 1

    if not records:
        raise ValueError(
            "Nenhuma requisicao valida foi encontrada. "
            "Verifique o formato dos logs."
        )

    df = pd.DataFrame(records)

    # Padroniza os horarios em UTC
    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        utc=True
    )

    print(f"\nLinhas validas: {len(df)}")
    print(f"Linhas ignoradas: {invalid}")

    return df


# ==================================================
# FILTRO DOS ULTIMOS 7 DIAS
# ==================================================

def filter_last_seven_days(df):

    now = pd.Timestamp.now(tz="UTC")

    start = now - pd.Timedelta(days=WINDOW_DAYS)

    filtered = df[
        (df["timestamp"] >= start) &
        (df["timestamp"] <= now)
    ].copy()

    print("\n========== PERIODO ANALISADO ==========")
    print(f"Inicio UTC: {start}")
    print(f"Fim UTC:    {now}")
    print(f"Requisicoes: {len(filtered)}")

    if filtered.empty:
        raise ValueError(
            "Nao existem requisicoes nos ultimos 7 dias."
        )

    return filtered


# ==================================================
# ANALISE DE IPs
# ==================================================

def analyze_ips(df):

    # Requisicoes por IP e minuto
    per_minute = (
        df.groupby([
            "ip",
            pd.Grouper(key="timestamp", freq="min")
        ])
        .size()
        .reset_index(name="requests")
    )

    peak = (
        per_minute.groupby("ip")["requests"]
        .max()
        .rename("max_requests_per_minute")
    )

    stats = df.groupby("ip").agg(
        total_requests=("ip", "size"),
        unique_endpoints=("path", "nunique"),
        errors_4xx=(
            "status",
            lambda x: ((x >= 400) & (x < 500)).sum()
        ),
        errors_5xx=(
            "status",
            lambda x: ((x >= 500) & (x < 600)).sum()
        ),
        sensitive_hits=(
            "findings",
            lambda x: sum(
                "Arquivo/caminho sensivel" in item
                for item in x
            )
        ),
        exploit_hits=(
            "findings",
            lambda x: sum(
                any(
                    finding in [
                        "SQL Injection",
                        "XSS",
                        "Path Traversal",
                        "Command Injection"
                    ]
                    for finding in item
                )
                for item in x
            )
        ),
        scanner_hits=(
            "findings",
            lambda x: sum(
                "User-Agent de scanner" in item
                for item in x
            )
        )
    )

    stats = stats.join(peak)

    stats["error_rate"] = (
        (stats["errors_4xx"] + stats["errors_5xx"])
        / stats["total_requests"] * 100
    )

    # Pontuacao heuristica de risco
    def calculate_risk(row):

        score = 0
        reasons = []

        if row["sensitive_hits"] > 0:
            score += 30
            reasons.append("Busca por arquivo sensivel")

        if row["exploit_hits"] > 0:
            score += 35
            reasons.append("Padrao de exploracao")

        if row["scanner_hits"] > 0:
            score += 15
            reasons.append("User-Agent de scanner")

        if row["max_requests_per_minute"] >= REQUESTS_PER_MINUTE_LIMIT:
            score += 20
            reasons.append("Volume elevado por minuto")

        if (
            row["total_requests"] >= MIN_REQUESTS_FOR_ERROR_RATE
            and row["error_rate"] >= 70
        ):
            score += 15
            reasons.append("Alta proporcao de erros")

        return min(score, 100), reasons

    results = stats.apply(
        calculate_risk,
        axis=1
    )

    stats["risk_score"] = results.apply(lambda x: x[0])
    stats["risk_reasons"] = results.apply(
        lambda x: ", ".join(x[1])
    )

    stats["classification"] = stats["risk_score"].apply(
        lambda x:
            "CRITICO" if x >= 80 else
            "ALTO" if x >= 60 else
            "MODERADO" if x >= 30 else
            "BAIXO"
    )

    return stats.sort_values(
        ["risk_score", "total_requests"],
        ascending=False
    )


# ==================================================
# DETECCAO DE VOLUME ELEVADO
# ==================================================

def detect_high_volume(df):

    per_minute = (
        df.groupby([
            "ip",
            pd.Grouper(key="timestamp", freq="min")
        ])
        .size()
        .reset_index(name="requests")
    )

    return per_minute[
        per_minute["requests"] >=
        REQUESTS_PER_MINUTE_LIMIT
    ].sort_values(
        "requests",
        ascending=False
    )


# ==================================================
# RELATORIO ESTATISTICO
# ==================================================

def generate_summary(df, stats, output_dir):

    total = len(df)
    suspicious = int(df["suspicious"].sum())

    errors = int(
        ((df["status"] >= 400) &
         (df["status"] < 500)).sum()
    )

    server_errors = int(
        ((df["status"] >= 500) &
         (df["status"] < 600)).sum()
    )

    risk_high = int(
        stats["classification"].isin(
            ["ALTO", "CRITICO"]
        ).sum()
    )

    print("\n========== ANALISE DE SEGURANCA ==========")

    print(f"Total de requisicoes: {total}")
    print(f"Requisicoes suspeitas: {suspicious}")
    print(f"IPs analisados: {len(stats)}")
    print(f"IPs de risco alto/critico: {risk_high}")
    print(f"Respostas 4xx: {errors}")
    print(f"Respostas 5xx: {server_errors}")

    print("\n========== TOP 10 IPs POR RISCO ==========")

    print(
        stats[
            [
                "total_requests",
                "risk_score",
                "classification",
                "risk_reasons"
            ]
        ].head(10).to_string()
    )

    print("\n========== INDICADORES SUSPEITOS ==========")

    findings = Counter()

    for items in df["findings"]:
        findings.update(items)

    if findings:
        for name, quantity in findings.most_common():
            print(f"{name}: {quantity}")
    else:
        print("Nenhum padrao suspeito identificado.")

    summary = [
        "APACHE SECURITY ANALYZER",
        "PERIODO: ULTIMOS 7 DIAS",
        "=" * 45,
        f"Total de requisicoes: {total}",
        f"Requisicoes suspeitas: {suspicious}",
        f"IPs analisados: {len(stats)}",
        f"IPs de risco alto/critico: {risk_high}",
        f"Respostas 4xx: {errors}",
        f"Respostas 5xx: {server_errors}",
        "",
        "INDICADORES:",
    ]

    for name, quantity in findings.most_common():
        summary.append(f"{name}: {quantity}")

    summary += [
        "",
        "TOP IPS:",
        stats.head(20).to_string()
    ]

    with open(
        output_dir / "relatorio_seguranca.txt",
        "w",
        encoding="utf-8"
    ) as file:

        file.write("\n".join(summary))


# ==================================================
# GRAFICOS
# ==================================================

def generate_graphs(df, stats, output_dir):

    plt.rcParams["figure.figsize"] = (12, 6)

    suspicious = df[df["suspicious"]].copy()

    # 1. Requisicoes suspeitas ao longo do tempo

    timeline = (
        suspicious.set_index("timestamp")
        .resample("h")
        .size()
    )

    plt.figure()
    timeline.plot(marker="o")

    plt.title("Requisicoes suspeitas por hora")
    plt.xlabel("Data e horario UTC")
    plt.ylabel("Quantidade")
    plt.grid(True)
    plt.tight_layout()

    plt.savefig(output_dir / "01_suspeitas_tempo.png")
    plt.close()

    # 2. IPs com maior pontuacao de risco

    top = stats.head(15).sort_values("risk_score")

    plt.figure()
    top["risk_score"].plot(kind="barh")

    plt.title("Top 15 IPs por pontuacao de risco")
    plt.xlabel("Pontuacao de risco")
    plt.ylabel("Endereco IP")
    plt.tight_layout()

    plt.savefig(output_dir / "02_ips_risco.png")
    plt.close()

    # 3. Indicadores de ataques identificados

    findings = Counter()

    for items in df["findings"]:
        findings.update(items)

    plt.figure()

    if findings:
        pd.Series(findings).sort_values().plot(
            kind="barh"
        )
    else:
        plt.text(
            0.5, 0.5,
            "Nenhum indicador identificado",
            ha="center",
            va="center"
        )

    plt.title("Indicadores suspeitos identificados")
    plt.xlabel("Quantidade")
    plt.tight_layout()

    plt.savefig(output_dir / "03_indicadores.png")
    plt.close()

    # 4. Requisicoes suspeitas por dia

    daily = (
        suspicious.set_index("timestamp")
        .resample("D")
        .size()
    )

    plt.figure()
    daily.plot(kind="bar")

    plt.title("Requisicoes suspeitas por dia")
    plt.xlabel("Data UTC")
    plt.ylabel("Quantidade")
    plt.tight_layout()

    plt.savefig(output_dir / "04_suspeitas_dia.png")
    plt.close()

    # 5. Distribuicao de status das suspeitas

    plt.figure()

    if not suspicious.empty:
        suspicious["status"].value_counts().sort_index().plot(
            kind="bar"
        )
    else:
        plt.text(
            0.5, 0.5,
            "Nenhuma requisicao suspeita",
            ha="center",
            va="center"
        )

    plt.title("Status HTTP das requisicoes suspeitas")
    plt.xlabel("Status HTTP")
    plt.ylabel("Quantidade")
    plt.tight_layout()

    plt.savefig(output_dir / "05_status_suspeitas.png")
    plt.close()

    # 6. Volume maximo por minuto dos principais IPs

    top_volume = (
        stats.sort_values(
            "max_requests_per_minute",
            ascending=False
        ).head(15).sort_values(
            "max_requests_per_minute"
        )
    )

    plt.figure()
    top_volume["max_requests_per_minute"].plot(
        kind="barh"
    )

    plt.title("Pico de requisicoes por minuto - Top IPs")
    plt.xlabel("Requisicoes/minuto")
    plt.ylabel("Endereco IP")
    plt.tight_layout()

    plt.savefig(output_dir / "06_volume_ips.png")
    plt.close()

    print("\nGraficos gerados com sucesso!")


# ==================================================
# EXPORTACAO
# ==================================================

def export_data(df, stats, high_volume, output_dir):

    suspicious = df[df["suspicious"]].copy()

    suspicious["findings"] = suspicious[
        "findings"
    ].apply(lambda x: ", ".join(x))

    suspicious.to_csv(
        output_dir / "requisicoes_suspeitas.csv",
        index=False
    )

    stats.to_csv(
        output_dir / "analise_ips.csv"
    )

    high_volume.to_csv(
        output_dir / "picos_requisicoes.csv",
        index=False
    )

    df.to_csv(
        output_dir / "logs_ultimos_7_dias.csv",
        index=False
    )


# ==================================================
# EXECUCAO PRINCIPAL
# ==================================================

def main():

    parser = argparse.ArgumentParser(
        description="Apache Security Analyzer - 7 dias"
    )

    parser.add_argument(
        "-f",
        "--file",
        required=True,
        help="Caminho do access.log"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="resultados_seguranca",
        help="Diretorio de resultados"
    )

    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    print("\nAPACHE SECURITY ANALYZER")
    print("=" * 45)

    try:

        files = discover_logs(args.file)

        print(f"\nArquivos encontrados: {len(files)}")

        df = parse_logs(files)

        df = filter_last_seven_days(df)

        stats = analyze_ips(df)

        high_volume = detect_high_volume(df)

        generate_summary(
            df,
            stats,
            output_dir
        )

        generate_graphs(
            df,
            stats,
            output_dir
        )

        export_data(
            df,
            stats,
            high_volume,
            output_dir
        )

        print("\n" + "=" * 45)
        print("ANALISE FINALIZADA")
        print(f"Resultados: {output_dir.resolve()}")
        print("=" * 45)

    except (FileNotFoundError, ValueError, OSError) as error:

        print(f"\nERRO: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
