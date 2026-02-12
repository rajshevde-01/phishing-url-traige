import argparse
import csv
import json
import math
import os
import re
import socket
import sys
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from uuid import uuid4
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

VERSION = "2.0.0"

SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "account",
    "update",
    "secure",
    "bank",
    "password",
    "confirm",
    "billing",
    "pay",
    "payment",
    "webscr",
    "alert",
    "security",
    "support",
    "icloud",
    "microsoft",
    "google",
    "paypal",
}

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "click",
    "link",
    "top",
    "xyz",
    "gq",
    "tk",
    "ml",
    "cf",
    "ru",
    "cn",
}

FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "protonmail.com",
    "proton.me",
    "icloud.com",
}

IP_IN_URL_RE = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}(/|$)")
IP_ONLY_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

MITRE_MAPPING = {
    "phishing_link": "T1566.002 Spearphishing Link",
    "newly_registered": "T1583.001 Acquire Infrastructure: Domains",
    "ti_urlhaus": "T1566.002 Spearphishing Link",
}

CATEGORY_KEYWORDS = {
    "credential_phish": {
        "login",
        "password",
        "verify",
        "account",
        "reset",
        "confirm",
        "security",
        "update",
    },
    "banking": {
        "bank",
        "payment",
        "pay",
        "billing",
        "invoice",
        "card",
        "wallet",
    },
    "cloud": {
        "icloud",
        "microsoft",
        "office",
        "onedrive",
        "google",
        "gmail",
        "drive",
        "dropbox",
    },
}


@dataclass
class Signal:
    name: str
    score: int
    detail: str


@dataclass
class TriageResult:
    url: str
    score: int
    risk: str
    signals: List[Signal]
    labels: List[str] = field(default_factory=list)
    sender: str = ""
    subject: str = ""
    ti_source: str = ""
    ti_status: str = ""
    ti_tags: str = ""
    ti_reference: str = ""
    rdap_status: str = ""
    rdap_age_days: int = 0
    dns_resolves: str = ""


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def extract_domain_parts(netloc: str) -> Tuple[str, str]:
    if not netloc:
        return "", ""
    parts = netloc.split(".")
    if len(parts) < 2:
        return netloc, ""
    return ".".join(parts[:-1]), parts[-1]


def get_hostname(url: str) -> str:
    parsed = urlparse(url)
    if parsed.hostname:
        return parsed.hostname.lower()
    parsed = urlparse(f"http://{url}")
    return (parsed.hostname or "").lower()


def is_ip_hostname(hostname: str) -> bool:
    return bool(IP_ONLY_RE.match(hostname))


def extract_sender_domain(sender: str) -> str:
    if not sender:
        return ""
    sender = sender.strip()
    if "@" not in sender:
        return ""
    return sender.split("@")[-1].lower()


def lookup_urlhaus(url: str, timeout: int) -> Dict[str, str]:
    payload = urlencode({"url": url}).encode("utf-8")
    request = Request("https://urlhaus-api.abuse.ch/v1/url/", data=payload)
    request.add_header("User-Agent", "phishing-url-triage/1.0")
    with urlopen(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8")
    data = json.loads(raw)
    return {
        "status": data.get("query_status", ""),
        "threat": data.get("threat", ""),
        "tags": ", ".join(data.get("tags", []) or []),
        "reference": data.get("urlhaus_reference", ""),
    }


def lookup_rdap(hostname: str, timeout: int) -> Dict[str, str]:
    request = Request(f"https://rdap.org/domain/{hostname}")
    request.add_header("User-Agent", "phishing-url-triage/1.0")
    with urlopen(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8")
    data = json.loads(raw)
    events = data.get("events", []) or []
    registration = ""
    for event in events:
        if event.get("eventAction") in {"registration", "registered"}:
            registration = event.get("eventDate", "")
            break
    return {"registration": registration}


def resolve_dns(hostname: str) -> bool:
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.gaierror:
        return False


def parse_rdap_age_days(registration: str) -> int:
    if not registration:
        return 0
    try:
        dt = datetime.fromisoformat(registration.replace("Z", "+00:00"))
    except ValueError:
        return 0
    delta = datetime.now(timezone.utc) - dt
    return max(0, delta.days)


def detect_labels(text: str) -> List[str]:
    labels = []
    for label, keywords in CATEGORY_KEYWORDS.items():
        if any(keyword in text for keyword in keywords):
            labels.append(label)
    return labels


def triage_url(
    url: str,
    sender: str = "",
    subject: str = "",
    ti_lookup: Optional[Callable[[str], Dict[str, str]]] = None,
    rdap_lookup: Optional[Callable[[str], Dict[str, str]]] = None,
    dns_lookup: bool = False,
    rdap_age_threshold: int = 30,
) -> TriageResult:
    signals: List[Signal] = []
    score = 0

    parsed = urlparse(url)
    netloc = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    if not netloc:
        parsed_fallback = urlparse(f"http://{url}")
        netloc = (parsed_fallback.hostname or "").lower()
        if not path:
            path = parsed_fallback.path.lower()
    full = f"{netloc}{path}"

    if not parsed.scheme or not netloc:
        signals.append(Signal("invalid_url", 15, "Missing scheme or hostname"))
        score += 15

    if IP_IN_URL_RE.search(url):
        signals.append(Signal("ip_in_url", 25, "IP address used instead of domain"))
        score += 25

    if "xn--" in netloc:
        signals.append(Signal("punycode", 20, "Punycode domain detected"))
        score += 20

    keyword_hits = [k for k in SUSPICIOUS_KEYWORDS if k in full]
    if keyword_hits:
        hit_score = min(25, 5 * len(keyword_hits))
        signals.append(Signal("keywords", hit_score, f"Keywords: {', '.join(sorted(keyword_hits))}"))
        score += hit_score

    domain, tld = extract_domain_parts(netloc)
    if tld in SUSPICIOUS_TLDS:
        signals.append(Signal("suspicious_tld", 15, f"TLD: .{tld}"))
        score += 15

    if len(url) > 75:
        signals.append(Signal("long_url", 10, f"Length: {len(url)}"))
        score += 10

    if domain:
        entropy = shannon_entropy(domain)
        if entropy >= 3.6:
            signals.append(Signal("high_entropy", 10, f"Entropy: {entropy:.2f}"))
            score += 10

    if "@" in url:
        signals.append(Signal("at_symbol", 10, "@ in URL can hide true domain"))
        score += 10

    if parsed.scheme == "http":
        signals.append(Signal("http", 5, "HTTP used instead of HTTPS"))
        score += 5

    if subject:
        lowered = subject.lower()
        subject_hits = [k for k in SUSPICIOUS_KEYWORDS if k in lowered]
        if subject_hits:
            hit_score = min(10, 2 * len(subject_hits))
            signals.append(
                Signal(
                    "subject_keywords",
                    hit_score,
                    f"Subject keywords: {', '.join(sorted(subject_hits))}",
                )
            )
            score += hit_score

    label_text = f"{full} {subject.lower()}"
    labels = detect_labels(label_text)

    sender_domain = extract_sender_domain(sender)
    if sender_domain and sender_domain in FREE_EMAIL_DOMAINS:
        signals.append(
            Signal("free_mail_sender", 5, f"Sender domain: {sender_domain}")
        )
        score += 5

    if sender_domain and netloc and sender_domain not in netloc:
        signals.append(
            Signal("sender_domain_mismatch", 5, f"Sender domain: {sender_domain}")
        )
        score += 5

    ti_source = ""
    ti_status = ""
    ti_tags = ""
    ti_reference = ""
    if ti_lookup:
        try:
            ti_data = ti_lookup(url)
            ti_source = "urlhaus"
            ti_status = ti_data.get("status", "")
            ti_tags = ti_data.get("tags", "")
            ti_reference = ti_data.get("reference", "")
            if ti_status == "ok":
                threat = ti_data.get("threat", "")
                detail = "URLhaus hit"
                if threat:
                    detail += f" ({threat})"
                signals.append(Signal("ti_urlhaus", 30, detail))
                score += 30
        except Exception:
            ti_source = "urlhaus"
            ti_status = "error"

    rdap_status = ""
    rdap_age_days = 0
    if rdap_lookup and netloc and not is_ip_hostname(netloc):
        try:
            rdap_data = rdap_lookup(netloc)
            rdap_status = "ok" if rdap_data.get("registration") else "not_found"
            rdap_age_days = parse_rdap_age_days(rdap_data.get("registration", ""))
            if rdap_age_days and rdap_age_days <= rdap_age_threshold:
                signals.append(
                    Signal(
                        "newly_registered",
                        15,
                        f"Domain age: {rdap_age_days} days",
                    )
                )
                score += 15
        except Exception:
            rdap_status = "error"

    dns_resolves = ""
    if dns_lookup and netloc and not is_ip_hostname(netloc):
        resolves = resolve_dns(netloc)
        dns_resolves = "yes" if resolves else "no"
        if not resolves:
            signals.append(Signal("no_dns", 5, "Domain did not resolve"))
            score += 5

    risk = "low"
    if score >= 40:
        risk = "high"
    elif score >= 20:
        risk = "medium"

    return TriageResult(
        url=url,
        score=score,
        risk=risk,
        signals=signals,
        labels=labels,
        sender=sender,
        subject=subject,
        ti_source=ti_source,
        ti_status=ti_status,
        ti_tags=ti_tags,
        ti_reference=ti_reference,
        rdap_status=rdap_status,
        rdap_age_days=rdap_age_days,
        dns_resolves=dns_resolves,
    )


def write_csv(results: List[TriageResult], output_path: str) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        headers = ["url", "score", "risk", "signals"]
        if any(item.labels for item in results):
            headers.append("labels")
        if any(item.sender for item in results):
            headers.append("sender")
        if any(item.subject for item in results):
            headers.append("subject")
        if any(item.ti_source or item.ti_status for item in results):
            headers.extend(["ti_source", "ti_status", "ti_tags", "ti_reference"])
        if any(item.rdap_status or item.rdap_age_days for item in results):
            headers.extend(["rdap_status", "rdap_age_days"])
        if any(item.dns_resolves for item in results):
            headers.append("dns_resolves")
        writer.writerow(headers)
        for item in results:
            signal_text = "; ".join(f"{s.name}:{s.detail}" for s in item.signals)
            row = [item.url, item.score, item.risk, signal_text]
            if "labels" in headers:
                row.append("|".join(item.labels))
            if "sender" in headers:
                row.append(item.sender)
            if "subject" in headers:
                row.append(item.subject)
            if "ti_source" in headers:
                row.extend([item.ti_source, item.ti_status, item.ti_tags, item.ti_reference])
            if "rdap_status" in headers:
                row.extend([item.rdap_status, item.rdap_age_days])
            if "dns_resolves" in headers:
                row.append(item.dns_resolves)
            writer.writerow(row)


def write_html(results: List[TriageResult], output_path: str) -> None:
    rows = []
    for item in results:
        signal_list = "<br>".join(f"{s.name}: {s.detail}" for s in item.signals) or "none"
        sender = item.sender or ""
        subject = item.subject or ""
        ti_summary = ""
        if item.ti_source or item.ti_status:
            ti_summary = f"{item.ti_source} {item.ti_status} {item.ti_tags}".strip()
        rdap_summary = ""
        if item.rdap_status or item.rdap_age_days:
            rdap_summary = f"{item.rdap_status} {item.rdap_age_days}".strip()
        dns_summary = item.dns_resolves or ""
        label_summary = ", ".join(item.labels)
        rows.append(
            {
                "url": item.url,
                "score": item.score,
                "risk": item.risk,
                "signals": signal_list,
                "labels": label_summary,
                "sender": sender,
                "subject": subject,
                "ti": ti_summary,
                "rdap": rdap_summary,
                "dns": dns_summary,
            }
        )

    html = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Phishing URL Triage Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 24px; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ccc; padding: 8px; vertical-align: top; }
th { background: #f2f2f2; }
.low { background: #e8f5e9; }
.medium { background: #fff8e1; }
.high { background: #ffebee; }
</style>
</head>
<body>
<h2>Phishing URL Triage Report</h2>
<table>
<thead>
<tr><th>URL</th><th>Score</th><th>Risk</th><th>Signals</th><th>Labels</th><th>Sender</th><th>Subject</th><th>Threat Intel</th><th>RDAP</th><th>DNS</th></tr>
</thead>
<tbody>
"""

    for item in rows:
        html += (
            f"<tr class=\"{item['risk']}\"><td>{item['url']}</td>"
            f"<td>{item['score']}</td><td>{item['risk']}</td><td>{item['signals']}</td>"
            f"<td>{item['labels']}</td><td>{item['sender']}</td><td>{item['subject']}</td><td>{item['ti']}</td>"
            f"<td>{item['rdap']}</td><td>{item['dns']}</td></tr>\n"
        )

    html += """
</tbody>
</table>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(html)


def load_urls(input_path: str) -> List[str]:
    if input_path.lower().endswith(".txt"):
        with open(input_path, encoding="utf-8") as handle:
            return [line.strip() for line in handle if line.strip()]
    with open(input_path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "url" not in reader.fieldnames:
            raise ValueError("Input CSV must contain a 'url' column.")
        return [row["url"].strip() for row in reader if row.get("url")]


def load_email_rows(input_path: str) -> List[Dict[str, str]]:
    with open(input_path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "url" not in reader.fieldnames:
            raise ValueError("Email CSV must contain a 'url' column.")
        rows = []
        for row in reader:
            url = (row.get("url") or "").strip()
            if not url:
                continue
            rows.append(
                {
                    "url": url,
                    "sender": (row.get("sender") or "").strip(),
                    "subject": (row.get("subject") or "").strip(),
                }
            )
        return rows


def collect_mitre_techniques(results: List[TriageResult]) -> List[str]:
    techniques = set()
    for item in results:
        for signal in item.signals:
            if signal.name in MITRE_MAPPING:
                techniques.add(MITRE_MAPPING[signal.name])
    if any(item.risk in {"medium", "high"} for item in results):
        techniques.add(MITRE_MAPPING["phishing_link"])
    return sorted(techniques)


def build_ioc_exports(results: List[TriageResult], output_dir: str, min_score: int) -> None:
    filtered = [item for item in results if item.score >= min_score]
    if not filtered:
        return

    url_set = []
    domain_set = []
    for item in filtered:
        url_set.append(item.url)
        hostname = get_hostname(item.url)
        if hostname:
            domain_set.append(hostname)

    url_set = sorted(set(url_set))
    domain_set = sorted(set(domain_set))

    ioc_text_path = os.path.join(output_dir, "iocs.txt")
    with open(ioc_text_path, "w", encoding="utf-8") as handle:
        for value in url_set + domain_set:
            handle.write(f"{value}\n")

    ioc_json_path = os.path.join(output_dir, "iocs.json")
    ioc_entries = []
    for item in filtered:
        ioc_entries.append(
            {
                "url": item.url,
                "domain": get_hostname(item.url),
                "score": item.score,
                "risk": item.risk,
                "signals": [f"{s.name}:{s.detail}" for s in item.signals],
                "labels": item.labels,
                "ti_source": item.ti_source,
                "ti_status": item.ti_status,
                "ti_tags": item.ti_tags,
                "ti_reference": item.ti_reference,
            }
        )
    with open(ioc_json_path, "w", encoding="utf-8") as handle:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(), "iocs": ioc_entries}, handle, indent=2)

    stix_path = os.path.join(output_dir, "stix_bundle.json")
    stix_objects = []
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    for item in filtered:
        stix_objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid4()}",
                "created": timestamp,
                "modified": timestamp,
                "name": "Phishing URL",
                "pattern": f"[url:value = '{item.url}']",
                "pattern_type": "stix",
            }
        )
    stix_bundle = {"type": "bundle", "id": f"bundle--{uuid4()}", "objects": stix_objects}
    with open(stix_path, "w", encoding="utf-8") as handle:
        json.dump(stix_bundle, handle, indent=2)


def write_alert_exports(results: List[TriageResult], output_dir: str, min_score: int) -> None:
    alerts = sorted(
        [item for item in results if item.score >= min_score],
        key=lambda x: x.score,
        reverse=True,
    )[:10]
    if not alerts:
        return

    mitre = collect_mitre_techniques(alerts)
    lines = [
        "Phishing URL Triage Alert",
        f"Total alerts: {len(alerts)}",
        f"MITRE: {', '.join(mitre) if mitre else 'N/A'}",
        "",
    ]
    for item in alerts:
        signals = "; ".join(f"{s.name}:{s.detail}" for s in item.signals)
        label_text = ",".join(item.labels) if item.labels else "none"
        lines.append(
            f"- {item.url} | score={item.score} | risk={item.risk} | labels={label_text} | {signals}"
        )

    text_path = os.path.join(output_dir, "alert.txt")
    with open(text_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))

    json_path = os.path.join(output_dir, "alert.json")
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "min_score": min_score,
                "mitre": mitre,
                "alerts": [
                    {
                        "url": item.url,
                        "score": item.score,
                        "risk": item.risk,
                        "labels": item.labels,
                        "signals": [f"{s.name}:{s.detail}" for s in item.signals],
                    }
                    for item in alerts
                ],
            },
            handle,
            indent=2,
        )


def write_analyst_report(results: List[TriageResult], output_path: str, min_score: int) -> None:
    total = len(results)
    high = sum(1 for item in results if item.risk == "high")
    medium = sum(1 for item in results if item.risk == "medium")
    low = sum(1 for item in results if item.risk == "low")
    ti_hits = sum(1 for item in results if item.ti_status == "ok")

    signal_counts: Dict[str, int] = {}
    for item in results:
        for signal in item.signals:
            signal_counts[signal.name] = signal_counts.get(signal.name, 0) + 1

    top_signals = sorted(signal_counts.items(), key=lambda x: x[1], reverse=True)[:8]
    top_high = sorted(
        [item for item in results if item.score >= min_score],
        key=lambda x: x.score,
        reverse=True,
    )[:10]

    label_counts: Dict[str, int] = {}
    for item in results:
        for label in item.labels:
            label_counts[label] = label_counts.get(label, 0) + 1
    top_labels = sorted(label_counts.items(), key=lambda x: x[1], reverse=True)[:6]

    mitre = collect_mitre_techniques(results)

    html = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Analyst Summary Report</title>
<style>
body { font-family: Arial, sans-serif; margin: 24px; }
.kpis { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 16px; }
.kpi { border: 1px solid #ccc; padding: 12px; border-radius: 6px; min-width: 120px; text-align: center; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ccc; padding: 8px; vertical-align: top; }
th { background: #f2f2f2; }
</style>
</head>
<body>
<h2>Analyst Summary Report</h2>
<div class="kpis">
  <div class="kpi"><div>Total</div><strong>{total}</strong></div>
  <div class="kpi"><div>High</div><strong>{high}</strong></div>
  <div class="kpi"><div>Medium</div><strong>{medium}</strong></div>
  <div class="kpi"><div>Low</div><strong>{low}</strong></div>
  <div class="kpi"><div>TI Hits</div><strong>{ti_hits}</strong></div>
</div>
<h3>Top Signals</h3>
<ul>
{signal_list}
</ul>
<h3>Top Labels</h3>
<ul>
{label_list}
</ul>
<h3>MITRE ATT&CK Mapping</h3>
<ul>
{mitre_list}
</ul>
<h3>Top High-Risk URLs</h3>
<table>
<thead><tr><th>URL</th><th>Score</th><th>Risk</th><th>Signals</th></tr></thead>
<tbody>
{top_rows}
</tbody>
</table>
<h3>Recommended Actions</h3>
<ol>
  <li>Validate high-risk URLs and consider blocking at email gateway or proxy.</li>
  <li>Investigate sender domains and user impact for any matches.</li>
  <li>Submit confirmed phishing URLs to threat intel feeds.</li>
</ol>
</body>
</html>
"""

    signal_list = "\n".join(f"<li>{name} ({count})</li>" for name, count in top_signals)
    top_rows = ""
    for item in top_high:
        signal_text = "; ".join(f"{s.name}:{s.detail}" for s in item.signals)
        top_rows += (
            f"<tr><td>{item.url}</td><td>{item.score}</td><td>{item.risk}</td><td>{signal_text}</td></tr>\n"
        )

    html = html.format(
        total=total,
        high=high,
        medium=medium,
        low=low,
        ti_hits=ti_hits,
        signal_list=signal_list,
        label_list="\n".join(f"<li>{name} ({count})</li>" for name, count in top_labels)
        if top_labels
        else "<li>N/A</li>",
        mitre_list="\n".join(f"<li>{item}</li>" for item in mitre) if mitre else "<li>N/A</li>",
        top_rows=top_rows,
    )

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(html)


def write_pdf_report(results: List[TriageResult], output_path: str, min_score: int) -> None:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
        from reportlab.lib import colors
    except ImportError as exc:
        raise RuntimeError("reportlab is required for PDF output") from exc

    total = len(results)
    high = sum(1 for item in results if item.risk == "high")
    medium = sum(1 for item in results if item.risk == "medium")
    low = sum(1 for item in results if item.risk == "low")
    ti_hits = sum(1 for item in results if item.ti_status == "ok")
    mitre = collect_mitre_techniques(results)

    top_high = sorted(
        [item for item in results if item.score >= min_score],
        key=lambda x: x.score,
        reverse=True,
    )[:10]

    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Analyst Summary Report", styles["Title"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f"Total: {total} | High: {high} | Medium: {medium} | Low: {low} | TI Hits: {ti_hits}", styles["BodyText"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph("MITRE ATT&CK Mapping", styles["Heading2"]))
    story.append(Paragraph(", ".join(mitre) if mitre else "N/A", styles["BodyText"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph("Top High-Risk URLs", styles["Heading2"]))

    table_data = [["URL", "Score", "Risk", "Signals"]]
    for item in top_high:
        signal_text = "; ".join(f"{s.name}:{s.detail}" for s in item.signals)
        table_data.append([item.url, str(item.score), item.risk, signal_text])

    table = Table(table_data, colWidths=[240, 50, 50, 200])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(table)

    doc.build(story)


def process_single_file(
    input_path: str,
    out_dir: str,
    ti_lookup: Optional[Callable[[str], Dict[str, str]]],
    rdap_lookup: Optional[Callable[[str], Dict[str, str]]],
    dns_lookup: bool,
    rdap_age_threshold: int,
    export_ioc: bool,
    export_alert: bool,
    analyst_report: bool,
    pdf_report: bool,
    min_score: int,
    email_mode: bool,
) -> None:
    results: List[TriageResult] = []
    if email_mode:
        rows = load_email_rows(input_path)
        for row in rows:
            results.append(
                triage_url(
                    row["url"],
                    sender=row.get("sender", ""),
                    subject=row.get("subject", ""),
                    ti_lookup=ti_lookup,
                    rdap_lookup=rdap_lookup,
                    dns_lookup=dns_lookup,
                    rdap_age_threshold=rdap_age_threshold,
                )
            )
    else:
        urls = load_urls(input_path)
        results = [
            triage_url(
                url,
                ti_lookup=ti_lookup,
                rdap_lookup=rdap_lookup,
                dns_lookup=dns_lookup,
                rdap_age_threshold=rdap_age_threshold,
            )
            for url in urls
        ]

    results.sort(key=lambda r: r.score, reverse=True)
    os.makedirs(out_dir, exist_ok=True)
    csv_path = os.path.join(out_dir, "report.csv")
    html_path = os.path.join(out_dir, "report.html")
    analyst_path = os.path.join(out_dir, "analyst_report.html")
    pdf_path = os.path.join(out_dir, "analyst_report.pdf")

    write_csv(results, csv_path)
    write_html(results, html_path)

    if export_ioc:
        build_ioc_exports(results, out_dir, min_score)
    if export_alert:
        write_alert_exports(results, out_dir, min_score)
    if analyst_report:
        write_analyst_report(results, analyst_path, min_score)
    if pdf_report:
        write_pdf_report(results, pdf_path, min_score)


def watch_directory(
    watch_dir: str,
    out_dir: str,
    ti_lookup: Optional[Callable[[str], Dict[str, str]]],
    rdap_lookup: Optional[Callable[[str], Dict[str, str]]],
    dns_lookup: bool,
    rdap_age_threshold: int,
    ti_enabled: bool,
    export_ioc: bool,
    export_alert: bool,
    analyst_report: bool,
    pdf_report: bool,
    min_score: int,
    interval: int,
) -> None:
    print(f"Watching {watch_dir} for new files...")
    seen: Dict[str, float] = {}

    while True:
        try:
            for name in os.listdir(watch_dir):
                if not name.lower().endswith((".csv", ".txt")):
                    continue
                path = os.path.join(watch_dir, name)
                if not os.path.isfile(path):
                    continue
                mtime = os.path.getmtime(path)
                if path in seen and seen[path] >= mtime:
                    continue

                base_name = os.path.splitext(name)[0]
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                target_dir = os.path.join(out_dir, f"{base_name}_{timestamp}")
                email_mode = "sender" in name.lower() or "email" in name.lower()

                process_single_file(
                    path,
                    target_dir,
                    ti_lookup,
                    rdap_lookup,
                    dns_lookup,
                    rdap_age_threshold,
                    export_ioc,
                    export_alert,
                    analyst_report,
                    pdf_report,
                    min_score,
                    email_mode,
                )
                seen[path] = mtime
                if ti_enabled:
                    print(f"Processed {path} with threat intel.")
                else:
                    print(f"Processed {path}.")
        except KeyboardInterrupt:
            print("Watch mode stopped.")
            break
        time.sleep(max(1, interval))


def main() -> int:
    parser = argparse.ArgumentParser(description="Phishing URL triage tool")
    parser.add_argument("--input", help="Path to CSV/TXT with a 'url' column or list")
    parser.add_argument("--email-input", help="Path to email CSV with url/sender/subject")
    parser.add_argument("--out", default="reports", help="Output directory")
    parser.add_argument("--ti", action="store_true", help="Enable URLhaus threat intel lookup")
    parser.add_argument("--ti-timeout", type=int, default=4, help="Threat intel timeout seconds")
    parser.add_argument("--rdap", action="store_true", help="Enable RDAP domain age lookup")
    parser.add_argument("--rdap-timeout", type=int, default=4, help="RDAP timeout seconds")
    parser.add_argument("--rdap-age-threshold", type=int, default=30, help="New domain age in days")
    parser.add_argument("--dns", action="store_true", help="Enable DNS resolution check")
    parser.add_argument("--export-ioc", action="store_true", help="Export IOC files")
    parser.add_argument("--export-alert", action="store_true", help="Export alert files")
    parser.add_argument("--analyst-report", action="store_true", help="Write analyst summary HTML")
    parser.add_argument("--pdf-report", action="store_true", help="Write analyst summary PDF")
    parser.add_argument("--min-score", type=int, default=40, help="Threshold for IOC/report exports")
    parser.add_argument("--watch-dir", help="Watch a folder for new files")
    parser.add_argument("--watch-interval", type=int, default=10, help="Seconds between scans")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    args = parser.parse_args()

    if args.version:
        print(f"Phishing URL Triage v{VERSION}")
        return 0

    print(f"Phishing URL Triage v{VERSION}")

    if args.watch_dir and (args.input or args.email_input):
        print("Error: watch mode cannot be combined with --input or --email-input")
        return 1

    if not args.input and not args.email_input and not args.watch_dir:
        print("Error: provide --input, --email-input, or --watch-dir")
        return 1

    if args.input and args.email_input:
        print("Error: use only one of --input or --email-input")
        return 1

    ti_cache: Dict[str, Dict[str, str]] = {}
    ti_lookup = None
    if args.ti:
        def cached_lookup(url: str) -> Dict[str, str]:
            if url in ti_cache:
                return ti_cache[url]
            ti_cache[url] = lookup_urlhaus(url, args.ti_timeout)
            return ti_cache[url]

        ti_lookup = cached_lookup

    results: List[TriageResult] = []

    rdap_cache: Dict[str, Dict[str, str]] = {}
    rdap_lookup = None
    if args.rdap:
        def cached_rdap(hostname: str) -> Dict[str, str]:
            if hostname in rdap_cache:
                return rdap_cache[hostname]
            rdap_cache[hostname] = lookup_rdap(hostname, args.rdap_timeout)
            return rdap_cache[hostname]

        rdap_lookup = cached_rdap
    try:
        if args.watch_dir:
            watch_directory(
                args.watch_dir,
                args.out,
                ti_lookup,
                rdap_lookup,
                args.dns,
                args.rdap_age_threshold,
                args.ti,
                args.export_ioc,
                args.export_alert,
                args.analyst_report,
                args.pdf_report,
                args.min_score,
                args.watch_interval,
            )
            return 0
        if args.email_input:
            rows = load_email_rows(args.email_input)
            for row in rows:
                results.append(
                    triage_url(
                        row["url"],
                        sender=row.get("sender", ""),
                        subject=row.get("subject", ""),
                        ti_lookup=ti_lookup,
                        rdap_lookup=rdap_lookup,
                        dns_lookup=args.dns,
                        rdap_age_threshold=args.rdap_age_threshold,
                    )
                )
        else:
            urls = load_urls(args.input)
            results = [
                triage_url(
                    url,
                    ti_lookup=ti_lookup,
                    rdap_lookup=rdap_lookup,
                    dns_lookup=args.dns,
                    rdap_age_threshold=args.rdap_age_threshold,
                )
                for url in urls
            ]
    except Exception as exc:
        print(f"Error reading input: {exc}")
        return 1

    results = [triage_url(url) for url in urls]
    results.sort(key=lambda r: r.score, reverse=True)

    os.makedirs(args.out, exist_ok=True)
    csv_path = os.path.join(args.out, "report.csv")
    html_path = os.path.join(args.out, "report.html")
    analyst_path = os.path.join(args.out, "analyst_report.html")
    pdf_path = os.path.join(args.out, "analyst_report.pdf")

    write_csv(results, csv_path)
    write_html(results, html_path)

    if args.export_ioc:
        build_ioc_exports(results, args.out, args.min_score)

    if args.export_alert:
        write_alert_exports(results, args.out, args.min_score)

    if args.analyst_report:
        write_analyst_report(results, analyst_path, args.min_score)

    if args.pdf_report:
        write_pdf_report(results, pdf_path, args.min_score)

    print(f"Wrote {csv_path}")
    print(f"Wrote {html_path}")
    if args.export_ioc:
        print(f"Wrote IOC exports to {args.out}")
    if args.export_alert:
        print(f"Wrote alert exports to {args.out}")
    if args.analyst_report:
        print(f"Wrote {analyst_path}")
    if args.pdf_report:
        print(f"Wrote {pdf_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
