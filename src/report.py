# src/report.py
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


# ─── Цвета по вердикту ────────────────────────────────────────────────────────
_VERDICT_COLOR = {
    "legitimate":  ("#22c55e", "#dcfce7", "✅ Легитимный"),
    "suspicious":  ("#f59e0b", "#fef9c3", "⚠️ Подозрительный"),
    "malicious":   ("#ef4444", "#fee2e2", "🚨 Вредоносный / Фишинг"),
}

_BASE_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a;
       color: #e2e8f0; min-height: 100vh; padding: 2rem; }
.card { background: #1e293b; border-radius: 12px; padding: 1.5rem;
        margin-bottom: 1.5rem; border: 1px solid #334155; }
h1 { font-size: 1.6rem; font-weight: 700; margin-bottom: 0.4rem; }
h2 { font-size: 1.1rem; font-weight: 600; color: #94a3b8;
     margin-bottom: 1rem; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }
.badge { display: inline-block; padding: 0.3rem 0.9rem; border-radius: 999px;
         font-weight: 700; font-size: 0.95rem; }
.row { display: flex; gap: 0.5rem; align-items: baseline;
       margin-bottom: 0.4rem; font-size: 0.9rem; }
.label { color: #94a3b8; min-width: 200px; }
.val { color: #f1f5f9; word-break: break-all; }
.score-bar-wrap { background: #0f172a; border-radius: 999px;
                  height: 12px; margin: 0.8rem 0; overflow: hidden; }
.score-bar { height: 100%; border-radius: 999px;
             transition: width 0.6s ease; }
table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
th { text-align: left; color: #94a3b8; padding: 0.5rem 0.75rem;
     border-bottom: 1px solid #334155; }
td { padding: 0.5rem 0.75rem; border-bottom: 1px solid #1e293b;
     word-break: break-all; }
tr:hover td { background: #1e293b44; }
.reasons li { margin: 0.3rem 0 0.3rem 1.2rem; font-size: 0.88rem; color: #cbd5e1; }
a { color: #60a5fa; }
"""


def _verdict_html(verdict: str, score: int) -> str:
    color, bg, label = _VERDICT_COLOR.get(
        verdict, ("#94a3b8", "#1e293b", verdict)
    )
    bar_color = color
    return f"""
        <div style="margin-bottom:1rem;">
          <span class="badge" style="background:{bg};color:{color};border:1px solid {color}">
            {label}
          </span>
          <span style="margin-left:1rem;font-size:1.5rem;font-weight:900;color:{color}">{score} / 100</span>
        </div>
        <div class="score-bar-wrap">
          <div class="score-bar" style="width:{score}%;background:{bar_color};"></div>
        </div>
    """


def _extract_reasons(details: Dict[str, Any]) -> List[str]:
    """Извлекает причины риска из details скоринга."""
    reasons: List[str] = []

    # SSL
    ssl = details.get("ssl", {})
    if ssl.get("expired"):
        reasons.append("SSL-сертификат истёк")
    if ssl.get("self_signed"):
        reasons.append("Самоподписанный SSL-сертификат")
    if ssl.get("hostname_mismatch"):
        reasons.append("Несоответствие хоста в SSL-сертификате")
    if ssl.get("short_validity"):
        reasons.append("Короткий срок действия SSL-сертификата (< 30 дней)")
    if ssl.get("error") and not ssl.get("present"):
        reasons.append("SSL-сертификат отсутствует или ошибка подключения")

    # VirusTotal
    vt = details.get("virustotal", {})
    vt_pos = vt.get("vt_positives")
    if vt_pos and vt_pos > 0:
        reasons.append(f"VirusTotal: {vt_pos} срабатываний")

    # OpenTIP
    ot = details.get("opentip", {})
    ot_flags = ot.get("raw_flags", [])
    if "malicious_or_phishing" in ot_flags:
        reasons.append("Kaspersky OpenTIP: обнаружен как вредоносный/фишинг")
    elif "suspicious" in ot_flags:
        reasons.append("Kaspersky OpenTIP: подозрительный")

    # TLD
    tld = details.get("tld", {})
    if tld.get("suspicious_tld"):
        reasons.append(f"Подозрительная доменная зона: .{tld.get('tld', '')}")

    # Brand abuse
    brand_flags = details.get("brand_abuse_flags", [])
    if brand_flags:
        for flag in brand_flags:
            brand = flag.get("brand", "?")
            mtype = flag.get("match_type", "")
            reasons.append(f"Имитация бренда: {brand} ({mtype})")

    # Redirect
    redirect = details.get("redirect", {})
    if redirect.get("suspicious_redirect"):
        reasons.append(f"Подозрительный редирект на {redirect.get('redirect_scheme', '?')}")

    # Domain age
    domain_age = details.get("domain_age", {})
    if domain_age.get("young_domain"):
        age = domain_age.get("age_days", "?")
        reasons.append(f"Домен зарегистрирован менее 30 дней назад (возраст: {age} дн.)")

    # HTML
    html = details.get("html", {})
    if html.get("has_password_input") and html.get("suspicious_context"):
        reasons.append("Форма ввода пароля в подозрительном контексте")
    if html.get("has_payment_keywords") and html.get("suspicious_context"):
        reasons.append("Платёжные ключевые слова в подозрительном контексте")

    return reasons


def _extract_components(details: Dict[str, Any]) -> Dict[str, str]:
    """Формирует читаемые компоненты оценки."""
    components: Dict[str, str] = {}

    ssl = details.get("ssl", {})
    if ssl.get("present"):
        nb = ssl.get("not_before", "?")
        na = ssl.get("not_after", "?")
        components["SSL-сертификат"] = f"OK (действителен до {na})"
    elif ssl.get("error"):
        components["SSL-сертификат"] = f"Ошибка: {ssl['error']}"
    else:
        components["SSL-сертификат"] = "Не найден"

    vt = details.get("virustotal", {})
    if vt.get("vt_positives") is not None:
        components["VirusTotal"] = f"{vt['vt_positives']} / {vt.get('vt_total', '?')}"
    else:
        components["VirusTotal"] = "Нет данных"

    ot = details.get("opentip", {})
    ot_flags = ot.get("raw_flags", [])
    components["Kaspersky OpenTIP"] = ", ".join(ot_flags) if ot_flags else "Нет данных"

    tld = details.get("tld", {})
    tld_val = tld.get("tld", "?")
    if tld.get("suspicious_tld"):
        tld_val += " ⚠️ подозрительная"
    components["Доменная зона (TLD)"] = tld_val

    brand_flags = details.get("brand_abuse_flags", [])
    if brand_flags:
        brands = ", ".join(f.get("brand", "?") for f in brand_flags)
        components["Имитация брендов"] = f"Обнаружена: {brands}"
    else:
        components["Имитация брендов"] = "Не обнаружена"

    redirect = details.get("redirect", {})
    if redirect.get("has_redirect"):
        if redirect.get("suspicious_redirect"):
            components["Редирект"] = f"Подозрительный ({redirect.get('redirect_scheme', '?')})"
        else:
            components["Редирект"] = "Да (нормальный)"
    else:
        components["Редирект"] = "Нет"

    domain_age = details.get("domain_age", {})
    age_days = domain_age.get("age_days")
    if age_days is not None:
        components["Возраст домена"] = f"{age_days} дн."
        if domain_age.get("young_domain"):
            components["Возраст домена"] += " ⚠️ менее 30 дней"
    else:
        components["Возраст домена"] = "Нет данных (WHOIS недоступен)"

    html = details.get("html", {})
    html_flags = []
    if html.get("has_password_input"):
        html_flags.append("password input")
    if html.get("has_login_keywords"):
        html_flags.append("login keywords")
    if html.get("has_payment_keywords"):
        html_flags.append("payment keywords")
    components["HTML-контент"] = ", ".join(html_flags) if html_flags else "Нейтральный"

    net = details.get("network", {})
    components["Сетевые запросы"] = str(net.get("total_requests", 0))
    third_party = net.get("third_party_hosts", [])
    if third_party:
        components["Сторонние хосты"] = ", ".join(third_party[:5])

    return components


def generate_html_report(score_data: dict, output_path: Path) -> None:
    """
    Генерирует HTML-отчёт для одного URL на основе score_data.
    Сохраняет файл по пути output_path.
    """
    # Адаптация: compute_risk_score возвращает risk_score/original_url/details
    url = score_data.get("url") or score_data.get("original_url", "—")
    final_url = score_data.get("final_url", url)
    score = score_data.get("score") or score_data.get("risk_score", 0)
    verdict = score_data.get("verdict", "unknown")
    timestamp = score_data.get("timestamp", datetime.now().isoformat())
    details = score_data.get("details", {})

    reasons = score_data.get("reasons") or _extract_reasons(details)
    components = score_data.get("components") or _extract_components(details)

    # ── Детали компонентов ──────────────────────────────────────────────────
    comp_rows = ""
    for key, val in components.items():
        comp_rows += f"<tr><td>{key}</td><td>{val}</td></tr>"

    # ── Причины ────────────────────────────────────────────────────────────
    reasons_html = ""
    if reasons:
        items = "".join(f"<li>{r}</li>" for r in reasons)
        reasons_html = f"""
        <div class="card">
          <h2>Факторы риска</h2>
          <ul class="reasons">{items}</ul>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>Отчёт: {url[:60]}</title>
<style>{_BASE_CSS}</style>
</head>
<body>
<div class="card">
  <h1>🔍 Отчёт анализа веб-артефактов</h1>
  <div style="color:#94a3b8;font-size:0.85rem;margin-bottom:1rem">{timestamp}</div>

  {_verdict_html(verdict, score)}

  <div class="row"><span class="label">Исходный URL</span>
    <a class="val" href="{url}" target="_blank">{url}</a></div>
  <div class="row"><span class="label">Финальный URL (после редиректов)</span>
    <a class="val" href="{final_url}" target="_blank">{final_url}</a></div>
</div>

{reasons_html}

<div class="card">
  <h2>Компоненты оценки</h2>
  <table>
    <thead><tr><th>Компонент</th><th>Значение / Баллы</th></tr></thead>
    <tbody>{comp_rows}</tbody>
  </table>
</div>

<div style="color:#475569;font-size:0.78rem;text-align:center;margin-top:2rem">
  Сгенерировано программным комплексом web_artifacts_project
</div>
</body>
</html>
"""
    output_path.write_text(html, encoding="utf-8")


def generate_summary_report(all_scores: list, output_path: Path) -> None:
    """
    Генерирует сводный HTML-отчёт по всей сессии проверки.
    all_scores — список score_data для каждого URL.
    """
    total = len(all_scores)
    counts = {"legitimate": 0, "suspicious": 0, "malicious": 0}
    for s in all_scores:
        v = s.get("verdict", "unknown")
        if v in counts:
            counts[v] += 1

    timestamp = datetime.now().strftime("%d.%m.%Y %H:%M:%S")

    # ── Цвета для светлой темы ────────────────────────────────────────────
    _LIGHT_VERDICT = {
        "legitimate":  ("#16a34a", "#dcfce7", "#f0fdf4"),
        "suspicious":  ("#d97706", "#fef3c7", "#fffbeb"),
        "malicious":   ("#dc2626", "#fee2e2", "#fef2f2"),
    }

    # ── Сводная статистика ──────────────────────────────────────────────────
    stat_cards = ""
    for verdict_key, label_emoji in [
        ("legitimate",  "✅ Легитимных"),
        ("suspicious",  "⚠️ Подозрительных"),
        ("malicious",   "🚨 Вредоносных"),
    ]:
        color, bg, border_bg = _LIGHT_VERDICT[verdict_key]
        n = counts[verdict_key]
        pct = round(n / total * 100) if total else 0
        stat_cards += f"""
        <div style="background:{border_bg};border:2px solid {color};border-radius:12px;
                    padding:1.2rem 1.5rem;flex:1;min-width:160px;text-align:center;">
          <div style="font-size:2.2rem;font-weight:900;color:{color}">{n}</div>
          <div style="color:#64748b;font-size:0.9rem;font-weight:600">{label_emoji}</div>
          <div style="color:{color};font-size:0.85rem;font-weight:500">{pct}% от {total}</div>
        </div>"""

    # ── Список сайтов, требующих допроверки (suspicious) ──────────────────
    manual_review = [s for s in all_scores if s.get("verdict") == "suspicious"]
    review_html = ""
    if manual_review:
        review_items = ""
        for s in sorted(manual_review, key=lambda x: x.get("score", x.get("risk_score", 0)), reverse=True):
            url = s.get("url") or s.get("original_url", "—")
            score = s.get("score") or s.get("risk_score", 0)
            details = s.get("details", {})
            reasons = _extract_reasons(details)
            reasons_list = "".join(f"<li>{r}</li>" for r in reasons) if reasons else "<li>Автоматическая классификация — уточните вручную</li>"
            review_items += f"""
            <div style="background:#fffbeb;border:1px solid #f59e0b;border-radius:8px;padding:1rem;margin-bottom:0.75rem;">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem;">
                <a href="{url}" target="_blank" style="color:#d97706;font-weight:600;font-size:0.95rem;">{url[:90]}</a>
                <span style="background:#fef3c7;color:#d97706;font-weight:700;padding:0.2rem 0.7rem;border-radius:999px;font-size:0.85rem;">{score} баллов</span>
              </div>
              <ul style="margin:0;padding-left:1.2rem;color:#78716c;font-size:0.85rem;">{reasons_list}</ul>
            </div>"""
        review_html = f"""
        <div class="card" style="border:2px solid #f59e0b;">
          <h2 style="color:#d97706;">⚠️ Требуют ручной допроверки ({len(manual_review)})</h2>
          {review_items}
        </div>"""

    # ── Таблица всех URL ────────────────────────────────────────────────────
    sorted_scores = sorted(
        all_scores,
        key=lambda x: x.get("score", x.get("risk_score", 0)),
        reverse=True,
    )
    table_rows = ""
    for i, s in enumerate(sorted_scores, 1):
        url = s.get("url") or s.get("original_url", "—")
        score = s.get("score") or s.get("risk_score", 0)
        verdict = s.get("verdict", "unknown")
        color, bg, row_bg = _LIGHT_VERDICT.get(
            verdict, ("#94a3b8", "#f1f5f9", "#f8fafc")
        )

        table_rows += f"""
        <tr style="background:{row_bg};">
          <td style="color:#64748b;padding:0.6rem 0.75rem;">{i}</td>
          <td style="padding:0.6rem 0.75rem;"><a href="{url}" target="_blank" style="color:#2563eb;font-weight:500;">{url[:80]}</a></td>
          <td style="padding:0.6rem 0.75rem;"><span style="background:{bg};color:{color};border:1px solid {color};
              padding:0.2rem 0.6rem;border-radius:999px;font-size:0.8rem;font-weight:600;">{_VERDICT_COLOR.get(verdict, ('', '', ''))[2]}</span></td>
          <td style="color:{color};font-weight:700;font-size:1.05rem;padding:0.6rem 0.75rem;">{score}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>Сводный отчёт — {timestamp}</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f1f5f9;
       color: #1e293b; min-height: 100vh; padding: 2rem; }}
.card {{ background: #ffffff; border-radius: 12px; padding: 1.5rem;
        margin-bottom: 1.5rem; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.06); }}
h1 {{ font-size: 1.6rem; font-weight: 700; margin-bottom: 0.4rem; color: #0f172a; }}
h2 {{ font-size: 1.1rem; font-weight: 600; color: #475569;
     margin-bottom: 1rem; border-bottom: 1px solid #e2e8f0; padding-bottom: 0.5rem; }}
.stat-row {{ display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:1.5rem; }}
table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
th {{ text-align: left; color: #64748b; padding: 0.6rem 0.75rem;
     border-bottom: 2px solid #e2e8f0; font-weight: 600; }}
td {{ padding: 0.6rem 0.75rem; border-bottom: 1px solid #f1f5f9; word-break: break-all; }}
</style>
</head>
<body>
<div class="card">
  <h1>📊 Сводный отчёт проверки URL</h1>
  <div style="color:#64748b;font-size:0.85rem;margin-bottom:1.2rem;">
    Сессия завершена: {timestamp} &middot; Проверено URL: <strong style="color:#0f172a;">{total}</strong>
  </div>
  <div class="stat-row">
    {stat_cards}
  </div>
</div>

{review_html}

<div class="card">
  <h2>Все проверенные URL (отсортировано по убыванию риска)</h2>
  <table>
    <thead>
      <tr>
        <th>#</th>
        <th>URL</th>
        <th>Вердикт</th>
        <th>Баллы</th>
      </tr>
    </thead>
    <tbody>{table_rows}</tbody>
  </table>
</div>

</body>
</html>
"""
    output_path.write_text(html, encoding="utf-8")
