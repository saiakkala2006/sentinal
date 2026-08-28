#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           SENTINEL — Bulk Email Testing Module                  ║
║  Tests thousands of .eml files against the live Sentinel API    ║
║  Generates CSV + JSON + HTML report with full statistics        ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
  python bulk_tester.py --dir /path/to/emails
  python bulk_tester.py --dir /path/to/emails --workers 20
  python bulk_tester.py --dir /path/to/emails --url http://localhost:8000
  python bulk_tester.py --dir /path/to/emails --output my_results

Folder label auto-detection (optional — enables accuracy / F1 stats):
  emails/
    phishing/   <- auto-labeled as THREAT
    spam/       <- auto-labeled as THREAT
    legit/      <- auto-labeled as BENIGN
    ham/        <- auto-labeled as BENIGN

If no subfolders match, all emails are still processed without ground truth.
"""

import argparse
import asyncio
import csv
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# ── Optional dependency guards ─────────────────────────────────────────────────
try:
    import httpx
except ImportError:
    print("[ERROR] httpx not installed.  Run:  pip install httpx")
    sys.exit(1)

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

# ── Constants ──────────────────────────────────────────────────────────────────
VERSION       = "1.0.0"
DEFAULT_URL   = "http://localhost:8000"
DEFAULT_WORKERS = 10
DEFAULT_TIMEOUT = 30.0   # seconds per request
SAVE_EVERY    = 100      # incremental CSV flush interval

THREAT_LABELS = {"phishing", "spam", "malware", "threat", "attack", "suspicious"}
BENIGN_LABELS = {"legit", "legitimate", "ham", "benign", "safe", "clean"}

CSV_FIELDS = [
    "filename", "status", "ground_truth", "risk_score", "severity",
    "recommended_action", "anomaly_score", "detection_score",
    "attribution_country", "attribution_confidence", "campaign_id",
    "healing_applied", "from_addr", "spf", "dkim", "dmarc",
    "elapsed_ms", "explanation", "error", "timestamp", "file",
]


# ── Helpers ────────────────────────────────────────────────────────────────────
def infer_label(path: Path) -> Optional[str]:
    """Infer THREAT / BENIGN from the parent folder name."""
    for part in reversed(path.parts[:-1]):
        lp = part.lower()
        if lp in THREAT_LABELS:
            return "THREAT"
        if lp in BENIGN_LABELS:
            return "BENIGN"
    return None


def collect_emails(root: Path, exts=(".eml", ".msg", ".txt")) -> List[Path]:
    files: List[Path] = []
    for ext in exts:
        files.extend(root.rglob(f"*{ext}"))
    return sorted(files)


def simple_bar(done: int, total: int, prefix: str = "") -> None:
    pct = (done / total * 100) if total else 0
    bar = "█" * int(pct // 2) + "░" * (50 - int(pct // 2))
    print(f"\r{prefix}[{bar}] {done}/{total} ({pct:.1f}%)", end="", flush=True)


# ── Single email analysis ──────────────────────────────────────────────────────
async def analyze_one(
    client: httpx.AsyncClient,
    eml_path: Path,
    api_url: str,
    user_id: str,
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    async with semaphore:
        t0 = time.perf_counter()
        rec: Dict[str, Any] = {
            "file": str(eml_path), "filename": eml_path.name,
            "ground_truth": infer_label(eml_path), "status": "ERROR",
            "error": None, "risk_score": None, "severity": None,
            "recommended_action": None, "anomaly_score": None,
            "detection_score": None, "explanation": None,
            "attribution_country": None, "attribution_confidence": None,
            "campaign_id": None, "healing_applied": None,
            "from_addr": None, "spf": None, "dkim": None, "dmarc": None,
            "elapsed_ms": None, "timestamp": datetime.now().isoformat(),
        }
        try:
            raw = eml_path.read_bytes()
        except (OSError, IOError) as read_err:
            rec["error"] = f"READ_ERROR: {str(read_err)[:100]}"
            rec["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 1)
            return rec

        try:
            resp = await client.post(
                f"{api_url}/analyze",
                files={"file": (eml_path.name, raw, "message/rfc822")},
                data={"user_id": user_id, "update_twin": "false"},
                timeout=DEFAULT_TIMEOUT,
            )
            resp.raise_for_status()
            d = resp.json()
            meta = d.get("metadata") or {}
            auth = meta.get("authentication") or {}
            attr = d.get("attribution") or {}
            expl = d.get("explanation") or {}
            rec.update({
                "status":                 "OK",
                "risk_score":             d.get("risk_score"),
                "severity":               d.get("severity"),
                "recommended_action":     d.get("recommended_action"),
                "anomaly_score":          d.get("anomaly_score"),
                "detection_score":        d.get("detection_score"),
                "explanation":            expl.get("summary", "") if isinstance(expl, dict) else str(expl)[:200],
                "attribution_country":    attr.get("top_country"),
                "attribution_confidence": attr.get("confidence"),
                "campaign_id":            d.get("campaign_id"),
                "healing_applied":        d.get("healing_applied"),
                "from_addr":              meta.get("from") or meta.get("from_addr"),
                "spf":                    auth.get("spf"),
                "dkim":                   auth.get("dkim"),
                "dmarc":                  auth.get("dmarc"),
            })
        except httpx.ReadTimeout:
            rec["error"] = "TIMEOUT"
        except httpx.HTTPStatusError as e:
            rec["error"] = f"HTTP_{e.response.status_code}"
        except Exception as e:
            rec["error"] = str(e)[:120]
        finally:
            rec["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        return rec



# ── Statistics ─────────────────────────────────────────────────────────────────
def compute_stats(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    ok  = [r for r in results if r["status"] == "OK"]
    err = [r for r in results if r["status"] != "OK"]

    risks   = [r["risk_score"]   for r in ok if r["risk_score"]   is not None]
    anomaly = [r["anomaly_score"] for r in ok if r["anomaly_score"] is not None]
    ms_list = [r["elapsed_ms"]   for r in ok if r["elapsed_ms"]   is not None]

    actions   = Counter(r.get("recommended_action", "UNKNOWN") for r in ok)
    sevs      = Counter(r.get("severity", "UNKNOWN") for r in ok)
    countries = Counter(r.get("attribution_country") for r in ok if r.get("attribution_country"))
    errs_cnt  = Counter(r.get("error") for r in err if r.get("error"))
    campaigns = len({r["campaign_id"] for r in ok if r.get("campaign_id")})
    healed    = sum(1 for r in ok if r.get("healing_applied"))

    labeled = [r for r in ok if r.get("ground_truth")]
    acc: Dict[str, Any] = {}
    if labeled:
        tp = sum(1 for r in labeled if r["ground_truth"] == "THREAT"
                 and r.get("recommended_action") in ("QUARANTINE", "ALERT", "BLOCK"))
        tn = sum(1 for r in labeled if r["ground_truth"] == "BENIGN"
                 and r.get("recommended_action") == "ALLOW")
        fp = sum(1 for r in labeled if r["ground_truth"] == "BENIGN"
                 and r.get("recommended_action") in ("QUARANTINE", "ALERT", "BLOCK"))
        fn = sum(1 for r in labeled if r["ground_truth"] == "THREAT"
                 and r.get("recommended_action") == "ALLOW")
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec  = tp / (tp + fn) if tp + fn else 0.0
        f1   = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        accy = (tp + tn) / len(labeled) if labeled else 0.0
        acc  = {
            "total_labeled": len(labeled),
            "true_positives": tp, "true_negatives": tn,
            "false_positives": fp, "false_negatives": fn,
            "precision": round(prec, 4), "recall": round(rec, 4),
            "f1_score":  round(f1, 4),  "accuracy": round(accy, 4),
        }

    return {
        "total": len(results), "successful": len(ok), "errors": len(err),
        "error_rate":      round(len(err) / len(results) * 100, 2) if results else 0,
        "avg_risk_score":  round(sum(risks)   / len(risks),   2)  if risks   else 0,
        "max_risk_score":  round(max(risks),   2)                  if risks   else 0,
        "avg_anomaly":     round(sum(anomaly)  / len(anomaly), 4)  if anomaly else 0,
        "avg_elapsed_ms":  round(sum(ms_list)  / len(ms_list), 1)  if ms_list else 0,
        "min_elapsed_ms":  round(min(ms_list), 1)                  if ms_list else 0,
        "max_elapsed_ms":  round(max(ms_list), 1)                  if ms_list else 0,
        "action_counts":   dict(actions),
        "severity_counts": dict(sevs),
        "top_countries":   dict(countries.most_common(10)),
        "error_types":     dict(errs_cnt),
        "campaigns_found": campaigns,
        "healing_triggered": healed,
        "accuracy":        acc,
    }


# ── Report Writers ─────────────────────────────────────────────────────────────
def write_csv(results: List[Dict[str, Any]], path: Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(results)


def write_json(results: List[Dict[str, Any]], stats: Dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps({"stats": stats, "results": results}, indent=2, default=str), encoding="utf-8")


def write_html(results: List[Dict[str, Any]], stats: Dict[str, Any],
               path: Path, run_id: str, elapsed: float) -> None:
    ok = [r for r in results if r["status"] == "OK"]
    sev_clr = {"CRITICAL": "#ff4c4c", "HIGH": "#ff8c00",
                "MEDIUM": "#ffd700",  "LOW": "#00c851", "UNKNOWN": "#888"}

    action_labels  = json.dumps(list(stats["action_counts"].keys()))
    action_values  = json.dumps(list(stats["action_counts"].values()))
    sev_labels     = json.dumps(list(stats["severity_counts"].keys()))
    sev_values     = json.dumps(list(stats["severity_counts"].values()))
    sev_colors     = json.dumps([sev_clr.get(k, "#888") for k in stats["severity_counts"]])
    ctr_labels     = json.dumps(list(stats["top_countries"].keys()))
    ctr_values     = json.dumps(list(stats["top_countries"].values()))

    buckets = [0] * 10
    for r in ok:
        if r["risk_score"] is not None:
            buckets[min(int(r["risk_score"] // 10), 9)] += 1
    risk_labels = json.dumps([f"{i*10}-{i*10+10}" for i in range(10)])
    risk_values = json.dumps(buckets)

    # Accuracy block
    acc     = stats.get("accuracy") or {}
    acc_sec = ""
    if acc:
        acc_sec = f"""
<div class="section">
  <h2>🎯 Detection Accuracy (Ground Truth)</h2>
  <div class="sg">
    <div class="sc ab"><div class="sv">{round(acc['accuracy']*100,1)}%</div><div class="sl">Accuracy</div></div>
    <div class="sc ag"><div class="sv">{round(acc['precision']*100,1)}%</div><div class="sl">Precision</div></div>
    <div class="sc ap"><div class="sv">{round(acc['recall']*100,1)}%</div><div class="sl">Recall</div></div>
    <div class="sc ao"><div class="sv">{round(acc['f1_score']*100,1)}%</div><div class="sl">F1 Score</div></div>
  </div>
  <table class="cmt">
    <thead><tr><th></th><th>Pred THREAT</th><th>Pred BENIGN</th></tr></thead>
    <tbody>
      <tr><th>Actual THREAT</th><td class="tp">TP: {acc['true_positives']}</td><td class="fn">FN: {acc['false_negatives']}</td></tr>
      <tr><th>Actual BENIGN</th><td class="fp">FP: {acc['false_positives']}</td><td class="tn">TN: {acc['true_negatives']}</td></tr>
    </tbody>
  </table>
</div>"""

    # Top threats table
    top = sorted([r for r in ok if (r["risk_score"] or 0) >= 50],
                 key=lambda x: x["risk_score"] or 0, reverse=True)[:25]

    def badge(sev):
        c = sev_clr.get(sev or "UNKNOWN", "#888")
        return f'<span style="background:{c};color:#fff;padding:2px 7px;border-radius:4px;font-size:11px">{sev or "?"}</span>'

    rows = "".join(
        f"<tr><td title='{r['file']}'>{r['filename'][:45]}</td>"
        f"<td>{r['risk_score']}</td><td>{badge(r['severity'])}</td>"
        f"<td>{r.get('recommended_action','')}</td>"
        f"<td>{(r.get('from_addr') or '')[:35]}</td>"
        f"<td>{r.get('attribution_country','')}</td>"
        f"<td>{r.get('spf','')}</td><td>{r.get('dkim','')}</td><td>{r.get('dmarc','')}</td></tr>"
        for r in top
    ) or "<tr><td colspan='9' style='text-align:center;color:#8b949e'>No high-risk emails</td></tr>"

    tput = round(len(results) / elapsed, 1) if elapsed else "—"
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel Bulk Test — {run_id}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{{--bg:#0d1117;--sf:#161b22;--bd:#30363d;--tx:#c9d1d9;--ac:#58a6ff;--gr:#3fb950;--rd:#f85149;--yl:#d29922;--pu:#bc8cff}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--tx);font-family:'Segoe UI',system-ui,sans-serif;padding:24px}}
h1{{font-size:28px;color:#fff;margin-bottom:4px}} h2{{font-size:17px;color:var(--ac);margin-bottom:14px}}
.meta{{color:#8b949e;font-size:13px;margin-bottom:26px}}
.section{{background:var(--sf);border:1px solid var(--bd);border-radius:10px;padding:22px;margin-bottom:22px}}
.sg{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:18px}}
.sc{{background:var(--bg);border:1px solid var(--bd);border-radius:8px;padding:14px;text-align:center}}
.sv{{font-size:26px;font-weight:700;color:#fff}} .sl{{font-size:11px;color:#8b949e;margin-top:3px;text-transform:uppercase}}
.ab .sv{{color:var(--ac)}} .ag .sv{{color:var(--gr)}} .ar .sv{{color:var(--rd)}}
.ay .sv{{color:var(--yl)}} .ap .sv{{color:var(--pu)}} .ao .sv{{color:#ff8c00}}
.charts{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}
.cw{{background:var(--bg);border:1px solid var(--bd);border-radius:8px;padding:14px}}
.cw canvas{{max-height:270px}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th,td{{padding:8px 10px;border-bottom:1px solid var(--bd);text-align:left}}
th{{color:#8b949e;font-weight:600;background:var(--bg)}}
tr:hover td{{background:rgba(88,166,255,.05)}}
.cmt{{max-width:400px;margin-top:14px}} .cmt td{{text-align:center;font-weight:700;font-size:14px}}
.tp,.tn{{color:var(--gr)}} .fp,.fn{{color:var(--rd)}}
@media(max-width:640px){{.charts{{grid-template-columns:1fr}}}}
</style></head><body>
<h1>🛡️ Sentinel — Bulk Test Report</h1>
<p class="meta">Run: <strong>{run_id}</strong> &nbsp;·&nbsp; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;·&nbsp; Wall-time: {elapsed:.1f}s &nbsp;·&nbsp; Throughput: {tput} emails/s</p>

<div class="section">
  <h2>📊 Summary</h2>
  <div class="sg">
    <div class="sc"><div class="sv">{stats['total']:,}</div><div class="sl">Total</div></div>
    <div class="sc ag"><div class="sv">{stats['successful']:,}</div><div class="sl">Successful</div></div>
    <div class="sc ar"><div class="sv">{stats['errors']:,}</div><div class="sl">Errors</div></div>
    <div class="sc ay"><div class="sv">{stats['avg_risk_score']}</div><div class="sl">Avg Risk</div></div>
    <div class="sc ao"><div class="sv">{stats['max_risk_score']}</div><div class="sl">Max Risk</div></div>
    <div class="sc ab"><div class="sv">{stats['avg_elapsed_ms']}ms</div><div class="sl">Avg Latency</div></div>
    <div class="sc ap"><div class="sv">{stats['campaigns_found']}</div><div class="sl">Campaigns</div></div>
    <div class="sc ag"><div class="sv">{stats['healing_triggered']}</div><div class="sl">Healings</div></div>
  </div>
</div>
{acc_sec}
<div class="section">
  <h2>📈 Distribution Charts</h2>
  <div class="charts">
    <div class="cw"><p style="font-size:12px;color:#8b949e;margin-bottom:8px">ACTIONS</p><canvas id="aC"></canvas></div>
    <div class="cw"><p style="font-size:12px;color:#8b949e;margin-bottom:8px">SEVERITY</p><canvas id="sC"></canvas></div>
    <div class="cw"><p style="font-size:12px;color:#8b949e;margin-bottom:8px">RISK HISTOGRAM</p><canvas id="rC"></canvas></div>
    <div class="cw"><p style="font-size:12px;color:#8b949e;margin-bottom:8px">TOP COUNTRIES</p><canvas id="cC"></canvas></div>
  </div>
</div>
<div class="section">
  <h2>🚨 Top 25 Highest-Risk Emails</h2>
  <table><thead><tr><th>File</th><th>Risk</th><th>Severity</th><th>Action</th><th>From</th><th>Country</th><th>SPF</th><th>DKIM</th><th>DMARC</th></tr></thead>
  <tbody>{rows}</tbody></table>
</div>
<script>
const G={{responsive:true,plugins:{{legend:{{labels:{{color:'#c9d1d9',font:{{size:11}}}}}}}},scales:{{x:{{ticks:{{color:'#8b949e'}},grid:{{color:'#21262d'}}}},y:{{ticks:{{color:'#8b949e'}},grid:{{color:'#21262d'}}}}}}}};
new Chart(document.getElementById('aC'),{{type:'doughnut',data:{{labels:{action_labels},datasets:[{{data:{action_values},backgroundColor:['#3fb950','#d29922','#f85149','#58a6ff','#bc8cff'],borderWidth:0}}]}},options:{{plugins:G.plugins}}}});
new Chart(document.getElementById('sC'),{{type:'bar',data:{{labels:{sev_labels},datasets:[{{data:{sev_values},backgroundColor:{sev_colors},borderRadius:4}}]}},options:{{...G,plugins:{{...G.plugins,legend:{{display:false}}}}}}}});
new Chart(document.getElementById('rC'),{{type:'bar',data:{{labels:{risk_labels},datasets:[{{label:'Emails',data:{risk_values},backgroundColor:'#58a6ff88',borderColor:'#58a6ff',borderWidth:1,borderRadius:3}}]}},options:G}});
new Chart(document.getElementById('cC'),{{type:'bar',data:{{labels:{ctr_labels},datasets:[{{label:'Emails',data:{ctr_values},backgroundColor:'#bc8cff88',borderColor:'#bc8cff',borderWidth:1,borderRadius:3}}]}},options:{{...G,indexAxis:'y'}}}});
</script></body></html>"""
    path.write_text(html, encoding="utf-8")


# ── Main async runner ──────────────────────────────────────────────────────────
async def run(args: argparse.Namespace) -> None:
    root = Path(args.dir)
    if not root.exists():
        print(f"[ERROR] Directory not found: {root}"); sys.exit(1)

    print(f"\n{'═'*58}\n  🛡️  SENTINEL BULK TESTER  v{VERSION}\n{'═'*58}")
    print(f"  📂 Dir     : {root}")
    print(f"  🌐 API     : {args.url}")
    print(f"  👷 Workers : {args.workers}\n{'═'*58}\n")

    print("🔍 Collecting emails...")
    files = collect_emails(root)
    if not files:
        print("[ERROR] No .eml files found."); sys.exit(1)

    total   = len(files)
    labeled = sum(1 for f in files if infer_label(f))
    print(f"  ✅ {total:,} files found  ({labeled:,} with ground truth labels)")

    run_id  = datetime.now().strftime("run_%Y%m%d_%H%M%S")
    out_dir = Path(args.output) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    live_csv = out_dir / "results_live.csv"
    print(f"  📁 Output  : {out_dir}\n")

    # Ping the API
    print("🔗 Checking API...")
    try:
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{args.url}/", timeout=5.0); r.raise_for_status()
            info = r.json()
            print(f"  ✅ {info.get('system','Sentinel')} — {info.get('status','OK')}\n")
    except Exception as e:
        print(f"  ❌ Cannot reach {args.url}: {e}\n     Start backend:  uvicorn app.main:app --reload")
        sys.exit(1)

    # Run concurrent analysis
    semaphore = asyncio.Semaphore(args.workers)
    results: List[Dict[str, Any]] = []
    wall_start = time.perf_counter()

    transport = httpx.AsyncHTTPTransport(retries=2)
    limits    = httpx.Limits(max_connections=args.workers + 4, max_keepalive_connections=args.workers)

    with open(live_csv, "w", newline="", encoding="utf-8") as lf:
        writer = csv.DictWriter(lf, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()

        async with httpx.AsyncClient(transport=transport, limits=limits) as client:
            tasks = [analyze_one(client, fp, args.url, args.user_id, semaphore) for fp in files]

            if TQDM_AVAILABLE:
                pbar = tqdm(total=total, desc="Analyzing", unit="email", colour="cyan",
                            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]")

            done = 0
            for coro in asyncio.as_completed(tasks):
                res = await coro
                results.append(res)
                writer.writerow(res)
                done += 1

                if TQDM_AVAILABLE:
                    pbar.set_postfix_str(
                        f"{res.get('recommended_action','?')} risk={res.get('risk_score','?')}",
                        refresh=False)
                    pbar.update(1)
                else:
                    simple_bar(done, total, "Analyzing ")

                if done % SAVE_EVERY == 0:
                    lf.flush()

        if TQDM_AVAILABLE:
            pbar.close()

    elapsed = time.perf_counter() - wall_start
    print(f"\n\n✅ Finished {total:,} emails in {elapsed:.1f}s  ({round(total/elapsed,1)} emails/s)\n")

    print("📝 Generating reports...")
    stats = compute_stats(results)
    write_csv(results, out_dir / "results.csv")
    write_json(results, stats, out_dir / "results.json")
    write_html(results, stats, out_dir / "report.html", run_id, elapsed)

    # Console summary
    print(f"\n{'═'*58}")
    print(f"  📊 RESULTS SUMMARY")
    print(f"{'═'*58}")
    print(f"  Total      : {stats['total']:>8,}")
    print(f"  Successful : {stats['successful']:>8,}")
    print(f"  Errors     : {stats['errors']:>8,}  ({stats['error_rate']}%)")
    print(f"  Avg risk   : {stats['avg_risk_score']:>8}")
    print(f"  Max risk   : {stats['max_risk_score']:>8}")
    print(f"  Avg ms     : {stats['avg_elapsed_ms']:>8} ms")
    print(f"  Campaigns  : {stats['campaigns_found']:>8}")
    print(f"  Healings   : {stats['healing_triggered']:>8}")
    print(f"\n  Actions:")
    for action, cnt in stats["action_counts"].items():
        pct = round(cnt / stats["successful"] * 100, 1) if stats["successful"] else 0
        print(f"    {action:<14} {cnt:>7,}  ({pct}%)")
    if acc := stats.get("accuracy"):
        print(f"\n  Accuracy (labeled):")
        print(f"    Precision {acc['precision']*100:.1f}%  Recall {acc['recall']*100:.1f}%  F1 {acc['f1_score']*100:.1f}%  Accuracy {acc['accuracy']*100:.1f}%")
    if stats["error_types"]:
        print(f"\n  Error types:")
        for e, c in stats["error_types"].items():
            print(f"    {str(e):<25} {c}")
    print(f"\n{'═'*58}")
    print(f"  📄 CSV    → {out_dir}/results.csv")
    print(f"  📄 JSON   → {out_dir}/results.json")
    print(f"  🌐 HTML   → {out_dir}/report.html")
    print(f"  🔄 Live   → {out_dir}/results_live.csv")
    print(f"{'═'*58}\n")


def main() -> None:
    p = argparse.ArgumentParser(
        description="Sentinel Bulk Tester — analyze thousands of .eml files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--dir",     "-d", required=True, help="Root directory of .eml files")
    p.add_argument("--url",     "-u", default=DEFAULT_URL,  help=f"API base URL (default: {DEFAULT_URL})")
    p.add_argument("--workers", "-w", type=int, default=DEFAULT_WORKERS, help=f"Concurrent workers (default: {DEFAULT_WORKERS})")
    p.add_argument("--user-id", dest="user_id", default="bulk_tester", help="User ID tag")
    p.add_argument("--output",  "-o", default="results", help="Output parent directory (default: ./results)")
    p.add_argument("--version", action="version", version=f"Sentinel Bulk Tester v{VERSION}")
    asyncio.run(run(p.parse_args()))


if __name__ == "__main__":
    main()
