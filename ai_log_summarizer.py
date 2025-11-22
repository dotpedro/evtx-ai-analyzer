#!/usr/bin/env python3

import argparse
import os
import json
import datetime
import webbrowser  # <--- ADDED: To open the browser
from typing import List, Dict, Any

from dotenv import load_dotenv
from openai import OpenAI

# Import your local analyzer
from log_analyzer import LogAnalyzer, process_evtx_file

# --- CONFIGURATION ---
load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")

if not api_key:
    raise SystemExit(
        "[ERROR] OPENAI_API_KEY is missing. "
        "Create a .env file with: OPENAI_API_KEY=yourkey"
    )

# Strip newline characters that might exist in the .env file
api_key = api_key.strip()

client = OpenAI(api_key=api_key)

# --- HELPER FUNCTIONS ---

def build_event_snippet(events, max_events=50) -> str:
    """Formats raw events for the AI prompt."""
    lines = []
    for ev in events[:max_events]:
        ts = ev.timestamp.isoformat(" ") if ev.timestamp else "N/A"
        main = f"{ts} | type={ev.event_type} | ip={ev.ip or '-'} | user={ev.username or '-'}"
        
        # Add extra data if available
        interesting = [
            "EventID", "LogonType", "TargetUserName", "SourceAddress", 
            "DestAddress", "DestPort", "ProcessName", "Service Name"
        ]
        extra = [f"{k}={ev.data[k]}" for k in interesting if k in ev.data]
        if extra:
            main += " | " + ", ".join(extra)
        lines.append(main)
    return "\n".join(lines)

def build_alert_snippet(alerts, max_alerts=30) -> str:
    """Formats analyzer alerts for the AI prompt."""
    if not alerts:
        return "No programmatic alerts generated."
    lines = []
    for al in alerts[:max_alerts]:
        ts = al.timestamp.isoformat(" ") if al.timestamp else "N/A"
        lines.append(
            f"{ts} | [{al.severity}] {al.event_type} | "
            f"src={al.source_ip} | user={al.username} | {al.details}"
        )
    return "\n".join(lines)

def call_openai_analysis(events_text: str, alerts_text: str, model: str) -> Dict[str, Any]:
    """
    Sends logs to OpenAI and requests a JSON response containing
    Risk Score, Classification, Timeline, and Summary.
    """
    system_prompt = """
    You are a Tier 3 SOC Analyst. Analyze the provided Windows logs and alerts.
    
    You MUST respond with a valid JSON object containing exactly these keys:
    1. "risk_score": An integer from 0 (safe) to 100 (critical).
    2. "classification": A short string (e.g., "Brute Force", "Lateral Movement", "Reconnaissance", "False Positive").
    3. "timeline_narrative": A chronological story of the attack (Markdown supported).
    4. "executive_summary": A professional summary for management.
    5. "remediation_steps": A list of strings describing how to fix the issue.
    """

    user_prompt = f"""
    === RAW LOGS (Subset) ===
    {events_text}

    === DETECTED ALERTS ===
    {alerts_text}
    """

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            response_format={"type": "json_object"}, # Forces valid JSON
            temperature=0.2
        )
        
        content = response.choices[0].message.content
        return json.loads(content)
    except Exception as e:
        print(f"[!] OpenAI API Error: {e}")
        return {
            "risk_score": 0,
            "classification": "Error",
            "timeline_narrative": "Could not generate timeline due to API error.",
            "executive_summary": f"Analysis failed: {str(e)}",
            "remediation_steps": ["Check API Key", "Check Token Limits"]
        }

# --- HTML GENERATOR ---

def generate_html_report(data: Dict, alerts: List, filename="security_report.html"):
    """
    Generates a 'Sexy SOC-style' Dark Mode HTML report.
    """
    
    # Determine Color based on Score
    score = data.get('risk_score', 0)
    if score < 30:
        score_color = "#00e676" # Green
        score_level = "LOW"
    elif score < 70:
        score_color = "#ffea00" # Yellow
        score_level = "MEDIUM"
    else:
        score_color = "#ff1744" # Red
        score_level = "CRITICAL"

    # Convert Alert objects to HTML Table rows
    alert_rows = ""
    for al in alerts:
        ts = al.timestamp.strftime('%Y-%m-%d %H:%M:%S') if al.timestamp else "N/A"
        alert_rows += f"""
        <tr>
            <td>{ts}</td>
            <td><span class="badge {al.severity.lower()}">{al.severity}</span></td>
            <td>{al.event_type}</td>
            <td>{al.source_ip or '-'}</td>
            <td>{al.username or '-'}</td>
            <td>{al.details}</td>
        </tr>
        """

    # Remediation bullets
    remediation_html = "".join([f"<li>{step}</li>" for step in data.get('remediation_steps', [])])

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>AI Security Analysis Report</title>
        <style>
            :root {{
                --bg-color: #121212;
                --card-bg: #1e1e1e;
                --text-main: #e0e0e0;
                --text-dim: #a0a0a0;
                --accent: {score_color};
                --border: #333;
            }}
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: var(--bg-color); color: var(--text-main); margin: 0; padding: 20px; }}
            .container {{ max-width: 1100px; margin: 0 auto; }}
            
            /* Header & Score */
            .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; border-bottom: 2px solid var(--accent); padding-bottom: 20px; }}
            .title h1 {{ margin: 0; font-size: 24px; text-transform: uppercase; letter-spacing: 2px; }}
            .title span {{ color: var(--accent); font-weight: bold; }}
            
            .score-box {{ text-align: center; background: var(--card-bg); padding: 15px 30px; border-radius: 8px; border: 1px solid var(--accent); }}
            .score-val {{ font-size: 36px; font-weight: bold; color: var(--accent); display: block; }}
            .score-label {{ font-size: 12px; color: var(--text-dim); text-transform: uppercase; }}

            /* Cards */
            .card {{ background-color: var(--card-bg); border-radius: 8px; padding: 20px; margin-bottom: 20px; border: 1px solid var(--border); box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
            .card h2 {{ margin-top: 0; color: var(--accent); font-size: 18px; border-bottom: 1px solid var(--border); padding-bottom: 10px; }}
            
            /* Timeline & Summary */
            .narrative {{ line-height: 1.6; color: #ccc; white-space: pre-wrap; }}
            
            /* Table */
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }}
            th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid var(--border); }}
            th {{ background-color: #252525; color: var(--text-dim); text-transform: uppercase; font-size: 12px; }}
            tr:hover {{ background-color: #2a2a2a; }}
            
            /* Badges */
            .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }}
            .badge.high {{ background-color: rgba(255, 23, 68, 0.2); color: #ff1744; }}
            .badge.medium {{ background-color: rgba(255, 234, 0, 0.2); color: #ffea00; }}
            .badge.low {{ background-color: rgba(0, 230, 118, 0.2); color: #00e676; }}

            /* Classification Tag */
            .tag {{ display: inline-block; background: var(--accent); color: #000; padding: 5px 10px; border-radius: 4px; font-weight: bold; margin-top: 5px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="title">
                    <h1>AI Security <span>Report</span></h1>
                    <div style="margin-top:5px; color: #777;">Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
                </div>
                <div class="score-box">
                    <span class="score-val">{score} / 100</span>
                    <span class="score-label">Risk Score ({score_level})</span>
                </div>
            </div>

            <div class="card">
                <h2>🛡️ Executive Summary</h2>
                <div class="narrative">
                    <strong>Detected Pattern:</strong> <span class="tag">{data.get('classification')}</span><br><br>
                    {data.get('executive_summary')}
                </div>
            </div>

            <div class="card">
                <h2>⏳ Attack Timeline Narrative</h2>
                <div class="narrative">{data.get('timeline_narrative')}</div>
            </div>

            <div class="card">
                <h2>🔧 Recommended Remediation</h2>
                <ul>{remediation_html}</ul>
            </div>

            <div class="card">
                <h2>🚨 Alert Evidence ({len(alerts)})</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Sev</th>
                            <th>Type</th>
                            <th>Source IP</th>
                            <th>User</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {alert_rows}
                    </tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    """
    
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"\n[✔] HTML Report generated successfully: {filename}")
    except Exception as e:
        print(f"[X] Failed to write HTML report: {e}")

# --- MAIN ---

def main():
    parser = argparse.ArgumentParser(description="AI Security Log Summarizer + HTML Report")
    parser.add_argument("--log-file", required=True)
    parser.add_argument("--model", default="gpt-4o")
    parser.add_argument("--output", default="report.html", help="Output HTML filename")
    parser.add_argument("--fail-threshold", type=int, default=5)
    
    args = parser.parse_args()

    log_path = args.log_file
    if not os.path.exists(log_path):
        raise SystemExit(f"[ERROR] Log file not found: {log_path}")

    print(f"[+] Analyzing: {log_path}")
    
    # 1. Run Local Analysis
    analyzer = LogAnalyzer(fail_threshold=args.fail_threshold)
    if log_path.lower().endswith(".evtx"):
        process_evtx_file(log_path, analyzer, max_events=10000)
    else:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                analyzer.process_line(line)

    events = analyzer.events
    alerts = analyzer.analyze()
    
    print(f"[+] Stats: {len(events)} events parsed, {len(alerts)} alerts detected.")

    # 2. Prepare Data for AI
    events_str = build_event_snippet(events, max_events=50)
    alerts_str = build_alert_snippet(alerts, max_alerts=30)

    print("[+] Sending data to OpenAI for Risk Scoring & Classification...")
    
    # 3. Get AI Analysis (JSON)
    ai_results = call_openai_analysis(events_str, alerts_str, args.model)

    # 4. Console Output (Summary)
    print("\n" + "="*40)
    print(f" RISK SCORE: {ai_results.get('risk_score')}/100")
    print(f" PATTERN:    {ai_results.get('classification')}")
    print("="*40)
    
    # 5. Generate HTML Report
    generate_html_report(ai_results, alerts, args.output)

    # 6. Open the report automatically
    report_path = os.path.abspath(args.output)
    print(f"[+] Opening report in browser: {report_path}")
    webbrowser.open(f"file://{report_path}")

if __name__ == "__main__":
    main()