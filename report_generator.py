def generate_html_report(findings, output_file="report.html"):
    severity_colors = {
        "CRITICAL": "#ff4d4d",
        "HIGH": "#ff944d",
        "MEDIUM": "#ffd24d",
        "LOW": "#4da6ff",
    }

    html = f"""
    <html>
    <head>
        <title>AAVS Scan Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background: #0f172a;
                color: #e2e8f0;
                margin: 0;
                padding: 20px;
            }}
            h1 {{
                text-align: center;
                color: #38bdf8;
            }}
            .card {{
                background: #1e293b;
                padding: 15px;
                margin: 15px 0;
                border-radius: 10px;
                box-shadow: 0 0 10px rgba(0,0,0,0.5);
            }}
            .severity {{
                font-weight: bold;
                padding: 5px 10px;
                border-radius: 5px;
                display: inline-block;
                margin-bottom: 10px;
            }}
            .endpoint {{
                font-size: 18px;
                color: #22c55e;
            }}
            .method {{
                font-weight: bold;
                color: #facc15;
            }}
            pre {{
                background: #020617;
                padding: 10px;
                border-radius: 5px;
                overflow-x: auto;
                font-size: 12px;
            }}
        </style>
    </head>
    <body>

    <h1>🚨 AAVS Vulnerability Report</h1>
    <h3>Total Findings: {len(findings)}</h3>
    """

    for f in findings:
        severity = f.get("severity", "LOW").upper()
        color = severity_colors.get(severity, "#999")

        html += f"""
        <div class="card">
            <div class="severity" style="background:{color};">
                {severity}
            </div>

            <div class="endpoint">
                {f.get("method")} {f.get("endpoint")}
            </div>

            <p><b>Issue:</b> {f.get("reason")}</p>

            <p><b>Payload:</b></p>
            <pre>{f.get("payload")}</pre>

            <p><b>Response:</b></p>
            <pre>{f.get("response")}</pre>
        </div>
        """

    html += """
    </body>
    </html>
    """

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n[+] Report saved to {output_file}")