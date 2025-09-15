#!/usr/bin/env python3
"""
generate_status_html.py

Crea un report HTML con lo stato di validazione dei metadata SPID.
"""

import sys
import os
import html
from datetime import datetime

def load_results(results_file):
    results = []
    if not os.path.exists(results_file):
        return results
    with open(results_file, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(";", 2)
            if len(parts) == 3:
                results.append({"file": parts[0], "status": parts[1], "details": parts[2]})
    return results

def generate_html(results, output_file):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    rows = ""
    for r in results:
        color = "green" if r["status"] == "OK" else "red"
        rows += f"<tr><td>{html.escape(r['file'])}</td><td style='color:{color}'>{r['status']}</td><td>{html.escape(r['details'])}</td></tr>\n"

    html_content = f"""<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="UTF-8">
  <title>SPID Metadata Validation Status</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2em; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ccc; padding: 8px; }}
    th {{ background-color: #f2f2f2; }}
  </style>
</head>
<body>
  <h1>SPID Metadata Validation Status</h1>
  <p>Ultimo aggiornamento: {now}</p>
  <table>
    <tr><th>File</th><th>Stato</th><th>Dettagli</th></tr>
    {rows}
  </table>
</body>
</html>
"""
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)

def main():
    if len(sys.argv) != 3:
        print("Uso: generate_status_html.py <results.txt> <output.html>")
        sys.exit(1)
    results = load_results(sys.argv[1])
    generate_html(results, sys.argv[2])

if __name__ == "__main__":
    main()
