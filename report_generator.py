import html,json
def make_html_report(r):
 rows=''.join(f"<tr><td>{html.escape(str(x['severity']))}</td><td>{html.escape(str(x['finding']))}</td><td>{html.escape(str(x['evidence']))}</td><td>{x['priority']}</td></tr>" for x in r['findings'])
 rec=''.join(f'<li>{html.escape(str(x))}</li>' for x in r['recommendations'])
 return f'''<!doctype html><html><head><meta charset="utf-8"><title>SecureMailScope Report</title><style>body{{font-family:Arial;margin:40px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px}}pre{{background:#f5f5f5;padding:12px}}</style></head><body><h1>SecureMailScope</h1><p><b>Risk:</b> {r['summary']['risk_score']}/100 — {r['summary']['risk_level']}</p><h2>Findings</h2><table><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Priority</th></tr>{rows}</table><h2>Recommendations</h2><ul>{rec}</ul><h2>JSON Evidence</h2><pre>{html.escape(json.dumps(r,indent=2,default=str))}</pre></body></html>'''
