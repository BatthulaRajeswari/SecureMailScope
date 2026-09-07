import io
from datetime import datetime,timezone
from scapy.all import rdpcap,TCP,IP,IPv6,Raw
EMAIL_PORTS={25:'SMTP',465:'SMTP',587:'SMTP',143:'IMAP',993:'IMAP',110:'POP3',995:'POP3'}
TLS_VERSIONS={b'\x03\x01':'TLS 1.0',b'\x03\x02':'TLS 1.1',b'\x03\x03':'TLS 1.2',b'\x03\x04':'TLS 1.3'}
def payload(p): return bytes(p[Raw].load) if Raw in p else b''
def endpoint(p):
    if IP in p:return p[IP].src,p[IP].dst
    if IPv6 in p:return p[IPv6].src,p[IPv6].dst
    return 'Not Available','Not Available'
def analyze_pcap(data,filename='capture.pcap'):
    packets=rdpcap(io.BytesIO(data)); protocols=set(); sessions={}; blob=b''; tls=[]
    for p in packets:
        if TCP not in p: continue
        sp,dp=int(p[TCP].sport),int(p[TCP].dport); proto=EMAIL_PORTS.get(sp) or EMAIL_PORTS.get(dp); src,dst=endpoint(p)
        key=tuple(sorted([(src,sp),(dst,dp)])); sessions.setdefault(key,{'protocol':proto or 'Unknown','packets':0,'bytes':0}); sessions[key]['packets']+=1
        x=payload(p); sessions[key]['bytes']+=len(x); blob+=x
        if proto: protocols.add(proto)
        if len(x)>=5 and x[0] in (20,21,22,23,24) and x[1:3] in TLS_VERSIONS: tls.append(TLS_VERSIONS[x[1:3]])
    text=blob.decode('latin1','ignore').upper(); starts=[x for x in ('STARTTLS','STLS') if x in text]; tls=list(dict.fromkeys(tls)); findings=[]; score=100
    if not protocols: findings.append({'severity':'INFO','finding':'No SMTP/IMAP/POP3 traffic identified','evidence':'No matching TCP service ports observed.','priority':4})
    if any(x in ('TLS 1.0','TLS 1.1') for x in tls): findings.append({'severity':'HIGH','finding':'Deprecated TLS version observed','evidence':', '.join(tls),'priority':1}); score-=30
    if starts: findings.append({'severity':'INFO','finding':'STARTTLS/STLS command observed','evidence':', '.join(starts),'priority':3})
    elif protocols: findings.append({'severity':'MEDIUM','finding':'STARTTLS/STLS not observed in visible payloads','evidence':'Not observed; encrypted-only sessions may hide negotiation details.','priority':2}); score-=10
    if not tls and protocols: findings.append({'severity':'MEDIUM','finding':'TLS version not available from visible evidence','evidence':'No recognizable TLS record header observed.','priority':2}); score-=10
    score=max(0,min(100,score)); level='LOW' if score>=80 else 'MEDIUM' if score>=50 else 'HIGH'; findings.sort(key=lambda x:(x['priority'],x['severity']))
    rec=[]
    if any(x['severity']=='HIGH' for x in findings): rec.append('Disable deprecated TLS versions and require modern TLS configurations.')
    if any('STARTTLS/STLS not observed' in x['finding'] for x in findings): rec.append('Verify secure TLS upgrades and prevent insecure fallback.')
    if any('TLS version not available' in x['finding'] for x in findings): rec.append('Capture the complete TLS handshake when possible for stronger assessment.')
    if not rec: rec.append('Continue monitoring and validate cryptographic settings against current policy.')
    return {'product':'SecureMailScope','generated_at':datetime.now(timezone.utc).isoformat(),'summary':{'risk_score':score,'risk_level':level,'protocols':sorted(protocols),'sessions':len(sessions)},'protocol_analysis':{'pcap_file':filename,'packets_read':len(packets),'protocols_detected':sorted(protocols),'tcp_sessions':len(sessions),'starttls_commands_observed':starts or ['Not Available'],'tls_versions':tls or ['Not Available'],'session_summary':list(sessions.values())},'crypto':{'tls_versions':tls or ['Not Available'],'cipher_suites':['Not Available'],'key_exchange':'Not Available','x509_certificate':{'certificate':'Not Available','validity':'Not Available','expiration':'Not Available','public_key_algorithm':'Not Available','key_length':'Not Available','signature_algorithm':'Not Available','chain_validation':'Not Available'},'forward_secrecy':'Not Available','features':{'starttls_detected':bool(starts),'tls_versions_observed':tls},'assessment_method':'Transparent deterministic rules (MVP); ML plug-in point reserved.'},'findings':findings,'recommendations':rec}
def demo_result():
    r=analyze_pcap(b'', 'DEMO_CAPTURE.pcap')
    r['summary']={'risk_score':82,'risk_level':'LOW','protocols':['SMTP'],'sessions':3}; r['protocol_analysis'].update({'packets_read':1842,'protocols_detected':['SMTP'],'tcp_sessions':3,'starttls_commands_observed':['STARTTLS'],'tls_versions':['TLS 1.2']}); r['crypto'].update({'tls_versions':['TLS 1.2'],'cipher_suites':['ECDHE-RSA-AES256-GCM-SHA384'],'key_exchange':'ECDHE','x509_certificate':{'certificate':'Observed in demo dataset','validity':'Valid in demo dataset','expiration':'Demo value','public_key_algorithm':'RSA','key_length':2048,'signature_algorithm':'SHA256withRSA','chain_validation':'Demo validation result'},'forward_secrecy':'Supported (ECDHE)'}); r['findings']=[{'severity':'INFO','finding':'STARTTLS observed','evidence':'SMTP STARTTLS','priority':3}]; r['recommendations']=['Monitor certificate expiration and chain validity continuously.','Maintain modern TLS with strong cipher suites and forward secrecy.']; return r
