# SecureMailScope MVP

## Run
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
streamlit run app.py

The MVP accepts PCAP/PCAPNG, identifies email protocols by TCP service ports, searches visible payloads for STARTTLS/STLS, recognizes TLS record versions where visible, provides evidence-aware risk findings, and exports JSON/HTML. Missing evidence is reported as Not Available. Demo mode is clearly labeled and is not real PCAP evidence.
