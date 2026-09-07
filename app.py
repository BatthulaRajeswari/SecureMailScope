import streamlit as st
import json
import pandas as pd
import plotly.express as px
from datetime import datetime

from analyzer import analyze_pcap, demo_result
from report_generator import make_html_report


# -------------------------------------------------
# PAGE SETTINGS
# -------------------------------------------------

st.set_page_config(
    page_title="SecureMailScope",
    page_icon="🔐",
    layout="wide"
)


# -------------------------------------------------
# TITLE
# -------------------------------------------------

st.title("🔐 SecureMailScope")

st.write(
    "AI-assisted security analysis for email traffic. "
    "Detects weak TLS, certificate problems and weak encryption."
)

st.divider()


# -------------------------------------------------
# SIDEBAR
# -------------------------------------------------

st.sidebar.header("📂 Upload Traffic")

uploaded_file = st.sidebar.file_uploader(
    "Upload PCAP / PCAPNG file",
    type=["pcap", "pcapng"]
)

demo_mode = st.sidebar.checkbox(
    "Use Demo Data",
    value=True
)

analyze = st.sidebar.button(
    "🚀 Analyze Traffic",
    use_container_width=True
)


# -------------------------------------------------
# ANALYZE
# -------------------------------------------------

if analyze:

    try:

        if uploaded_file:

            with st.spinner("Analyzing network traffic..."):

                result = analyze_pcap(
                    uploaded_file.getvalue(),
                    uploaded_file.name
                )

            st.session_state["result"] = result
            st.session_state["source"] = uploaded_file.name

        elif demo_mode:

            with st.spinner("Loading demo data..."):

                result = demo_result()

            st.session_state["result"] = result
            st.session_state["source"] = "Demo Data"

        else:

            st.warning(
                "Please upload a PCAP file or enable Demo Data."
            )

    except Exception as e:

        st.error(f"Analysis failed: {e}")


# -------------------------------------------------
# GET RESULT
# -------------------------------------------------

result = st.session_state.get("result")


if not result:

    st.info(
        "👈 Upload a PCAP file or use Demo Data, "
        "then click Analyze Traffic."
    )

    st.stop()


# -------------------------------------------------
# DATA
# -------------------------------------------------

summary = result.get("summary", {})

risk_score = summary.get("risk_score", 0)

risk_level = summary.get(
    "risk_level",
    "UNKNOWN"
)

protocols = summary.get(
    "protocols",
    []
)

sessions = summary.get(
    "sessions",
    0
)

findings = result.get(
    "findings",
    []
)


# -------------------------------------------------
# BASIC INFORMATION
# -------------------------------------------------

st.subheader("📄 Analysis Information")

col1, col2, col3 = st.columns(3)

with col1:
    st.write("**Source:**")
    st.write(st.session_state.get("source", "Unknown"))

with col2:
    st.write("**Analysis Time:**")
    st.write(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

with col3:
    st.write("**Total Findings:**")
    st.write(len(findings))


st.divider()


# -------------------------------------------------
# SECURITY SUMMARY
# -------------------------------------------------

st.subheader("🛡️ Security Summary")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "Risk Score",
        f"{risk_score}/100"
    )

with col2:
    st.metric(
        "Risk Level",
        risk_level
    )

with col3:
    st.metric(
        "TCP Sessions",
        sessions
    )

with col4:
    st.metric(
        "Findings",
        len(findings)
    )


# -------------------------------------------------
# RISK MESSAGE
# -------------------------------------------------

if risk_level == "HIGH":

    st.error(
        "🔴 HIGH RISK: Serious security problems were detected."
    )

elif risk_level == "MEDIUM":

    st.warning(
        "🟠 MEDIUM RISK: Some security problems were detected."
    )

else:

    st.success(
        "🟢 LOW RISK: No major security problems detected."
    )


st.divider()


# -------------------------------------------------
# TABS
# -------------------------------------------------

tab1, tab2, tab3, tab4, tab5 = st.tabs(
    [
        "📊 Overview",
        "📡 Protocols",
        "🔐 Cryptography",
        "⚠️ Findings",
        "📄 Reports"
    ]
)


# =================================================
# TAB 1 - OVERVIEW
# =================================================

with tab1:

    st.subheader("📊 Security Overview")

    st.write(
        "The overall security score of the analyzed email traffic."
    )

    st.progress(
        min(risk_score, 100) / 100
    )

    st.write(
        f"**Risk Score:** {risk_score}/100"
    )

    st.write(
        f"**Risk Level:** {risk_level}"
    )

    # ---- Risk pie chart (by findings severity) ----

    st.write("### ⚠️ Risk Breakdown")

    severity_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    for finding in findings:
        severity = str(finding.get("severity", "INFO")).upper()
        if severity not in severity_counts:
            severity = "INFO"
        severity_counts[severity] += 1

    risk_data = pd.DataFrame(
        {
            "Severity": list(severity_counts.keys()),
            "Count": list(severity_counts.values())
        }
    )

    risk_data = risk_data[risk_data["Count"] > 0]

    if not risk_data.empty:

        fig = px.pie(
            risk_data,
            names="Severity",
            values="Count",
            title="Findings by Severity",
            hole=0.35
        )

        fig.update_traces(
            textposition="inside",
            textinfo="label+percent+value"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    else:

        st.info("No risk data available.")

    # ---- Risk score pie chart ----

    st.write("### 🎯 Risk Score Breakdown")

    score_value = max(0, min(int(risk_score), 100))

    score_data = pd.DataFrame(
        {
            "Type": ["Risk Score", "Remaining"],
            "Value": [score_value, 100 - score_value]
        }
    )

    score_fig = px.pie(
        score_data,
        names="Type",
        values="Value",
        title="Risk Score (out of 100)",
        hole=0.35,
        color="Type",
        color_discrete_map={
            "Risk Score": "#e74c3c",
            "Remaining": "#2ecc71"
        }
    )

    score_fig.update_traces(
        textposition="inside",
        textinfo="label+percent"
    )

    st.plotly_chart(
        score_fig,
        use_container_width=True
    )

    st.write("### 📧 Detected Protocols")

    if protocols:

        for protocol in protocols:

            st.write(f"• {protocol}")

    else:

        st.write("No email protocols detected.")


# =================================================
# TAB 2 - PROTOCOLS
# =================================================

with tab2:

    st.subheader("📡 Email Protocols")

    protocol_analysis = result.get(
        "protocol_analysis",
        {}
    )

    detected = protocol_analysis.get(
        "protocols_detected",
        []
    )

    session_summary = protocol_analysis.get(
        "session_summary",
        []
    )

    if detected:

        for protocol in detected:

            count = sum(
                1
                for session in session_summary
                if session.get("protocol") == protocol
            )

            st.write(
                f"### {protocol}"
            )

            st.info(
                f"{count} TCP session(s) detected"
            )

    else:

        st.warning(
            "No SMTP, IMAP or POP3 traffic detected."
        )


# =================================================
# TAB 3 - CRYPTOGRAPHY
# =================================================

with tab3:

    st.subheader("🔐 Cryptographic Analysis")

    crypto = result.get(
        "crypto",
        {}
    )

    col1, col2 = st.columns(2)

    with col1:

        st.write("### 🔒 TLS Version")

        tls_versions = crypto.get(
            "tls_versions",
            []
        )

        if tls_versions:

            for tls in tls_versions:
                st.write(f"• {tls}")

        else:

            st.write("Not Available")


    with col2:

        st.write("### 🔑 Cipher Suite")

        ciphers = crypto.get(
            "cipher_suites",
            []
        )

        if ciphers:

            for cipher in ciphers:
                st.write(f"• {cipher}")

        else:

            st.write("Not Available")


    st.write("### 🛡️ Forward Secrecy")

    st.info(
        crypto.get(
            "forward_secrecy",
            "Not Available"
        )
    )


    st.write("### 📜 Certificate")

    certificate = crypto.get(
        "x509_certificate",
        {}
    )

    if certificate:

        for key, value in certificate.items():

            st.write(
                f"**{key}:** {value}"
            )

    else:

        st.warning(
            "Certificate information not available."
        )


# =================================================
# TAB 4 - FINDINGS
# =================================================

with tab4:

    st.subheader("⚠️ Security Findings")

    if not findings:

        st.success(
            "✅ No security problems detected."
        )

    else:

        for finding in findings:

            severity = finding.get(
                "severity",
                "INFO"
            )

            name = finding.get(
                "finding",
                "Unknown Finding"
            )

            evidence = finding.get(
                "evidence",
                "Not Available"
            )

            priority = finding.get(
                "priority",
                "Not Available"
            )


            if severity == "HIGH":

                st.error(
                    f"🔴 HIGH - {name}"
                )

            elif severity == "MEDIUM":

                st.warning(
                    f"🟠 MEDIUM - {name}"
                )

            elif severity == "LOW":

                st.success(
                    f"🟢 LOW - {name}"
                )

            else:

                st.info(
                    f"🔵 INFO - {name}"
                )


            st.write(
                f"**Evidence:** {evidence}"
            )

            st.write(
                f"**Priority:** {priority}"
            )

            st.divider()


    # Recommendations

    st.subheader("💡 Recommendations")

    recommendations = result.get(
        "recommendations",
        []
    )

    if recommendations:

        for i, recommendation in enumerate(
            recommendations,
            1
        ):

            st.write(
                f"**{i}.** {recommendation}"
            )

    else:

        st.write(
            "No specific recommendations."
        )


# =================================================
# TAB 5 - REPORTS
# =================================================

with tab5:

    st.subheader("📄 Download Reports")

    # JSON

    json_report = json.dumps(
        result,
        indent=2,
        default=str
    )

    st.download_button(
        "⬇️ Download JSON Report",
        json_report,
        "securemailscope_report.json",
        "application/json",
        use_container_width=True
    )


    # HTML

    html_report = make_html_report(
        result
    )

    st.download_button(
        "🌐 Download HTML Report",
        html_report,
        "securemailscope_report.html",
        "text/html",
        use_container_width=True
    )


    st.info(
        "Open the HTML report in your browser. "
        "You can print it and save it as PDF."
    )


# -------------------------------------------------
# FOOTER
# -------------------------------------------------

st.divider()

st.caption(
    "🔐 SecureMailScope | Passive Email Cryptographic Security Analysis"
)
