import json
import textwrap
from dataclasses import dataclass
from typing import List, Dict, Optional

import requests
import streamlit as st
from PIL import Image

# Hard-coded endpoint for the self-hosted LLM
LLM_ENDPOINT = "http://localhost:11434/v1/chat/completions"


@dataclass
class ThreatPattern:
    title: str
    description: str
    keywords: List[str]


THREAT_PATTERNS: List[ThreatPattern] = [
    ThreatPattern(
        title="Authentication & Identity",
        description=(
            "Ensure identity providers, session tokens, and MFA flows are protected. "
            "Look for weak JWT validation, token leakage, replay risks, and inadequate claims handling."
        ),
        keywords=["auth", "jwt", "oauth", "sso", "identity", "login", "mfa"],
    ),
    ThreatPattern(
        title="Data & Storage",
        description=(
            "Data at rest and in transit must be encrypted with key rotation and secrets management. "
            "Check for missing encryption, stale backups, exposed object storage, and weak KMS policies."
        ),
        keywords=["database", "s3", "storage", "bucket", "kms", "backup", "encryption"],
    ),
    ThreatPattern(
        title="Networking & APIs",
        description=(
            "APIs, gateways, and service mesh configurations need strict authentication, rate limiting, and monitoring. "
            "Consider SSRF, path traversal, injection, and weak service discovery controls."
        ),
        keywords=["api", "gateway", "grpc", "service", "mesh", "ingress", "proxy"],
    ),
    ThreatPattern(
        title="Observability & Ops",
        description=(
            "Logging, monitoring, and deployment pipelines must preserve integrity. "
            "Watch for unsigned artifacts, inadequate audit logs, and over-privileged CI/CD runners."
        ),
        keywords=["log", "monitor", "cicd", "pipeline", "deploy", "runner", "observability"],
    ),
    ThreatPattern(
        title="Client & UX",
        description=(
            "Front-end surfaces need protection against spoofing, clickjacking, and malicious input. "
            "Check CSP, anti-CSRF tokens, and secure cookie handling."
        ),
        keywords=["web", "browser", "spa", "client", "cookie", "csrf", "csp"],
    ),
]


@dataclass
class RAGContext:
    architecture_summary: str
    patterns: List[ThreatPattern]
    diagram_insights: Optional[str] = None


def parse_uploaded_diagram(uploaded_file) -> Optional[str]:
    """Extract lightweight metadata from the uploaded diagram to ground the prompt."""
    if uploaded_file is None:
        return None

    try:
        image = Image.open(uploaded_file)
        width, height = image.size
        mode = image.mode
        format_hint = image.format or "unknown"
        return (
            f"Architecture diagram uploaded (format={format_hint}, mode={mode}, "
            f"width={width}px, height={height}px). "
            "Use this as a visual reference even though textual extraction is limited."
        )
    except Exception:
        return "Architecture diagram uploaded, but automatic parsing failed; rely on textual description."


def retrieve_patterns(text: str) -> List[ThreatPattern]:
    lowered = text.lower()
    matches: List[ThreatPattern] = []
    for pattern in THREAT_PATTERNS:
        if any(keyword in lowered for keyword in pattern.keywords):
            matches.append(pattern)
    return matches or THREAT_PATTERNS[:3]


def build_rag_context(architecture_text: str, diagram_note: Optional[str]) -> RAGContext:
    summary = textwrap.shorten(architecture_text.strip(), width=600, placeholder=" ...")
    patterns = retrieve_patterns(architecture_text)
    return RAGContext(architecture_summary=summary, patterns=patterns, diagram_insights=diagram_note)


def format_patterns(patterns: List[ThreatPattern]) -> str:
    lines = ["Relevant threat patterns and controls:"]
    for pattern in patterns:
        lines.append(f"- **{pattern.title}**: {pattern.description}")
    return "\n".join(lines)


def call_llm(messages: List[Dict[str, str]], model: str = "gpt-4o-mini") -> str:
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.3,
    }
    try:
        response = requests.post(LLM_ENDPOINT, json=payload, timeout=60)
        response.raise_for_status()
        data = response.json()
        return data.get("choices", [{}])[0].get("message", {}).get("content", "")
    except requests.RequestException as exc:
        return f"Error contacting LLM endpoint: {exc}"
    except (json.JSONDecodeError, KeyError):
        return "Unexpected response from LLM endpoint."


def build_prompt(user_prompt: str, architecture_text: str, rag_context: RAGContext) -> List[Dict[str, str]]:
    context_parts = [
        "You are a security engineer generating a STRIDE-based threat model.",
        "Follow the structure used by stridegpt.streamlit.app, returning rich markdown with headings",
        "for Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.",
        "For each category include threats, affected assets/flows, mitigations, and relevant controls.",
    ]

    if rag_context.diagram_insights:
        context_parts.append(f"Diagram context: {rag_context.diagram_insights}")

    context_parts.append(f"Architecture summary: {rag_context.architecture_summary}")
    context_parts.append(format_patterns(rag_context.patterns))

    user_content = f"User intent: {user_prompt}\n\nArchitecture/context details:\n{architecture_text}"

    return [
        {"role": "system", "content": "\n".join(context_parts)},
        {"role": "user", "content": user_content},
    ]


def main():
    st.set_page_config(page_title="STRIDE Threat Modeller", page_icon="🛡️", layout="wide")
    st.title("STRIDE Threat Model Generator")
    st.caption(
        "Provide a prompt and architecture context (diagram or text). "
        "The assistant uses RAG over security patterns to produce a full STRIDE analysis."
    )

    with st.sidebar:
        st.header("Context Inputs")
        user_prompt = st.text_input("Prompt", "Generate a detailed threat model for this system")
        architecture_text = st.text_area(
            "Architecture / Context (text)",
            placeholder="Describe components, data flows, identities, and trust boundaries...",
            height=220,
        )
        uploaded_diagram = st.file_uploader("Architecture Diagram (optional)", type=["png", "jpg", "jpeg", "webp"])

        st.markdown("**LLM endpoint**: Hard-coded to the self-hosted API.")

        generate = st.button("Generate Threat Model", type="primary")

    if generate:
        if not user_prompt.strip():
            st.error("Please provide a prompt.")
            return

        diagram_note = parse_uploaded_diagram(uploaded_diagram)
        rag_context = build_rag_context(architecture_text or "No architecture provided.", diagram_note)

        st.subheader("Enriched Context")
        st.markdown(f"**Architecture summary:** {rag_context.architecture_summary or 'N/A'}")
        if rag_context.diagram_insights:
            st.markdown(f"**Diagram:** {rag_context.diagram_insights}")
        st.markdown(format_patterns(rag_context.patterns))

        messages = build_prompt(user_prompt, architecture_text, rag_context)
        st.subheader("Threat Model")
        with st.spinner("Calling local LLM and assembling STRIDE model..."):
            result = call_llm(messages)

        st.markdown(result)

    st.markdown(
        "---\nThis app uses a local LLM endpoint and lightweight retrieval of security patterns "
        "to guide STRIDE threat modelling."
    )


if __name__ == "__main__":
    main()
