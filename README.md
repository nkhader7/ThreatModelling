# ThreatModelling

A Streamlit application that generates STRIDE-based threat models using a self-hosted LLM endpoint.

## Features
- Accepts a free-form prompt describing the modelling goal.
- Supports either architecture text input or an uploaded diagram (basic metadata is extracted from images).
- Uses lightweight RAG over curated security patterns to enrich the LLM prompt.
- Calls a hard-coded local LLM endpoint to produce a structured STRIDE threat model inspired by [stridegpt.streamlit.app](https://stridegpt.streamlit.app/).

## Running locally
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Ensure your self-hosted LLM chat completion API is reachable at `http://localhost:11434/v1/chat/completions`.
3. Launch Streamlit:
   ```bash
   streamlit run app.py
   ```
4. Open the provided URL, enter your prompt, and supply architecture context (text or diagram) to generate the threat model.
