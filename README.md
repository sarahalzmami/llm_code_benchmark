# Benchmark for LLM Code Generation

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)]()
[![FastAPI](https://img.shields.io/badge/FastAPI-🚀-green.svg)]()

A modular, extensible benchmark for evaluating open-source LLMs on source code generation tasks.  
Outputs are aggregated into CSV/JSONL and visualized via a FastAPI dashboard.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Creative Aspects](#creative-aspects)
- [Quickstart (One-Click Run)](#quickstart-one-click-run)
- [Tech Stack Choices](#tech-stack-choices)
- [Future Extensions](#future-extensions)

---

# Overview

This benchmark evaluates open-source LLMs on source code generation tasks:

- **Frontend Development**: React components, UI logic, styling, and user interactions
- **Backend Development**: API endpoints, database operations, business logic, and server-side functionality
- **Test Case Generation**: Unit tests, integration tests, and end-to-end testing scenarios

It supports two modes:

- **LLM-as-Judge (via DSPy)**: Candidate models generate code, then an evaluation pipeline built with DSPy applies a structured rubric and uses a strong model to judge the outputs.
- **Wrapper Mode**: Extend with external benchmarks (e.g., BaXBench) or any command-driven suite.

Outputs are saved as CSV + JSONL files, then visualized in a FastAPI web app.

---

# Architecture

The benchmark is designed with modularity and extensibility at its core, combining two complementary approaches:

1. **LLM-as-Judge Mode (via DSPy)**

   - Candidate models solve code-generation challenges (frontend, testing).
   - Outputs are evaluated by a stronger model orchestrated through DSPy, which enforces structured rubrics, ensures consistency with self-consistency voting, and produces transparent rationales.
   - This enables fine-grained evaluation of functionality, code quality, security, performance, accessibility, and error handling—going beyond simple pass/fail tests.

2. **Wrapper Mode (Extending Existing Benchmarks)**
   - A wrapper layer enables running external or command-driven benchmarks (e.g., BaXBench, HumanEval, MBPP, or custom CLI tasks).
   - The system integrates seamlessly with existing benchmarks instead of reinventing the wheel.
   - Results from external runs are normalized into the same CSV/JSONL schema, ensuring a unified dashboard view.

---

# Creative Aspects

- **Dual Evaluation Strategy**: Combines qualitative judgments (via DSPy) and quantitative metrics (via harness/test runners).
- **Task Modularity**: Each task folder is self-contained (prompt and task definition), making it easy to add new evaluation domains. The LLM-as-Judge evaluates model outputs directly, while external benchmarks bring their own datasets.
- **Model Registry**: Models are defined in the `./sample_models_config` folder, where each model has a JSON file specifying its name, provider URL, benchmarks to run, and configuration options.
- **Unified Results Schema**: Both in-house and external benchmarks feed into the same CSV/JSONL pipeline, simplifying aggregation and visualization.
- **Plug-in External Benchmarks**: Add any CLI- or Python-based benchmark without major re-engineering.

---

# Quickstart (One-Click Run)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run benchmarks from a config folder (JSON files) (NOTE: Populating the models config folder is a prerequisite.)

# Option A (Makefile)
make run CONFIG_DIR=sample_models_config

# Option B (direct)
python3 -m packages.code_score_lib.run sample_models_config

# 3. Launch the results dashboard
uvicorn benchmark_app.main:app --reload
# In .env, set results_path to the CSV path printed after the run
```

---

# Tech Stack Choices

- **Python**
- **FastAPI**: lightweight web API & UI
- **DSPy**: "A declarative framework for building modular AI software."

---

# Future Extensions

- **Built-in Custom Benchmarks**: Host domain-specific benchmarks (e.g., enterprise APIs, fintech workflows, accessibility-first frontends).
- **Parallel & Background Execution**: Extend beyond sequential runs with parallel task dispatch and background workers to optimize runtime.
- **Scalability**: While initial runs are resource-limited, the architecture naturally scales to GPU clusters or cloud deployments.
