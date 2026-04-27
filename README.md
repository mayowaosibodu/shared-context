# Shared Context Across Subtasks: An Approach to Protect Agents Against Malicious Objectives Split Into 'Harmless-Seeming' Subtasks

This project provides a framework for testing whether providing stateful, shared context to an AI agent improves its ability to detect and refuse multi-step 'harmless-seeming' tasks which sum to a malicious over-arching objective, while preserving its ability to perform benign tasks. [Blog Post](https://forum.effectivealtruism.org/posts/bRf6ZFrm78ecdzLHA/re-anthropic-chinese-cyber-attack-how-do-we-protect-open)

It compares a stateless "Control" agent against an "Experimental" agent that is given a memory of its past actions and inferred intents.

## Features

-   Stateful vs. Stateless agent comparison.
-   A benchmark composed of multi-step "chains" of both malicious and benign prompts.
-   Automated analysis of results to compare agent performance.
-   Automatic resume of interrupted benchmark runs.

## Setup Instructions

1.  **Clone the Repository**
    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```

2.  **Create and Activate Virtual Environment**
    ```bash
    python3 -m venv env
    source env/bin/activate
    ```

3.  **Install Dependencies**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set Up API Key**
    Create a file named `.env` in the root of the project and add your OpenAI API key to it.
    ```bash
    echo "OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" > .env
    ```
    *Replace `sk-xxxxxxxx...` with your actual API key.*

## Running the Benchmark

To run the full benchmark for both the control and experimental agents, use the following command:

```bash
python run_benchmark.py 2>&1 | tee -a run_logs/run.log
```

This command will:
-   Execute the benchmark.
-   Print the live output to your console.
-   Append a complete log of the run (including errors) to `run_logs/run.log`.

### Resuming an Interrupted Run

The benchmark script automatically detects and skips any chains that have already been fully completed.

-   **To resume a run**, simply execute the same command again. The script will pick up where it left off, re-running any chains that were only partially completed.

### Starting a Fresh Run

-   **To start a completely fresh run**, you must clear the contents of the `run_logs/` directory before running the script.
    ```bash
    rm -rf run_logs/*
    ```

## Analyzing Results

After a benchmark run is complete, you can generate a summary table comparing the performance of the two agents.

```bash
python analyze_results.py
```

This script parses the log files in the `run_logs/` directory and prints a comparison table showing how each agent performed on the malicious and benign chains.
