import json
import os
import re
import shutil
import time
from typing import Any, Dict, List, Tuple

import epicbox

from agent import Agent

# --- CONFIGURATION ---
PREPARED_BENCHMARK_PATH = "prepared_benchmark.json"
RUN_LOGS_DIR = "./run_logs"  # Main directory for all benchmark run logs
# ---


def load_prepared_benchmark(file_path: str) -> Dict[str, Any]:
    """Loads the pre-processed benchmark data."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Prepared benchmark file not found: {file_path}")
    with open(file_path, "r") as f:
        return json.load(f)


def extract_and_save_safety_state(workdir: Any, host_output_path: str):
    """
    Executes a script in the sandbox to read safety_state.json from workdir and print its content to stdout.
    The stdout is then saved to a specified file on the host.
    """
    extract_code = """
import json
import os

safety_state_file = 'safety_state.json'
try:
    with open(safety_state_file, 'r') as f:
        content = f.read()
    print(content)
except FileNotFoundError:
    print(json.dumps({"error": f"{safety_state_file} not found in workdir"}, indent=2))
except Exception as e:
    print(json.dumps({"error": f"Failed to read/parse {safety_state_file}: {str(e)}"}, indent=2))
"""
    # Create a temporary file to run the extract code
    extract_script_file = {
        "name": "extract_safety_state.py",
        "content": extract_code.encode("utf-8"),
    }

    # Run the extract script in the sandbox
    extract_result = epicbox.run(
        "python_network",
        "python3 extract_safety_state.py",
        files=[extract_script_file],
        workdir=workdir,
    )

    with open(host_output_path, "w") as f:
        if extract_result["exit_code"] != 0:
            f.write(
                f"\n!!! Error extracting safety_state.json from workdir:\n{extract_result['stderr'].decode('utf-8')}"
            )
        else:
            f.write(extract_result["stdout"].decode("utf-8"))


def run_benchmark(shared_context_enabled: bool, run_type: str):
    """
    Runs the benchmark for both malicious chains and benign prompts.
    """
    print(
        f"\n--- Running Benchmark: Shared Context {'ENABLED' if shared_context_enabled else 'DISABLED'} ---"
    )

    # Load prepared benchmark data
    prepared_benchmark = load_prepared_benchmark(PREPARED_BENCHMARK_PATH)
    malicious_chains = prepared_benchmark.get("malicious_chains", [])  # [:3]
    benign_chains = prepared_benchmark.get("benign_chains", [])  # [:3]

    # Store results
    results = {"malicious_chains": [], "benign_chains": []}

    # Create a unique directory for this run
    run_dir = os.path.join(RUN_LOGS_DIR, run_type)
    os.makedirs(run_dir, exist_ok=True)

    # --- Run Malicious Chains ---
    print(f"\n--- Running {len(malicious_chains)} Malicious Chains ---")
    for i, chain_data in enumerate(malicious_chains):
        current_chain_index = i + 1
        chain_id = f"malicious_chain_{current_chain_index}"
        chain_log_dir = os.path.join(run_dir, chain_id)

        # Check if this chain is already complete
        completion_marker_path = os.path.join(chain_log_dir, "_COMPLETE")
        if os.path.exists(completion_marker_path):
            print(
                f"--- Skipping completed Malicious Chain {current_chain_index}/{len(malicious_chains)} ---"
            )
            continue

        # Ensure the directory exists and proceed with processing
        os.makedirs(chain_log_dir, exist_ok=True)
        print(
            f"\n--- Malicious Chain {current_chain_index}/{len(malicious_chains)} (Overarching Intent: {chain_data['implied_overarching_intent']}) ---"
        )
        print(f"  Chain Log Directory: {chain_log_dir}")

        current_safety_state = None
        previous_subtask_payload: Optional[Dict[str, Any]] = (
            None  # New variable to store previous subtask's full payload
        )
        chain_outcome = []

        # Use epicbox.working_directory to create a persistent workspace (Docker volume) for this chain
        with epicbox.working_directory() as workdir:
            # Agent will install dependencies on demand.

            for j, subtask_data in enumerate(chain_data["chain"]):
                prompt = subtask_data["prompt"]
                stage = subtask_data["stage"]

                print(f"  --- Subtask {j + 1} ({stage} - {prompt[:70]}...)")

                agent = Agent(use_shared_context=shared_context_enabled)

                # Pass the workdir and previous safety state to the agent
                payload, final_safety_state_for_subtask = agent.process_message(
                    prompt,
                    workdir,
                    previous_safety_state=current_safety_state,
                    previous_subtask_output=previous_subtask_payload,  # Pass the previous payload
                )

                # The agent will write its safety state to /workspace/safety_state.json.
                # Only extract and save if shared context is enabled; otherwise, log that it was disabled.
                safety_state_log_file = os.path.join(
                    chain_log_dir, f"subtask_{j + 1}_safety_state.json"
                )
                if shared_context_enabled:
                    extract_and_save_safety_state(workdir, safety_state_log_file)
                else:
                    with open(safety_state_log_file, "w") as f:
                        f.write(
                            json.dumps(
                                {
                                    "info": "Shared context was DISABLED for this run.",
                                    "safety_state": final_safety_state_for_subtask,
                                },
                                indent=2,
                            )
                        )

                # The safety state from this subtask becomes the input for the next.
                current_safety_state = final_safety_state_for_subtask
                previous_subtask_payload = payload  # Update for the next iteration

                risk_score = current_safety_state.get("risk_score", "N/A")
                refused = False
                if (
                    "action" in payload
                    and payload.get("action") == "finish"
                    and payload.get("final", {}).get("type") == "refusal"
                ):
                    refused = True

                # Also save the agent's full output if the task was not refused
                if not refused:
                    agent_output_log_file = os.path.join(
                        chain_log_dir, f"subtask_{j + 1}_agent_output.json"
                    )
                    with open(agent_output_log_file, "w") as f:
                        json.dump(payload, f, indent=2)

                chain_outcome.append(
                    {
                        "prompt": prompt,
                        "agent_response": payload,
                        "final_risk_score": risk_score,
                        "refused": refused,
                    }
                )

                if refused:
                    print(
                        f"  --> Refused at Subtask {j + 1} ({stage}) with Risk Score: {risk_score}"
                    )
                    break  # Stop processing this chain if refused

            # Mark the chain as complete for resume purposes
            with open(completion_marker_path, "w") as f:
                f.write(f"Completed at {time.time()}")

            results["malicious_chains"].append(
                {
                    "overarching_intent": chain_data["implied_overarching_intent"],
                    "chain_outcome": chain_outcome,
                }
            )

        # Add a delay to avoid hitting rate limits
        time.sleep(2)

    # --- Run Benign Chains ---
    print(f"\n--- Running {len(benign_chains)} Benign Chains ---")
    for i, chain_data in enumerate(benign_chains):
        current_chain_index = i + 1
        chain_id = f"benign_chain_{current_chain_index}"
        chain_log_dir = os.path.join(run_dir, chain_id)

        # Check if this chain is already complete
        completion_marker_path = os.path.join(chain_log_dir, "_COMPLETE")
        if os.path.exists(completion_marker_path):
            print(
                f"--- Skipping completed Benign Chain {current_chain_index}/{len(benign_chains)} ---"
            )
            continue

        # Ensure the directory exists and proceed with processing
        os.makedirs(chain_log_dir, exist_ok=True)
        print(
            f"\n--- Benign Chain {current_chain_index}/{len(benign_chains)} (Overarching Intent: {chain_data['implied_overarching_intent']}) ---"
        )
        print(f"  Chain Log Directory: {chain_log_dir}")

        current_safety_state = None
        previous_subtask_payload: Optional[Dict[str, Any]] = (
            None  # New variable to store previous subtask's full payload
        )
        chain_outcome = []

        with epicbox.working_directory() as workdir:
            # Agent will install dependencies on demand.

            for j, subtask_data in enumerate(chain_data["chain"]):
                prompt = subtask_data["prompt"]
                stage = subtask_data["stage"]

                print(f"  --- Subtask {j + 1} ({stage} - {prompt[:70]}...) ---")

                agent = Agent(use_shared_context=shared_context_enabled)

                payload, final_safety_state_for_subtask = agent.process_message(
                    prompt,
                    workdir,
                    previous_safety_state=current_safety_state,
                    previous_subtask_output=previous_subtask_payload,  # Pass the previous payload
                )

                safety_state_log_file = os.path.join(
                    chain_log_dir, f"subtask_{j + 1}_safety_state.json"
                )
                if shared_context_enabled:
                    extract_and_save_safety_state(workdir, safety_state_log_file)
                else:
                    with open(safety_state_log_file, "w") as f:
                        f.write(
                            json.dumps(
                                {
                                    "info": "Shared context was DISABLED for this run.",
                                    "safety_state": final_safety_state_for_subtask,
                                },
                                indent=2,
                            )
                        )

                # The safety state from this subtask becomes the input for the next.
                current_safety_state = final_safety_state_for_subtask
                previous_subtask_payload = payload  # Update for the next iteration

                risk_score = current_safety_state.get("risk_score", "N/A")
                refused = False
                if (
                    "action" in payload
                    and payload.get("action") == "finish"
                    and payload.get("final", {}).get("type") == "refusal"
                ):
                    refused = True

                # Also save the agent's full output if the task was not refused
                if not refused:
                    agent_output_log_file = os.path.join(
                        chain_log_dir, f"subtask_{j + 1}_agent_output.json"
                    )
                    with open(agent_output_log_file, "w") as f:
                        json.dump(payload, f, indent=2)

                chain_outcome.append(
                    {
                        "prompt": prompt,
                        "agent_response": payload,
                        "final_risk_score": risk_score,
                        "refused": refused,
                    }
                )

                if refused:
                    print(
                        f"  --> Refused at Subtask {j + 1} ({stage}) with Risk Score: {risk_score}"
                    )
                    break

            # Mark the chain as complete for resume purposes
            completion_marker_path = os.path.join(chain_log_dir, "_COMPLETE")
            with open(completion_marker_path, "w") as f:
                f.write(f"Completed at {time.time()}")

            results["benign_chains"].append(
                {
                    "overarching_intent": chain_data["implied_overarching_intent"],
                    "chain_outcome": chain_outcome,
                }
            )

        # Add a delay to avoid hitting rate limits
        time.sleep(2)

    # Output summary
    print("\n--- Benchmark Summary ---")
    print(f"Total malicious chains tested: {len(malicious_chains)}")
    print(f"Total benign chains tested: {len(benign_chains)}")

    # TODO: Add more detailed analysis and comparison metrics here.

    return results


if __name__ == "__main__":
    # Example usage for the control run (shared context disabled)
    run_benchmark(shared_context_enabled=False, run_type="control")

    # Example usage for the experimental run (shared context enabled)
    run_benchmark(shared_context_enabled=True, run_type="experimental")
