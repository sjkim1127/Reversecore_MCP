import argparse
import json
import logging

# Suppress angr logs
logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("claripy").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)


def run_symbolic_execution(binary_path: str, start_addr: int | None, target_addr: int) -> dict:
    try:
        import angr
    except ImportError:
        return {"error": "angr is not installed", "satisfiable": False}

    try:
        # Load the binary
        project = angr.Project(binary_path, auto_load_libs=False)

        # Determine start state
        if start_addr is not None:
            state = project.factory.blank_state(addr=start_addr)
        else:
            state = project.factory.entry_state()

        simgr = project.factory.simulation_manager(state)

        # Explore paths to the target address
        simgr.explore(find=target_addr)

        if simgr.found:
            found_state = simgr.found[0]

            # Try to extract concrete input data that leads to this path
            # For standard stdin/argv inputs:
            try:
                stdin_data = found_state.posix.dumps(0)
                input_str = stdin_data.decode("utf-8", errors="ignore") if stdin_data else ""
            except Exception:
                input_str = ""

            return {
                "satisfiable": True,
                "concrete_input": input_str,
                "target_address": hex(target_addr),
                "error": None,
            }
        else:
            return {
                "satisfiable": False,
                "concrete_input": None,
                "target_address": hex(target_addr),
                "error": None,
            }

    except Exception as e:
        return {"satisfiable": False, "error": str(e), "target_address": hex(target_addr)}


def main():
    parser = argparse.ArgumentParser(description="Angr Worker for Vulnerability Hunter")
    parser.add_argument("--binary", required=True, help="Path to the binary file")
    parser.add_argument("--start-addr", type=lambda x: int(x, 0), help="Start address (hex or int)")
    parser.add_argument(
        "--target-addr", type=lambda x: int(x, 0), required=True, help="Target address (hex or int)"
    )

    args = parser.parse_args()

    result = run_symbolic_execution(args.binary, args.start_addr, args.target_addr)

    # Print the result as JSON to stdout
    print(json.dumps(result))


if __name__ == "__main__":
    main()
