import argparse
import json
import logging
import sys

# Suppress angr logs
logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("claripy").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)


def run_symbolic_execution(
    binary_path: str,
    start_addr: int | None,
    target_addr: int,
    avoid_addrs: list[int] | None = None,
) -> dict:
    try:
        import angr
        import claripy
    except ImportError:
        return {"error": "angr or claripy is not installed", "satisfiable": False}

    try:
        # Load the binary
        project = angr.Project(binary_path, auto_load_libs=False)

        # Automatically adjust relative offsets for PIE binaries
        base_addr = project.loader.main_object.mapped_base
        if base_addr > 0:
            if target_addr < base_addr:
                target_addr += base_addr
            if start_addr is not None and start_addr < base_addr:
                start_addr += base_addr
            if avoid_addrs:
                avoid_addrs = [
                    addr + base_addr if addr < base_addr else addr for addr in avoid_addrs
                ]

        # Create symbolic variables for argv[1] and stdin
        # Let's support up to 50 bytes for argv[1]
        sym_arg1 = claripy.BVS("arg1", 50 * 8)
        args = [project.filename, sym_arg1]

        # Determine start state using entry_state to set up argv and stack correctly
        if start_addr is not None:
            state = project.factory.entry_state(args=args, addr=start_addr)
        else:
            state = project.factory.entry_state(args=args)

        simgr = project.factory.simulation_manager(state)

        # Explore paths to the target address, optionally avoiding error/exit states
        explore_kwargs = {"find": target_addr}
        if avoid_addrs:
            explore_kwargs["avoid"] = avoid_addrs

        simgr.explore(**explore_kwargs)

        if simgr.found:
            found_state = simgr.found[0]

            # Try to extract concrete values from both channels
            concrete_results = {}

            # 1. Resolve argv[1]
            try:
                concrete_arg1 = found_state.solver.eval(sym_arg1, cast_to=bytes)
                # Split at null byte to get the clean string
                arg1_str = concrete_arg1.split(b"\x00")[0].decode("utf-8", errors="ignore")
                if arg1_str:
                    concrete_results["argv1"] = arg1_str
            except Exception:
                pass

            # 2. Resolve stdin
            try:
                stdin_data = found_state.posix.dumps(0)
                if stdin_data:
                    stdin_str = stdin_data.split(b"\x00")[0].decode("utf-8", errors="ignore")
                    if stdin_str:
                        concrete_results["stdin"] = stdin_str
            except Exception:
                pass

            # Primary concrete input selection: prefer argv1 if resolved, otherwise stdin
            concrete_input = concrete_results.get("argv1") or concrete_results.get("stdin") or ""

            return {
                "satisfiable": True,
                "concrete_input": concrete_input,
                "inputs": concrete_results,
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
        "--target-addr",
        type=lambda x: int(x, 0),
        required=True,
        help="Target address (hex or int)",
    )
    parser.add_argument(
        "--avoid-addrs", help="Comma-separated list of addresses to avoid (hex or int)"
    )

    args = parser.parse_args()

    avoid_list = None
    if args.avoid_addrs:
        try:
            avoid_list = [int(x.strip(), 0) for x in args.avoid_addrs.split(",") if x.strip()]
        except ValueError as e:
            print(json.dumps({"satisfiable": False, "error": f"Invalid avoid-addrs format: {e}"}))
            sys.exit(1)

    result = run_symbolic_execution(args.binary, args.start_addr, args.target_addr, avoid_list)

    # Print the result as JSON to stdout
    print(json.dumps(result))


if __name__ == "__main__":
    main()
