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
    source_addr: int | None = None,
    source_api: str | None = None,
    sink_api: str | None = None,
    check_taint: bool = False,
) -> dict:
    try:
        import angr
        import claripy
    except ImportError:
        return {
            "error": "angr or claripy is not installed",
            "satisfiable": False,
            "taint_verified": False,
            "data_flow_confirmed": False,
        }

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
            if source_addr is not None and source_addr < base_addr:
                source_addr += base_addr
            if avoid_addrs:
                avoid_addrs = [
                    addr + base_addr if addr < base_addr else addr for addr in avoid_addrs
                ]

        # Tag for taint tracking
        taint_tag = f"taint_{source_api.lower()}" if source_api else "taint_source"
        if check_taint and source_api and source_api.lower() == "argv":
            sym_arg1 = claripy.BVS(f"{taint_tag}_argv1", 50 * 8)
        else:
            sym_arg1 = claripy.BVS("arg1", 50 * 8)
        args = [project.filename, sym_arg1]

        # Determine start state using entry_state to set up argv and stack correctly
        if start_addr is not None:
            state = project.factory.entry_state(args=args, addr=start_addr)
        else:
            state = project.factory.entry_state(args=args)

        # Hook I/O source functions with SimProcedures when taint verification is requested
        if check_taint and source_api and source_api.lower() != "argv":
            norm_src = source_api.lower()

            class TaintSourceProcedure(angr.SimProcedure):
                def run(self, *proc_args, **proc_kwargs):
                    sym_buf = claripy.BVS(f"taint_{norm_src}_buf", 64 * 8)
                    buf_ptr = None
                    if norm_src in ("read", "recv", "recvfrom", "recvmsg"):
                        if len(proc_args) > 1:
                            buf_ptr = proc_args[1]
                    elif norm_src in ("fgets", "fread", "gets", "getline", "scanf", "fscanf"):
                        if len(proc_args) > 0:
                            buf_ptr = proc_args[0]

                    if buf_ptr is not None:
                        try:
                            self.state.memory.store(buf_ptr, sym_buf)
                        except Exception:
                            pass

                    if norm_src == "getenv":
                        try:
                            env_mem = self.state.heap.allocate(64)
                            self.state.memory.store(env_mem, sym_buf)
                            return env_mem
                        except Exception:
                            return claripy.BVV(0, self.state.arch.bits)

                    return claripy.BVV(64, self.state.arch.bits)

            for sym_variant in [
                source_api,
                f"sym.imp.{source_api}",
                f"imp.{source_api}",
                f"_{source_api}",
            ]:
                try:
                    project.hook_symbol(sym_variant, TaintSourceProcedure())
                except Exception:
                    pass

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
            raw_concrete_input = (
                concrete_results.get("argv1") or concrete_results.get("stdin") or ""
            )

            # Check taint data flow
            taint_verified = True
            data_flow_confirmed = True
            reachability_only = False
            evidence: dict = {}

            if check_taint:
                arch_name = found_state.arch.name
                regs_to_check = []
                if arch_name == "AMD64":
                    regs_to_check = [
                        found_state.regs.rdi,
                        found_state.regs.rsi,
                        found_state.regs.rdx,
                    ]
                elif arch_name in ("ARMEL", "ARMHF"):
                    regs_to_check = [
                        found_state.regs.r0,
                        found_state.regs.r1,
                        found_state.regs.r2,
                    ]
                elif arch_name == "AARCH64":
                    regs_to_check = [
                        found_state.regs.x0,
                        found_state.regs.x1,
                        found_state.regs.x2,
                    ]
                elif arch_name == "X86":
                    sp = found_state.regs.esp
                    regs_to_check = [
                        found_state.memory.load(
                            sp + 4 * i, 4, endness=found_state.arch.memory_endness
                        )
                        for i in range(3)
                    ]

                norm_sink = (sink_api or "").lower()
                args_to_inspect = []
                if norm_sink in ("strcpy", "strcat", "memcpy", "memmove"):
                    if len(regs_to_check) > 1:
                        args_to_inspect.append(regs_to_check[1])
                elif norm_sink in ("sprintf", "snprintf"):
                    if len(regs_to_check) > 1:
                        args_to_inspect.extend(regs_to_check[1:])
                else:
                    if len(regs_to_check) > 0:
                        args_to_inspect.append(regs_to_check[0])

                sink_vars: set[str] = set()
                for arg_expr in args_to_inspect:
                    sink_vars.update(arg_expr.variables)
                    try:
                        pointed_mem = found_state.memory.load(arg_expr, 64)
                        sink_vars.update(pointed_mem.variables)
                    except Exception:
                        pass

                expected_prefixes: list[str] = []
                if source_api:
                    s_low = source_api.lower()
                    expected_prefixes.append(f"taint_{s_low}")
                    expected_prefixes.append(s_low)
                    if s_low == "argv":
                        expected_prefixes.extend(["arg1", "argv"])
                    elif s_low in (
                        "read",
                        "fread",
                        "fgets",
                        "gets",
                        "stdin",
                        "scanf",
                        "getline",
                    ):
                        expected_prefixes.extend(["stdin", "file_"])
                else:
                    expected_prefixes.extend(["taint", "arg1", "stdin", "file_"])

                matching_vars = [
                    v for v in sink_vars if any(prefix in v.lower() for prefix in expected_prefixes)
                ]

                if matching_vars:
                    taint_verified = True
                    data_flow_confirmed = True
                    reachability_only = False
                    evidence["taint_variables"] = list(matching_vars)
                else:
                    taint_verified = False
                    data_flow_confirmed = False
                    reachability_only = True
                    evidence["reason"] = (
                        f"Sink {sink_api} arguments do not depend on source {source_api}. "
                        f"Variables found in sink: {list(sink_vars)}"
                    )

            concrete_input = raw_concrete_input if taint_verified else None

            return {
                "satisfiable": True,
                "reachability_only": reachability_only,
                "taint_verified": taint_verified,
                "data_flow_confirmed": data_flow_confirmed,
                "concrete_input": concrete_input,
                "reachability_concrete_input": raw_concrete_input,
                "inputs": concrete_results,
                "target_address": hex(target_addr),
                "source_address": hex(source_addr) if source_addr else None,
                "evidence": evidence,
                "error": None,
            }
        else:
            return {
                "satisfiable": False,
                "reachability_only": False,
                "taint_verified": False,
                "data_flow_confirmed": False,
                "concrete_input": None,
                "target_address": hex(target_addr),
                "source_address": hex(source_addr) if source_addr else None,
                "error": None,
            }

    except Exception as e:
        return {
            "satisfiable": False,
            "reachability_only": False,
            "taint_verified": False,
            "data_flow_confirmed": False,
            "error": str(e),
            "target_address": hex(target_addr),
            "source_address": hex(source_addr) if source_addr else None,
        }


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
    parser.add_argument(
        "--source-addr", type=lambda x: int(x, 0), help="Source address (hex or int)"
    )
    parser.add_argument("--source-api", help="Source API name")
    parser.add_argument("--sink-api", help="Sink API name")
    parser.add_argument(
        "--check-taint",
        action="store_true",
        help="Verify data-flow taint from source to sink",
    )

    args = parser.parse_args()

    avoid_list = None
    if args.avoid_addrs:
        try:
            avoid_list = [int(x.strip(), 0) for x in args.avoid_addrs.split(",") if x.strip()]
        except ValueError as e:
            print(json.dumps({"satisfiable": False, "error": f"Invalid avoid-addrs format: {e}"}))
            sys.exit(1)

    result = run_symbolic_execution(
        args.binary,
        args.start_addr,
        args.target_addr,
        avoid_list,
        source_addr=args.source_addr,
        source_api=args.source_api,
        sink_api=args.sink_api,
        check_taint=args.check_taint,
    )

    # Print the result as JSON to stdout
    print(json.dumps(result))


if __name__ == "__main__":
    main()
