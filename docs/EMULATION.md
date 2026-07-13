# Emulation runtime isolation

Reversecore MCP can generate Qiling/AFL fuzzing harnesses without importing or executing Qiling inside the MCP server process.

## Why Qiling is isolated

Qiling 1.4.6 depends on `python-fx==0.4.0`, which constrains Pillow to versions below 11. Current Pillow security fixes require Pillow 12.3.0 or newer. Installing both stacks in one environment would either leave known vulnerabilities unresolved or make dependency resolution fail.

For that reason:

- the normal and `full` Reversecore installations use Pillow 12.3 or newer;
- Qiling and `python-fx` are absent from the server lock file and release artifacts;
- harness generation remains supported;
- harness execution must happen in a separate disposable sandbox.

## Executing a generated harness

Use a dedicated VM or container with no credentials, no host network access, and only the target sample mounted read-only. Install the Qiling runtime according to the upstream Qiling documentation inside that isolated environment. Do not install Qiling into the Reversecore MCP server environment.

Treat generated harnesses and analyzed binaries as hostile input. Prefer `--network=none`, a read-only root filesystem, dropped Linux capabilities, and a disposable filesystem for every run.

When Qiling publishes a release compatible with the secure Pillow line, this isolation can be reconsidered after dependency and security testing.
