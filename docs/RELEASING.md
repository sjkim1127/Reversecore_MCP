# Release and Registry Publishing

Reversecore MCP uses a tag-driven release workflow to publish the same version to:

1. PyPI as `reversecore-mcp`
2. GitHub Container Registry as `ghcr.io/sjkim1127/reversecore_mcp`
3. The official MCP Registry as `io.github.sjkim1127/reversecore-mcp`
4. GitHub Releases with the wheel and source distribution attached

No long-lived package or registry token is stored in GitHub. PyPI and the MCP Registry use GitHub Actions OIDC.

## One-time PyPI setup

The first release requires a PyPI pending Trusted Publisher. In the PyPI account settings, open **Publishing**, add a pending GitHub publisher, and enter:

| Field | Value |
|---|---|
| PyPI project name | `reversecore-mcp` |
| GitHub owner | `sjkim1127` |
| GitHub repository | `Reversecore_MCP` |
| Workflow filename | `release.yml` |
| Environment name | `pypi` |

The pending publisher creates the PyPI project on the first successful workflow run. A pending publisher does not reserve the package name before publication.

In GitHub, create an environment named `pypi`. Deployment reviewers are optional but recommended for production releases.

## MCP Registry authentication

The release workflow runs:

```bash
mcp-publisher login github-oidc
mcp-publisher publish
```

The OIDC identity authorizes the namespace `io.github.sjkim1127/*`. No MCP Registry secret is required.

Ownership of each distribution is verified independently:

- PyPI: `PYPI_README.md` contains `<!-- mcp-name: io.github.sjkim1127/reversecore-mcp -->`
- OCI: `Dockerfile` contains the `io.modelcontextprotocol.server.name` label
- Registry metadata: `server.json` uses the same name and version

## Preparing a release

Update all release versions together:

- `pyproject.toml` — `project.version`
- `reversecore_mcp/__init__.py` — `__version__`
- `server.json` — root version, PyPI package version, and OCI image tag
- `PYPI_README.md` — pinned container example when appropriate

Validate locally with Python 3.11 or newer:

```bash
python scripts/check_release_metadata.py
python -m pip install --upgrade build twine
python -m build
python -m twine check dist/*
```

The `Release Metadata Validation` workflow performs the same checks on pull requests.

## Publishing

After the release commit is merged into `main`, create and push an annotated version tag that exactly matches `project.version`:

```bash
git checkout main
git pull --ff-only
git tag -a v2.1.0 -m "Reversecore MCP v2.1.0"
git push origin v2.1.0
```

The `Publish Release` workflow refuses tags that do not match the checked-in version. It publishes PyPI and OCI artifacts first, waits for both to succeed, publishes MCP Registry metadata, and finally creates the GitHub Release.

## Failure handling

- Do not reuse a version already uploaded to PyPI; package versions are immutable.
- A failed workflow before PyPI publication can be rerun after correcting account configuration.
- If PyPI succeeded but a later job failed, fix the downstream problem without changing the package artifact and rerun only when the target permits idempotent publication.
- The MCP Registry is currently preview infrastructure; temporary propagation failures are retried automatically by the workflow.
