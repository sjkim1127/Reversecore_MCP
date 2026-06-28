---
name: google-antigravity-sdk
description: "Design, implement, and debug autonomous AI agents and multi-agent systems using the Google Antigravity (AGY) SDK. ACTIVATE this skill when the user wants to create, configure, or orchestrate Google Antigravity agents."
---

# Google Antigravity SDK

## Installation & Setup

Before proceeding with any Google Antigravity tasks, ensure the environment is
ready:

-   **Verify Applicability**: If operating in an existing codebase, verify that
    using this Python SDK is possible and appropriate for the project.
-   **Check Dependencies**: Check if `google-antigravity` is listed in the
    project's dependencies (e.g., `requirements.txt`, `pyproject.toml`).
-   **Install Package**: Ensure the `google-antigravity` Python package is
    installed.
-   **Authentication Setup**: Check for a valid `GEMINI_API_KEY` environment
    variable or a `.env` file (required to access Gemini models).
    -   If credentials are missing, you MUST actively help the user get set up
        with an API key by providing the following link:
        -   Default to Google AI Studio:
            `https://aistudio.google.com/app/api-keys`
    -   Explain that the API key can be passed explicitly in code as shorthand
        (e.g., `LocalAgentConfig(api_key="...")`) or automatically read from the
        environment.

## Routing Table

Use the following information to dig deeper into specific topics based on the
user request. Read the referenced files or explore the directories to find
relevant information.

### References

-   If the user needs to understand the high-level overview and core concepts of
    the Google Antigravity SDK (Agent, Conversation, Connection), read
    `references/architecture.md`.
-   If the user needs to perform advanced agent configuration, select
    appropriate models, or understand the critical rules for model identifiers
    to avoid assumptions, read `references/agent_configuration.md`.
-   If the user needs to extend an agent's capabilities by integrating Model
    Context Protocol (MCP) servers, or configure tool permissions for the agent,
    read `references/mcp_integration.md`.
-   If the user needs to define safety policies, resolve execution order, or
    restrict agent actions using predicates, read
    `references/safety_policies.md`.
-   If the user needs to debug failed agents, stream logs, or implement error
    recovery using hooks to make agents robust, read
    `references/error_handling.md`.
-   If the user needs to monitor costs, track token usage (including thinking
    tokens), or build custom audit logs for advanced monitoring, read
    `references/observability.md`.
-   If the user needs to see a list of built-in tools and understand their default state, read `references/built_in_tools.md`.

### Examples

-   If the user needs to implement basic agent behavior, streaming responses, or
    expose internal thoughts, read `examples/getting_started/hello_world.md`.
-   If the user needs to equip an agent with custom capabilities (tools) derived
    from Python functions, or maintain agent state across tool execution, read
    `examples/getting_started/custom_tool.md`.
-   If the user needs to shape an agent's persona, define its system
    instructions, or dynamically adapt its behavior, read
    `examples/getting_started/persona_config.md`.
-   If the user needs to build multimodal agents capable of processing images
    and PDFs, or generating visual content, read
    `examples/getting_started/multimodal.md`.
-   If the user needs to implement multi-agent delegation, allowing a main agent
    to spawn and orchestrate subagents for complex tasks, read
    `examples/getting_started/subagents.md`.
-   If the user needs to connect an agent to external services via MCP (Stdio or
    SSE), read `examples/getting_started/mcp_tools.md`.
-   If the user needs to create proactive agents that respond to time-based
    events or file system triggers in the background, read
    `examples/getting_started/periodic_trigger.md`.
-   If the user needs to intercept agent lifecycle events (e.g., pre/post turn,
    tool execution, errors) to customize execution flow, read
    `examples/getting_started/hooks.md`.
-   If the user needs to implement persistent agents that remember past
    interactions across sessions, read
    `examples/getting_started/persistence.md`.
-   If the user needs to override the default application data directory
    for agent artifacts, scratch files, and media storage, read
    `examples/getting_started/app_data_dir_override.md`.
-   If the user needs an agent to output structured data (e.g., JSON matching a
    Pydantic schema) for reliable integration, read
    `examples/getting_started/structured_output.md`.
-   If the user needs to add, configure, or load agent skills into the Google
    Antigravity SDK agent, read `examples/getting_started/agent_skills.md`.
