import asyncio

from reversecore_mcp.tools.malware.vulnerability_hunter import vulnerability_hunter


async def main():
    print("Running vulnerability hunter...")
    result = await vulnerability_hunter("/app/workspace/vuln_firmware", auto_dynamic_verify=True)
    import json

    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
