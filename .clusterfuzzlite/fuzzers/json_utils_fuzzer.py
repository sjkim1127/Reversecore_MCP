import sys

import atheris

with atheris.instrument_imports():
    import reversecore_json_utils


def TestOneInput(data: bytes) -> None:
    """Exercise the project's JSON decoder with arbitrary input bytes."""
    try:
        reversecore_json_utils.loads(data)
    except (
        reversecore_json_utils.JSONDecodeError,
        UnicodeDecodeError,
    ):
        return


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
