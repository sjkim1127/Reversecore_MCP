#!/bin/bash
set -euo pipefail

project_src="$SRC/reversecore_mcp"
cp "$project_src/reversecore_mcp/core/json_utils.py" "$SRC/reversecore_json_utils.py"
export PYTHONPATH="$SRC${PYTHONPATH:+:$PYTHONPATH}"

while IFS= read -r -d '' fuzzer; do
    fuzzer_basename="$(basename -s .py "$fuzzer")"
    package_name="${fuzzer_basename}.pkg"
    work_dir="$WORK/pyinstaller/$fuzzer_basename"
    mkdir -p "$work_dir"

    pyinstaller \
        --distpath "$OUT" \
        --workpath "$work_dir/build" \
        --specpath "$work_dir" \
        --onefile \
        --name "$package_name" \
        "$fuzzer"

    cat > "$OUT/$fuzzer_basename" <<EOF
#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir="\$(dirname "\$0")"
exec "\$this_dir/$package_name" "\$@"
EOF
    chmod +x "$OUT/$fuzzer_basename"
done < <(find "$project_src/.clusterfuzzlite/fuzzers" -type f -name '*_fuzzer.py' -print0)
