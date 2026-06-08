#!/usr/bin/env bash
set -euo pipefail

version="${1:-0.1.0}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bundle_dir="$root/target/hbse-${version}-native-linux"
archive="$root/target/hbse-${version}-native-linux.tar.gz"

cargo build --manifest-path "$root/Cargo.toml" --release --quiet

rm -rf "$bundle_dir"
mkdir -p "$bundle_dir/bin"

install -m 0755 "$root/target/release/hbse" "$bundle_dir/bin/hbse"
install -m 0755 "$root/target/release/hbse-broker" "$bundle_dir/bin/hbse-broker"

cat > "$bundle_dir/README.md" <<EOF
# HBSE Native Linux Bundle

This bundle contains:

- \`bin/hbse\`
- \`bin/hbse-broker\`

Quick smoke:

\`\`\`bash
export PATH="\$PWD/bin:\$PATH"
hbse --help
hbse-broker --help
\`\`\`

Install the binaries into a directory on PATH, then use:

\`\`\`bash
hbse --vault "\$HOME/.local/share/hbse/vault.db" broker install-service --scope user --enable --start
\`\`\`
EOF

(
  cd "$bundle_dir"
  sha256sum bin/hbse bin/hbse-broker > SHA256SUMS
)

tar -C "$(dirname "$bundle_dir")" -czf "$archive" "$(basename "$bundle_dir")"
echo "$archive"
