#!/bin/bash

# SPDX-FileCopyrightText: 2026 Nicolas Iooss
#
# SPDX-License-Identifier: MIT

# Copy of https://web.archive.org/web/20251212221441/https://www.synacktiv.com/en/publications/2025-winter-challenge-quinindrome#-the-challenge

##### Argument checks #####
# Check if binary path is provided
if [ $# -ne 1 ]; then
    echo "[+] Usage: $0 <binary_path>"
    exit 1
fi

binary=$1

# Check if file exists and is readable
if [ ! -f "$binary" ] || [ ! -r "$binary" ]; then
    echo "[!] Error: File '$binary' does not exist or is not readable."
    exit 1
fi


##### First check: byte-wise palindrome #####
reversed_file=$(mktemp)
size=$(wc -c < "$binary")

# Read the file byte by byte in reverse order (in a very efficient way)
for ((i = size - 1; i >= 0; i--)); do
    dd if="$binary" bs=1 skip=$i count=1 2>/dev/null
done > "$reversed_file"

if cmp -s "$binary" "$reversed_file"; then
    echo "[+] First check passed: binary is a byte-wise palindrome."
    rm "$reversed_file"
else
    echo "[!] First check failed: binary is not a byte-wise palindrome."
    rm "$reversed_file"
    exit 1
fi


##### Build a scratch Podman image with the binary to test #####
# Create the containerfile
image_name="quinindrome_test"
containerfile=$(mktemp)

cat > "$containerfile" <<EOF
FROM scratch
COPY $binary /binary
CMD ["/binary"]
EOF

# Build the image
if ! podman build . -t "$image_name" -f "$containerfile" >/dev/null; then
    echo "[!] Failed to build Podman test image."
    rm "$containerfile"
    exit 1
fi
rm "$containerfile"


##### Second check: quine property #####
output_file=$(mktemp)
max_run_time=120

# Run the binary in the scratch container and capture output & return code
timeout "$max_run_time" podman run --rm "$image_name" > "$output_file"
return_code=$?

if [ $return_code -ne 0 ]; then
    echo "[!] Second check failed: binary execution returned non-zero status: $return_code."
    rm "$output_file"
    exit 1
fi

if cmp -s "$binary" "$output_file"; then
    echo "[+] Second check passed: binary is a true quine, its output matches itself."
    rm "$output_file"
else
    echo "[!] Second check failed: Is that a quine? Binary output does not match itself."
    rm "$output_file"
    exit 1
fi

echo "[+] Both checks passed: your binary is a very nice quinindrome!"
echo "[+] Your score: $size"
