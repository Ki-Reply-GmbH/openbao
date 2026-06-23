#!/usr/bin/env bash

# This script fetches all releases + their assets from GitHub and strips the
# extremely bloated JSON document created by GitHub's API down to a minimal
# index of available versions and assets.
# The resulting files can be uploaded to a web server such that the downloads
# page web frontend can pick them up and display available releases and
# downloads efficiently.

set -euo pipefail

echo "Fetching release info..."

# This generates the following layout:
#
# [
# 	{
# 		"tag_name": "v2.0.0",
# 		"assets": [
# 			"foo.tar.gz",
# 			"checksums.txt"
# 		]
# 	}
# ]
all=$(
    gh api \
      --paginate \
      --jq 'map(select(.draft == false) | { tag_name, assets: (.assets | map(.name)) })' \
      repos/openbao/openbao/releases
)

mkdir -p dist/index && cd dist/index

# One file that lists all tags:
jq -r 'map(.tag_name) | join("\n")' <<< "$all" > tags.txt
echo "Wrote tags.txt"

# One file per release that lists all assets:
jq -c '.[]' <<< "$all" | while read -r release; do
    file="$(jq -r '.tag_name' <<< "$release").txt"
    jq -r '.assets | join("\n")' <<< "$release" > "$file"
    echo "Wrote $file"
done
