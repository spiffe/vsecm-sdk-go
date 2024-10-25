#!/usr/bin/env bash

VERSION="$1"

echo ""
echo "--------"
echo "VSecM Go SDK"
if git tag -s v"$VERSION"; then
  git push origin --tags
  # gh release create
fi
