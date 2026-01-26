#!/bin/bash
set -e

# Create a clean test repo
rm -rf test-secrets-repo
mkdir test-secrets-repo
cd test-secrets-repo
git init

# 1. Commit a safe file
echo "console.log('Hello World');" > index.js
git add index.js
git commit -m "Initial commit"

# 2. Commit a SECRET (AWS Key pattern)
echo "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7FAKEKEY" > .env
git add .env
git commit -m "Deploy config"

# 3. 'Fix' the leak by deleting the file (but it remains in history!)
git rm .env
echo "Cleaned up secrets" > clean.txt
git add clean.txt
git commit -m "Removed secrets"

# 4. Run the scanner against this repo
cd ..
echo "Running Audit Scan on test-secrets-repo..."
node packages/agent-core/dist/index.js scan ./test-secrets-repo

# Clean up
# rm -rf test-secrets-repo
