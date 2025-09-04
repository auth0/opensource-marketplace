#!/bin/bash -e

# set -x

manifestPath=templates/*/manifest.yaml

# When running in a github action, GITHUB_BASE_REF points to the branch/ref
# we are merging into. Typically this is origin/main but in patch
# workflows this may be something different (e.g. patch-v202328.229) and so
# we want this to compare to that ref rather than main.
BASE_REF="origin/${GITHUB_BASE_REF:-main}"

if ! git status --porcelain; then
  echo "GIT repository needs to be clean to check release manifest"
  exit 1
fi

UPDATED_TEMPLATES=$(git diff --name-status "${BASE_REF}...HEAD" templates/*/manifest.yaml | egrep '^M.*/manifest.yaml$' | awk '{print $2}')

VIOLATIONS=0

if [ "${UPDATED_TEMPLATES}" != "" ]; then
  while IFS= read -r TPL; do
    if git diff "${BASE_REF}...HEAD" "${TPL}" | egrep '^[-+]id:' > /dev/null; then
      VIOLATIONS=1
      echo "You must not update the id of pre-existing templates. Revert the id change on: ${TPL}";
    fi

  done <<< "$UPDATED_TEMPLATES"
fi

if [ "${VIOLATIONS}" = "0" ]; then
  exit 0
fi

exit 1
