#!/bin/bash -e

# set -x

MANIFEST_PATH=templates/*/manifest.yaml

NUM_IDS=$(cat ${MANIFEST_PATH} | egrep '^id:' | wc -l)
NUM_IDS_UNIQUE=$(cat ${MANIFEST_PATH} | egrep '^id:' | awk '!seen[$0]++' | wc -l)

if [ "${NUM_IDS}" != "${NUM_IDS_UNIQUE}" ]; then
  echo "ERROR: one or more templates are re-using ids."
  echo
  echo "All Template IDs:"
  egrep '^id:' ${MANIFEST_PATH}
  echo

  exit 1
fi
