#!/bin/bash

# This script will fetch all repos (created in the last year) in an organization and run the credential-detector tool on them.
# For each repo, it will clone the repo, run the tool, and save the output to a file in the specified output directory.
# Empty files will be removed.

# Set the organization name
ORG_NAME="MyOrg"

# Set the path to the credential-detector binary
CRED_DETECTOR_PATH="/Users/MyUser/go/bin/credential-detector"

# Set the path to the credential-config.yaml file
CRED_CONFIG_PATH="/Users/MyUser/credential-config.yaml"

# Set the output directory for the scan results
OUTDIR="/Users/MyUser/credential-detector-output"

# Get a list of all repositories in the organization
#REPO_LIST=$(gh api "/orgs/$ORG_NAME/repos" --jq ".[].full_name" --paginate) #fetch all repos
REPO_LIST=$(gh api "/orgs/$ORG_NAME/repos" --paginate  | jq -r '.[] | select((.created_at | fromdateiso8601) >= (now - (365 * 24 * 60 * 60))) | .name') #fetch new repos created in the last year

# Iterate over each repository in the list
for REPO in $REPO_LIST; do
    if test -f "$OUTDIR/$(basename "$REPO").out"; then
        echo "Already scanned $REPO"
        continue
    fi

    # Clone the repository
    git clone "https://github.com/$ORG_NAME/$REPO.git"

    # Change into the newly cloned repository directory
    cd "$(basename "$REPO")"

    # Execute the credential-detector command and redirect output to a file
    $CRED_DETECTOR_PATH --config $CRED_CONFIG_PATH --path . > $OUTDIR/$(basename "$REPO").out

    # Change back to the parent directory
    cd ..

    # Remove the cloned repository directory
    rm -rf "$(basename "$REPO")"
done


# Remove files with no results
find $OUTDIR -type f -exec grep -q 'Results found: 0' {} \; -exec rm {} \;