#!/bin/sh

set -e

export RED="\033[33;1m"
export NONE="\033[0m"

if [ -z "$PROJECT_NAME" ]; then
    PROJECT_NAME=${TRAVIS_REPO_SLUG}
fi

# Environment check
echo -e "${RED}Note: PROJECT_NAME and COVERITY_SCAN_TOKEN are available on Project Settings page on scan.coverity.com${NONE}"
[ -z "$PROJECT_NAME" ] && echo "ERROR: PROJECT_NAME must be set" && exit 1
[ -z "$OWNER_EMAIL" ] && echo "ERROR: OWNER_EMAIL must be set" && exit 1
[ -z "$COVERITY_SCAN_BRANCH_PATTERN" ] && echo "ERROR: COVERITY_SCAN_BRANCH_PATTERN must be set" && exit 1
[ -z "$COVERITY_SCAN_BUILD_COMMAND" ] && echo "ERROR: COVERITY_SCAN_BUILD_COMMAND must be set" && exit 1

PLATFORM=`uname`
TOOL_ARCHIVE=/tmp/cov-analysis-${PLATFORM}.tgz
TOOL_URL=https://scan.coverity.com/download/${PLATFORM}
TOOL_BASE=/tmp/coverity-scan-analysis
UPLOAD_URL="http://scan5.coverity.com/cgi-bin/upload.py"
SCAN_URL="https://scan.coverity.com"

# Do not run on pull requests
if [ "${TRAVIS_PULL_REQUEST}" = "true" ]; then
  echo -e "${RED}INFO: Skipping Coverity Analysis: branch is a pull request.${NONE}"
  exit 0
fi

# Verify this branch should run
IS_COVERITY_SCAN_BRANCH=`ruby -e "puts '${TRAVIS_BRANCH}' =~ /\\A$COVERITY_SCAN_BRANCH_PATTERN\\z/ ? 1 : 0"`
if [ "$IS_COVERITY_SCAN_BRANCH" = "1" ]; then
  echo -e "${RED}Coverity Scan configured to run on branch ${TRAVIS_BRANCH}${NONE}"
else
  echo -e "${RED}Coverity Scan NOT configured to run on branch ${TRAVIS_BRANCH}${NONE}"
  exit 0 # Nothing to do, exit with success otherwise the build will be considered failed
fi

# If COVERITY_SCAN_TOKEN isn't set, then we're probably running from somewhere 
# other than ClusterLabs/pacemaker and coverity shouldn't be running anyway 
[ -z "$COVERITY_SCAN_TOKEN" ] && echo "${RED}ERROR: COVERITY_SCAN_TOKEN must be set${NONE}" && exit 0

# Verify upload is permitted
AUTH_RES=`curl -s --form project="$PROJECT_NAME" --form token="$COVERITY_SCAN_TOKEN" $SCAN_URL/api/upload_permitted`
if [ "$AUTH_RES" = "Access denied" ]; then
  echo -e "${RED}Coverity Scan API access denied. Check PROJECT_NAME and COVERITY_SCAN_TOKEN.${NONE}"
  exit 1
else
  AUTH=`echo $AUTH_RES | ruby -e "require 'rubygems'; require 'json'; puts JSON[STDIN.read]['upload_permitted']"`
  if [ "$AUTH" = "true" ]; then
    echo -e "${RED}Coverity Scan analysis authorized per quota.${NONE}"
  else
    WHEN=`echo $AUTH_RES | ruby -e "require 'rubygems'; require 'json'; puts JSON[STDIN.read]['next_upload_permitted_at']"`
    echo -e "${RED}Coverity Scan analysis NOT authorized until $WHEN.${NONE}"
    exit 1
  fi
fi

if [ ! -d $TOOL_BASE ]; then
  # Download Coverity Scan Analysis Tool
  if [ ! -e $TOOL_ARCHIVE ]; then
    echo -e "${RED}Downloading Coverity Scan Analysis Tool...${NONE}"
    wget -nv -O $TOOL_ARCHIVE $TOOL_URL --post-data "project=$PROJECT_NAME&token=$COVERITY_SCAN_TOKEN"
  fi

  # Extract Coverity Scan Analysis Tool
  echo -e "${RED}Extracting Coverity Scan Analysis Tool...${NONE}"
  mkdir -p $TOOL_BASE
  pushd $TOOL_BASE
  tar xzf $TOOL_ARCHIVE
  popd
fi

TOOL_DIR=`find $TOOL_BASE -type d -name 'cov-analysis*'`
export PATH=$TOOL_DIR/bin:$PATH

# Build
echo -e "${RED}Running Coverity Scan Analysis Tool...${NONE}"
COV_BUILD_OPTIONS=""
#COV_BUILD_OPTIONS="--return-emit-failures 8 --parse-error-threshold 85"
RESULTS_DIR="cov-int"
eval "${COVERITY_SCAN_BUILD_COMMAND_PREPEND}"
COVERITY_UNSUPPORTED=1 cov-build --dir $RESULTS_DIR $COV_BUILD_OPTIONS $COVERITY_SCAN_BUILD_COMMAND

# Upload results
echo -e "${RED}Tarring Coverity Scan Analysis results...${NONE}"
RESULTS_ARCHIVE=analysis-results.tgz
tar czf $RESULTS_ARCHIVE $RESULTS_DIR
SHA=`git rev-parse --short HEAD`

echo -e "${RED}Uploading Coverity Scan Analysis results...${NONE}"
curl \
  --progress-bar \
  --form project=$PROJECT_NAME \
  --form token=$COVERITY_SCAN_TOKEN \
  --form email=$OWNER_EMAIL \
  --form file=@$RESULTS_ARCHIVE \
  --form version=$SHA \
  --form description="Travis CI build" \
  $UPLOAD_URL
