#!/usr/bin/env bash
set -e
export BITWARDEN_SERVER=${BITWARDEN_SERVER:-}
export BITWARDEN_EMAIL=${BITWARDEN_EMAIL:-}
export BITWARDEN_PW=${BITWARDEN_PW:-}
export NO_BITWARDEN_LOGIN=${NO_BITWARDEN_LOGIN-1}
if [[ -n $NO_BITWARDEN_LOGIN ]] || [[ -z $BITWARDEN_PW ]];then
    debuglog "Skip bitwarden login"
else
    gosu $USER_NAME bash -li <<EOF
nvm use &>/dev/null
bw config server $BITWARDEN_SERVER
bw login $BITWARDEN_EMAIL $BITWARDEN_PW
EOF
fi
# vim:set et sts=4 ts=4 tw=80:
