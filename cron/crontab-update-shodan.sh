#!/bin/bash

CONFIG_GLOBAL="/usr/local/etc/osint/config.json"
CONFIG_LOCAL="$HOME/.osint.json"
DATE=$(date "+%Y-%m-%d")

# Check what config file to use
if [ -f "$CONFIG_GLOBAL" ] && [ -r "$CONFIG_GLOBAL" ];
then
  CONFIG_FILE=${CONFIG_GLOBAL}  
else
  if [ -f "$CONFIG_LOCAL" ] && [ -r "$CONFIG_LOCAL" ];
  then
    CONFIG_FILE=${CONFIG_LOCAL}
  else
    echo "No config file was found!"
    exit 1
  fi
fi
# Read the settings from CONFIG
GITDIR=$(cat ${CONFIG_FILE} | jq -r .path.basedir)
BINDIR=$(cat ${CONFIG_FILE} | jq -r .path.bindir)
LOGDIR=$(cat ${CONFIG_FILE} | jq -r .path.logdir)
KEYCHAIN=$(cat ${CONFIG_FILE} | jq -r .path.keychain)
SIGNAL_SRC=$(cat ${CONFIG_FILE} | jq -r .signal.src)
SIGNAL_DST=$(cat ${CONFIG_FILE} | jq -r .signal.dst)

RESULT_UPDATE=""
RESULT_GIT=""

echo "$(date '+%Y-%m-%d %H:%M:%S,000') - crontab-update-shodan - INFO - BEGIN." >> ${LOGDIR}/crontab.log
echo "$(date '+%Y-%m-%d %H:%M:%S,000') - crontab-update-shodan - INFO - Executing update-shodan." >> ${LOGDIR}/crontab.log

# Execute update script (list/id/path)
RESULT=`${BINDIR}/update-shodan.py -au`
# Is there a message?
if [ -n "$RESULT" ]
then
    RESULT_UPDATE="FAILED"
else
    RESULT_UPDATE="OK"
fi

echo "$(date '+%Y-%m-%d %H:%M:%S,000') - crontab-update-shodan - INFO - Setting ssh environment variables from keychain." >> ${LOGDIR}/crontab.log
. ${KEYCHAIN}

# git commit the changes
cd ${GITDIR}
echo "$(date '+%Y-%m-%d %H:%M:%S,000') - crontab-update-shodan - INFO - Executing git coommit + push." >> ${LOGDIR}/crontab.log
if OUTPUT=$(/usr/bin/git commit -a -m "factory-worker: auto-commit ${DATE}" && /usr/bin/git push 2>&1); then
  RESULT_GIT="OK"
else 
  RESULT_GIT="FAILED"
fi

# Just let me know
echo "$(date '+%Y-%m-%d %H:%M:%S,000') - crontab-update-shodan - INFO - Sending notification." >> ${LOGDIR}/crontab.log
echo -e "update-shodan: ${RESULT_UPDATE}\ngit-commit: ${RESULT_GIT}\n\n${OUTPUT}" | /usr/local/bin/signal-cli -u "${SIGNAL_SRC}" send "${SIGNAL_DST}"
echo "$(date '+%Y-%m-%d %H:%M:%S,000') - crontab-update-shodan - INFO - END." >> ${LOGDIR}/crontab.log
