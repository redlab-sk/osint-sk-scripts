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

RESULT_UPDATE_DOWNLOAD=""
RESULT_UPDATE_ACTUAL=""
RESULT_UPDATE_TRENDS=""
RESULT_GIT=""

echo "$(date '+%Y-%m-%d %H:%M:%S,000') - crontab-update-sknic - INFO - BEGIN." >> ${LOGDIR}/crontab.log
echo "$(date '+%Y-%m-%d %H:%M:%S,000') - crontab-update-sknic - INFO - Executing update-sknic." >> ${LOGDIR}/crontab.log

# Execute update script to download source data
RESULT=`${BINDIR}/update-sknic.py`
# Finished OK?
if [ $? -ne 0 ]
then
    RESULT_UPDATE_DOWNLOAD="FAILED"
else
    DOWNLOAD_DOMAINS_SIZE=$(echo ${RESULT} | jq -r .domains.size)
    DOWNLOAD_DOMAINS_FILE=$(echo ${RESULT} | jq -r .domains.file)
    DOWNLOAD_REGISTRARS_SIZE=$(echo ${RESULT} | jq -r .registrars.size)
    DOWNLOAD_REGISTRARS_FILE=$(echo ${RESULT} | jq -r .registrars.file)
    RESULT_UPDATE_DOWNLOAD=" * domains : ${DOWNLOAD_DOMAINS_SIZE}\n * registrars ${DOWNLOAD_REGISTRARS_SIZE}"
fi

# Execute update to generate actual stats
RESULT=`${BINDIR}/update-sknic.py -a -f ${DOWNLOAD_DOMAINS_FILE} -r ${DOWNLOAD_REGISTRARS_FILE}`
# Finished OK?
if [ $? -ne 0 ]
then
    RESULT_UPDATE_ACTUAL="FAILED"
else
    RESULT_UPDATE_ACTUAL="OK"
fi

# Execute update to generate trends
RESULT=`${BINDIR}/update-sknic.py -u`
# Finished OK?
if [ $? -ne 0 ]
then
    RESULT_UPDATE_TRENDS="FAILED"
else
    RESULT_UPDATE_TRENDS="OK"
fi

# Load sh env from keychain
echo "$(date '+%Y-%m-%d %H:%M:%S,000') - crontab-update-sknic - INFO - Setting ssh environment variables from keychain." >> ${LOGDIR}/crontab.log
. ${KEYCHAIN}

# git commit the changes
cd ${GITDIR}
echo "$(date '+%Y-%m-%d %H:%M:%S,000') - crontab-update-sknic - INFO - Executing git commit + push." >> ${LOGDIR}/crontab.log
if OUTPUT=$(/usr/bin/git commit -a -m "factory-worker: auto-commit ${DATE}" && /usr/bin/git push 2>&1); then
  RESULT_GIT="OK"
else 
  RESULT_GIT="FAILED"
fi

# Just let me know
echo "$(date '+%Y-%m-%d %H:%M:%S,000') - crontab-update-sknic - INFO - Sending notification." >> ${LOGDIR}/crontab.log
echo -e "[update-sknic]\ndownload:\n${RESULT_UPDATE_DOWNLOAD}\nstats: ${RESULT_UPDATE_ACTUAL}\ntrends:${RESULT_UPDATE_TRENDS}\ngit-commit: ${RESULT_GIT}\n\n${OUTPUT}" | /usr/local/bin/signal-cli -u "${SIGNAL_SRC}" send "${SIGNAL_DST}"
echo "$(date '+%Y-%m-%d %H:%M:%S,000') - crontab-update-sknic - INFO - END." >> ${LOGDIR}/crontab.log



