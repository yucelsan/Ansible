#!/bin/bash

# - ANSIBLE PLAYBOOK
# - AUTHOR : SERDAR AYSAN
# - COMPANY : YUCELSAN

# Génère un délai aléatoire entre 0 et 1200 secondes (20 minutes)
DELAY=$((RANDOM % 1200))

# Affiche le délai pour des raisons de débogage (facultatif)
echo "Waiting for $DELAY seconds before executing the task"

# Attend pendant le délai aléatoire
sleep $DELAY

set -e
echo $(date) "Time Scan Begins" >>/var/log/mdav_crontab_full_scan.log
/bin/mdatp scan full >> /var/log/mdav_crontab_full_scan.log
echo $(date) "Time Scan Finished" >>/var/log/mdav_crontab_full_scan.log
exit 0
