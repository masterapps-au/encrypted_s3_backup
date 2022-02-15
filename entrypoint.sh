#!/bin/bash
set -o noglob
declare -p | grep -Ev 'BASHOPTS|BASH_VERSINFO|EUID|PPID|SHELLOPTS|UID' > /container.env
CRONTAB=${CRONTAB:-"0 * * * *"}
echo "SHELL=/bin/bash
BASH_ENV=/container.env
$CRONTAB /encrypted_s3_backup.py >/proc/1/fd/1 2>/proc/1/fd/2
" > scheduler.txt
echo "encrypted_s3_backup docker has started with crontab of: $CRONTAB" >/proc/1/fd/1 2>/proc/1/fd/2
set +o noglob
crontab scheduler.txt
cron -f
