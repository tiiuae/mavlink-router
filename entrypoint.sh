#!/bin/bash

# To enable flight logging, define LOGGING_DIR env variable
#
# Env variables:
# LOGGING_DIR      : Full path to directory where flight logs are written to
# LOGGING_MODE     : Trigger event to start logging. Values:
#                      "while-armed" or "always". Default: "while-armed"
# LOGGING_MIN_FREE : Auto-delete old log files until there's at least the
#                    configured amount of bytes free on the storage device.
#                    Set to 0 to disable this functionality. Default: 0 (disabled)
# LOGGING_MAX_FILES: Auto-delete old log files until there are less than
#                    configured amount of logfiles in the log folder.
#                    Set to 0 to disable this functionality. Default: 0 (disabled)

args=$@

if [ "${LOGGING_DIR}" != "" ]; then
    # Mavlink logging enabled
    log_mode=${LOGGING_MODE:-"while-armed"}
    min_free_space=${LOGGING_MIN_FREE:-0}
    max_log_files=${LOGGING_MAX_FILES:-0}
    echo "Logging into '${LOGGING_DIR}' - triggered: '${log_mode}'"
    if [ $min_free_space != 0 ]; then
        echo "Auto-delete old logfiles until storage space above ${min_free_space} bytes"
        sed -i "/.General./a \ \ \ \ MinFreeSpace=${min_free_space}" /etc/mavlink-router/default.conf
    elif [ $max_log_files != 0 ]; then
        echo "Auto-delete old logfiles if more than ${max_log_files} logfiles found"
        sed -i "/.General./a \ \ \ \ MaxLogFiles=${max_log_files}" /etc/mavlink-router/default.conf
    fi
    sed -i "/.General./a \ \ \ \ LogMode=${log_mode}" /etc/mavlink-router/default.conf
    sed -i "/.General./a \ \ \ \ Log=${LOGGING_DIR}" /etc/mavlink-router/default.conf

    echo " "
    /usr/bin/mavlink-routerd -c /etc/mavlink-router/default.conf

elif [ "$1" != "" ]; then
    /usr/bin/mavlink-routerd $args
else
    /usr/bin/mavlink-routerd
fi

