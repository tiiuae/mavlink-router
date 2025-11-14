#!/bin/bash -e

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

args=("$@")

# Takes a list of arguments and prints transformed ones,
# replacing HOSTNAME[...] patterns with IPs.
resolve_hostnames() {
    local arg
    local new_args=()

    for arg in "$@"; do
        # Check if the argument contains a HOSTNAME[...] pattern
        if [[ $arg =~ HOSTNAME\[([^]]*)\] ]]; then
            local full_match="${BASH_REMATCH[0]}"  # e.g., HOSTNAME[example.com]
            local hostname="${BASH_REMATCH[1]}"    # e.g., example.com

            local ip
            ip=$(getent hosts "$hostname" | awk '{print $1; exit}')

            if [[ -z $ip ]]; then
                echo "Error: could not resolve hostname '$hostname'" >&2
                exit 1
            fi

            # Replace the matched pattern with the resolved IP
            arg=${arg//"$full_match"/$ip}
        fi
        new_args+=("$arg")
    done

    # Print all transformed arguments
    printf '%s\n' "${new_args[@]}"
}

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
    exec /usr/bin/mavlink-routerd -c /etc/mavlink-router/default.conf

else
    # mavlink-router does not support hostnames but raw IPs only 🫠
    # this transforms args like `-e HOSTNAME[fog-navigation]:14590` into `-e 10.20.30.40:14590` where the IP is resolved.
    args_with_hostnames_resolved=($(resolve_hostnames "${args[@]}"))

    exec /usr/bin/mavlink-routerd "${args_with_hostnames_resolved[@]}"
fi

