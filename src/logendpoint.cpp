/*
 * This file is part of the MAVLink Router project
 *
 * Copyright (C) 2017  Intel Corporation. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "logendpoint.h"

#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <common/log.h>
#include <common/util.h>

#include "mainloop.h"

#define STOPPING_TIMEOUT 3
#define ALIVE_TIMEOUT    5
#define MAX_RETRIES      10

#define STARTING_TIMEOUT_MS 1000
#define STOPPING_TIMEOUT_MS (STOPPING_TIMEOUT * 1000)
#define ALIVE_TIMEOUT_MS    (ALIVE_TIMEOUT * 1000)

// clang-format off
const ConfFile::OptionsTable LogEndpoint::option_table[] = {
    {"Log",             false, ConfFile::parse_stdstring,           OPTIONS_TABLE_STRUCT_FIELD(LogOptions, logs_dir)},
    {"LogMode",         false, LogEndpoint::parse_log_mode,         OPTIONS_TABLE_STRUCT_FIELD(LogOptions, log_mode)},
    {"MavlinkDialect",  false, LogEndpoint::parse_mavlink_dialect,  OPTIONS_TABLE_STRUCT_FIELD(LogOptions, mavlink_dialect)},
    {"MinFreeSpace",    false, ConfFile::parse_ul,                  OPTIONS_TABLE_STRUCT_FIELD(LogOptions, min_free_space)},
    {"MaxLogFiles",     false, ConfFile::parse_ul,                  OPTIONS_TABLE_STRUCT_FIELD(LogOptions, max_log_files)},
    {"LogSystemId",     false, LogEndpoint::parse_fcu_id,           OPTIONS_TABLE_STRUCT_FIELD(LogOptions, fcu_id)},
    {}
};
// clang-format on

LogEndpoint::LogEndpoint(std::string name, LogOptions conf)
    : Endpoint{ENDPOINT_TYPE_LOG, std::move(name)}
    , _config{conf}
{
    assert(!_config.logs_dir.empty());
    _add_sys_comp_id(LOG_ENDPOINT_SYSTEM_ID, 0);
    _fsync_cb.aio_fildes = -1;
    _fsync_data_cb.aio_fildes = -1;

#if HAVE_DECL_AIO_INIT
    aioinit aio_init_data{};
    aio_init_data.aio_threads = 1;
    aio_init_data.aio_num = 1;
    aio_init_data.aio_idle_time = 3; // make sure to keep the thread running
    aio_init(&aio_init_data);
#endif
    if (_config.fcu_id != -1) {
        _target_system_id = _config.fcu_id;
    } else {
        _target_system_id = -1;
    }
}

void LogEndpoint::_send_msg(const mavlink_message_t *msg, int target_sysid)
{
    uint8_t data[MAVLINK_MAX_PACKET_LEN] = {};
    struct buffer buffer = {};

    buffer.data = data;
    buffer.len = mavlink_msg_to_send_buffer(data, msg);
    buffer.curr.msg_id = msg->msgid;
    buffer.curr.target_sysid = target_sysid;
    buffer.curr.target_compid = MAV_COMP_ID_ALL;
    buffer.curr.src_sysid = msg->sysid;
    buffer.curr.src_compid = msg->compid;
    /* don't bother with it as it's only used by Log backends */
    buffer.curr.payload_len = 0;

    Mainloop::get_instance().route_msg(&buffer);

    _stat.read.total++;
    _stat.read.handled++;
    _stat.read.handled_bytes += buffer.len;
}

void LogEndpoint::mark_unfinished_logs()
{
    DIR *dir = opendir(_config.logs_dir.c_str());

    // Assume the directory does not exist if opendir failed
    if (!dir) {
        return;
    }

    struct dirent *ent;
    uint32_t u;

    while ((ent = readdir(dir)) != nullptr) {
        if (sscanf(ent->d_name, "%u-", &u) != 1) {
            continue;
        }

        char log_file[PATH_MAX];
        struct stat file_stat;
        if (snprintf(log_file, sizeof(log_file), "%s/%s", _config.logs_dir.c_str(), ent->d_name)
            >= (int)sizeof(log_file)) {
            continue;
        }

        if (stat(log_file, &file_stat)) {
            continue;
        }

        if (S_ISREG(file_stat.st_mode) && (file_stat.st_mode & S_IWUSR)) {
            log_info("File %s not read-only yet, marking as RO", ent->d_name);
            chmod(log_file, S_IRUSR | S_IRGRP | S_IROTH);
        }
    }
    closedir(dir);
}

void LogEndpoint::_delete_old_logs()
{
    struct statvfs buf;
    uint64_t free_space;

    if (statvfs(_config.logs_dir.c_str(), &buf) == 0) {
        free_space = (uint64_t)buf.f_bsize * buf.f_bavail;
    } else if (errno == ENOENT) {
        // Ignore error - we don't have any logs to delete if directory
        // doesn't exist
        return;
    } else {
        free_space = UINT64_MAX;
        log_error("[Log Deletion] Error when measuring free disk space: %m");
    }

    log_debug("[Log Deletion]  Total free space: %" PRIu64 "MB. Min free space: %luMB",
              free_space / (1ul << 20),
              _config.min_free_space / (1ul << 20));

    // This check is not necessary, it just saves on some file IO.
    if (free_space > _config.min_free_space && _config.max_log_files == 0) {
        return;
    }

    DIR *dir = opendir(_config.logs_dir.c_str());

    // Assume the directory does not exist if opendir failed
    if (!dir) {
        return;
    }

    int dir_fd = dirfd(dir);
    if (dir_fd < 0) {
        closedir(dir);
        log_error("[Log Deletion] Error getting dir file descriptor: %m");
        return;
    }

    // Map of index -> (filename, file size)
    // All three of these values are saved for later to reduce the amount of IO operations needed.
    std::map<unsigned long, std::tuple<std::string, unsigned long>> file_map;

    struct dirent *ent;
    uint32_t idx, year, month, day, hour, minute, second;

    // This loop just gathers the name, index, and size of each read-only file in the log dir
    while ((ent = readdir(dir)) != nullptr) {
        // Even though we don't need the timestamp, we want to match as much of the filename as
        // possible, so we don't accidentally delete something that isn't a log.
        if (sscanf(ent->d_name,
                   "%u-%u-%u-%u_%u-%u-%u.",
                   &idx,
                   &year,
                   &month,
                   &day,
                   &hour,
                   &minute,
                   &second)
            == 7) {
            struct stat file_stat;
            if (!fstatat(dir_fd, ent->d_name, &file_stat, 0)) {
                // Only bother with read-only files. If this function is somehow called while a file
                // is still being used (not read-only), it should not be deleted.
                if (!S_ISDIR(file_stat.st_mode) && !(file_stat.st_mode & S_IWUSR)) {
                    std::string str(ent->d_name);
                    file_map[idx] = std::make_tuple(str, file_stat.st_size);
                }
            }
        }
    }

    // If the configured value for min_free_space is 0, then we don't have to do anything special.
    int64_t bytes_to_delete = _config.min_free_space - free_space;
    // If the configured value for max_log_files is 0, then set this to -1 to indicate that we've
    // already deleted enough files.
    ssize_t files_to_delete
        = _config.max_log_files > 0 ? (ssize_t)file_map.size() - _config.max_log_files : -1;

    log_debug("[Log Deletion] Files to delete: %zd", files_to_delete);

    // Delete the logs in order until there's enough free space, and few enough files
    // It is possible for this loop to run only once and return immediately, if we don't actually
    // need to delete any files. Maps in C++ are ordered by the keys, so this iteration is
    // guaranteed to happen in index order (oldest -> newest)
    for (auto &pair : file_map) {
        if (bytes_to_delete <= 0 && files_to_delete <= 0) {
            break;
        }

        std::string &filename = std::get<0>(pair.second);
        const unsigned long filesize = std::get<1>(pair.second);
        char log_file[PATH_MAX];
        if (snprintf(log_file,
                     sizeof(log_file),
                     "%s/%s",
                     _config.logs_dir.c_str(),
                     filename.c_str())
            >= (int)sizeof(log_file)) {
            log_error("Directory + filename %s is longer than PATH_MAX of %d",
                      filename.c_str(),
                      PATH_MAX);
            continue;
        }

        int err_code = remove(log_file);
        if (err_code == 0) {
            bytes_to_delete -= filesize;
            files_to_delete--;
            log_info("[Log Deletion] Deleted old logfile %s", filename.c_str());
        } else {
            log_error("[Log Deletion] Error deleting old logfile %s: %m", filename.c_str());
        }
    }

    if (bytes_to_delete > 0) {
        log_error(
            "[Log Deletion] Deleted all closed logs, but there is still not enough free space.");
    }

    closedir(dir);
}

uint32_t LogEndpoint::_get_prefix(DIR *dir)
{
    struct dirent *ent;
    uint32_t u, prefix = 0;

    while ((ent = readdir(dir)) != nullptr) {
        if (sscanf(ent->d_name, "%u-", &u) == 1) {
            if (u >= prefix && u < UINT32_MAX) {
                prefix = ++u;
            }
        }
    }

    return prefix;
}

DIR *LogEndpoint::_open_or_create_dir(const char *name)
{
    int r;
    DIR *dir = opendir(name);

    // If failed because dir doesn't exist, try to create it
    if (!dir && errno == ENOENT) {
        r = mkdir_p(name, strlen(name), 0755);
        if (r < 0) {
            errno = -r;
            return nullptr;
        }
        dir = opendir(name);
    }

    return dir;
}

int LogEndpoint::_get_file(const char *extension, char *filename, size_t fnamesize,
                           bool use_exact_name)
{
    time_t t = time(nullptr);
    struct tm *timeinfo = localtime(&t);
    uint32_t i;
    int j, r;
    DIR *dir;
    int dir_fd;

    dir = _open_or_create_dir(_config.logs_dir.c_str());
    if (!dir) {
        log_error("Could not open log dir (%m)");
        return -1;
    }
    // Close dir when leaving function.
    std::shared_ptr<void> defer(dir, [](DIR *p) { closedir(p); });

    i = _get_prefix(dir);
    dir_fd = dirfd(dir);

    for (j = 0; j <= MAX_RETRIES; j++) {
        if (use_exact_name) {
            if (strlen(filename) >= fnamesize) {
                log_error("Filename too long");
                return -1;
            }
            r = strlen(filename);
        } else {
            r = snprintf(filename,
                         fnamesize,
                         "%05u-%i-%02i-%02i_%02i-%02i-%02i.%s",
                         i + j,
                         timeinfo->tm_year + 1900,
                         timeinfo->tm_mon + 1,
                         timeinfo->tm_mday,
                         timeinfo->tm_hour,
                         timeinfo->tm_min,
                         timeinfo->tm_sec,
                         extension);
        }

        if (r < 1 || (size_t)r >= fnamesize) {
            log_error("Error formatting Log file name: (%m)");
            return -1;
        }

        r = openat(dir_fd, filename, O_WRONLY | O_CLOEXEC | O_CREAT | O_NONBLOCK | O_EXCL, 0644);
        if (r < 0) {
            if (errno != EEXIST) {
                log_error("Unable to open Log file(%s): (%m)", filename);
                return -1;
            }
            if (!use_exact_name) {
                continue;
            } else {
                log_error("Log file(%s) already exists: (%m)", filename);
                return -1;
            }
        }

        // Ensure the directory entry of the file is written to disk
        if (fsync(dir_fd) == -1) {
            log_error("fsync failed: %m");
        }

        return r;
    }

    log_error("Unable to create a Log file without override another file.");
    return -EEXIST;
}

void LogEndpoint::stop()
{
    std::lock_guard<std::recursive_mutex> lock(_state_mtx);
    if (_is_logging_start_initiated()) {
        _handle_logging_state(LoggingState::stopping);
    } else {
        _handle_logging_state(LoggingState::idle);
    }
}

void LogEndpoint::_do_stop()
{
    Mainloop &mainloop = Mainloop::get_instance();

    if (_timeout.fsync) {
        mainloop.del_timeout(_timeout.fsync);
        _timeout.fsync = nullptr;
    }

    char log_file[PATH_MAX];

    if (_timeout.fsync_data) {
        mainloop.del_timeout(_timeout.fsync_data);
        _timeout.fsync_data = nullptr;
    }

    log_info("Concatenate Data & Ulg files");
    fsync(_datafile);
    close(_datafile);
    _datafile = -1;
    _fsync_data_cb.aio_fildes = -1;

    // copy data file in the end of ulg file
    if (snprintf(log_file, sizeof(log_file), "%s/%s", _config.logs_dir.c_str(), _datafilename)
        < (int)sizeof(log_file)) {
        int r = open(log_file, O_RDONLY);
        if (r >= 0) {
            ssize_t cnt = 0;
            while ((cnt = read(r, _data_buf, LOG_ENDPOINT_DATA_BUF_SIZE)) > 0) {
                write(_file, _data_buf, cnt);
            }
            close(r);
        } else {
            log_error("Unable to open Data file for concatenation (%s): (%m)", log_file);
        }
    }

    fsync(_file);
    close(_file);
    _file = -1;
    _fsync_cb.aio_fildes = -1;

    // Remove data file
    int err = remove(log_file);
    if (err < 0) {
        log_error("Error deleting datafile %s: %m", log_file);
    }

    // change file permissions to read-only to mark them as finished
    if (snprintf(log_file, sizeof(log_file), "%s/%s", _config.logs_dir.c_str(), _filename)
        < (int)sizeof(log_file)) {
        chmod(log_file, S_IRUSR | S_IRGRP | S_IROTH);
    }
    log_info("Logging ended.");
}

bool LogEndpoint::start()
{
    std::lock_guard<std::recursive_mutex> lock(_state_mtx);
    if (_logging_state == LoggingState::idle) {
        _handle_logging_state(LoggingState::starting);
        return true;
    }
    return false;
}

bool LogEndpoint::_do_start()
{
    char *dot = nullptr;

    if (_file != -1) {
        log_warning("Log already started");
        return false;
    }

    // Clear up space before opening a new file
    _delete_old_logs();

    _file = _get_file(_get_logfile_extension(), _filename, sizeof(_filename));
    if (_file < 0) {
        _file = -1;
        return false;
    }

    // Generate _datafilename from _filename by replacing .ulg with .data
    strncpy(_datafilename, _filename, sizeof(_datafilename));
    dot = strpbrk(_datafilename, ".");
    dot[0] = '\0';
    strncat(_datafilename, ".data", sizeof(_datafilename));

    // get file handle by using given _datafilename instead of generating it
    //  use_exact_name = true
    _datafile = _get_file("data", _datafilename, sizeof(_datafilename), true);
    if (_datafile < 0) {
        _datafile = -1;
        return false;
    }

    // Call fsync once per second
    _timeout.fsync = Mainloop::get_instance().add_timeout(MSEC_PER_SEC,
                                                          std::bind(&LogEndpoint::_fsync, this),
                                                          this);
    if (!_timeout.fsync) {
        log_error("Unable to add timeout");
        goto fsync_timeout_error;
    }

    // Call fsync_data once per second
    _timeout.fsync_data
        = Mainloop::get_instance().add_timeout(MSEC_PER_SEC,
                                               std::bind(&LogEndpoint::_fsync_data, this),
                                               this);
    if (!_timeout.fsync_data) {
        log_error("Unable to add timeout");
        goto fsync_timeout_error;
    }

    log_info("Logging target system_id=%u on %s (data: %s)",
             _target_system_id,
             _filename,
             _datafilename);
    return true;

fsync_timeout_error:
    close(_file);
    _file = -1;
    close(_datafile);
    _datafile = -1;
    return false;
}

bool LogEndpoint::_state_timeout()
{
    std::lock_guard<std::recursive_mutex> lock(_state_mtx);

    switch (_logging_state) {
    case LoggingState::starting:
        // Timeout getting ack for start logging message
        // retry starting
        log_warning("No ack received for start logging message, retrying..");
        _logging_start_timeout();
        break;
    case LoggingState::started:
        if (_timeout_write_total == _stat.write.total) {
            log_warning("No Log messages received in %u seconds...", ALIVE_TIMEOUT);
        }
        _timeout_write_total = _stat.write.total;
        break;
    case LoggingState::stopping:
        if (_timeout_write_total == _stat.write.total) {
            log_info("All log messages received, stop logging");
            _handle_logging_state(LoggingState::stopped);
        }
        _timeout_write_total = _stat.write.total;
        break;
    case LoggingState::stopped:
        log_error("timeout in stopped state");
        break;
    case LoggingState::idle:
        log_error("timeout in idle state");
        break;
    case LoggingState::error:
        log_error("timeout in error state");
        break;
    }

    return true;
}

bool LogEndpoint::_stopping_timeout()
{
    return true;
}

bool LogEndpoint::_alive_timeout()
{
    return true;
}

bool LogEndpoint::_fsync()
{
    if (_file < 0) {
        return false;
    }

    if (_fsync_cb.aio_fildes >= 0 && aio_error(&_fsync_cb) == EINPROGRESS) {
        // previous operation is still in progress
        return true;
    }
    _fsync_cb.aio_fildes = _file;
    _fsync_cb.aio_sigevent.sigev_notify = SIGEV_NONE;

    aio_fsync(O_SYNC, &_fsync_cb);

    return true;
}

bool LogEndpoint::_fsync_data()
{
    if (_datafile < 0) {
        return false;
    }

    if (_fsync_data_cb.aio_fildes >= 0 && aio_error(&_fsync_data_cb) == EINPROGRESS) {
        // previous operation is still in progress
        return true;
    }
    _fsync_data_cb.aio_fildes = _datafile;
    _fsync_data_cb.aio_sigevent.sigev_notify = SIGEV_NONE;

    aio_fsync(O_SYNC, &_fsync_data_cb);

    return true;
}

bool LogEndpoint::_start_state_timeout(uint32_t timeout_ms)
{
    _timeout.state
        = Mainloop::get_instance().add_timeout(timeout_ms,
                                               std::bind(&LogEndpoint::_state_timeout, this),
                                               this);

    return !!_timeout.state;
}

void LogEndpoint::_remove_state_timeout()
{
    if (!_timeout.state) {
        return;
    }
    Mainloop::get_instance().del_timeout(_timeout.state);
    _timeout.state = nullptr;
}

void LogEndpoint::_handle_auto_start_stop(const struct buffer *pbuf)
{
    // wait until initialized
    if (_target_system_id == -1) {
        return;
    }

    if (_is_logging_error()) {
        return;
    }

    if (_config.log_mode == LogMode::always) {
        if (!_is_logging_start_initiated()) {
            if (!start()) {
                _config.log_mode = LogMode::disabled;
            }
        }

        return;
    }

    if (_config.log_mode == LogMode::while_armed) {
        if (pbuf->curr.msg_id == MAVLINK_MSG_ID_HEARTBEAT
            && pbuf->curr.src_sysid == _target_system_id
            && pbuf->curr.src_compid == MAV_COMP_ID_AUTOPILOT1) {

            const mavlink_heartbeat_t *heartbeat = (mavlink_heartbeat_t *)pbuf->curr.payload;
            const bool is_armed = heartbeat->base_mode & MAV_MODE_FLAG_SAFETY_ARMED;

            if (is_logging_idle() && is_armed) {
                log_info("Arming detected");
                if (!start()) {
                    log_warning("Could not start logging on arming, yet. Retrying..");
                }
            } else if (_is_logging_start_initiated() && !is_armed) {
                log_info("Disarming detected");
                stop();
            }
        }
    }
}

int LogEndpoint::parse_mavlink_dialect(const char *val, size_t val_len, void *storage,
                                       size_t storage_len)
{
    assert(val);
    assert(storage);
    assert(val_len);

    auto *dialect = (LogOptions::MavDialect *)storage;

    if (storage_len < sizeof(LogOptions::mavlink_dialect)) {
        return -ENOBUFS;
    }
    if (val_len > INT_MAX) {
        return -EINVAL;
    }

    if (memcaseeq(val, val_len, "auto", sizeof("auto") - 1)) {
        *dialect = LogOptions::MavDialect::Auto;
    } else if (memcaseeq(val, val_len, "common", sizeof("common") - 1)) {
        *dialect = LogOptions::MavDialect::Common;
    } else if (memcaseeq(val, val_len, "ardupilotmega", sizeof("ardupilotmega") - 1)) {
        *dialect = LogOptions::MavDialect::Ardupilotmega;
    } else {
        log_error("Invalid argument for MavlinkDialect = %.*s", (int)val_len, val);
        return -EINVAL;
    }

    return 0;
}

#define MAX_LOG_MODE_SIZE 20
int LogEndpoint::parse_log_mode(const char *val, size_t val_len, void *storage, size_t storage_len)
{
    assert(val);
    assert(storage);
    assert(val_len);

    if (storage_len < sizeof(LogOptions::log_mode)) {
        return -ENOBUFS;
    }
    if (val_len > MAX_LOG_MODE_SIZE) {
        return -EINVAL;
    }

    const char *log_mode_str = strndupa(val, val_len);
    LogMode log_mode;
    if (strcaseeq(log_mode_str, "always")) {
        log_mode = LogMode::always;
    } else if (strcaseeq(log_mode_str, "while-armed")) {
        log_mode = LogMode::while_armed;
    } else {
        log_error("Invalid argument for LogMode = %s", log_mode_str);
        return -EINVAL;
    }
    *((LogMode *)storage) = log_mode;

    return 0;
}
#undef MAX_LOG_MODE_SIZE

int LogEndpoint::parse_fcu_id(const char *val, size_t val_len, void *storage, size_t storage_len)
{
    const int i_ret = ConfFile::parse_i(val, val_len, storage, storage_len);
    if (i_ret != 0) {
        return i_ret;
    }

    if (*(int *)storage > 255 || *(int *)storage <= 0) {
        log_error("Invalid argument for FcuId = %.*s, should be in [0, 255]", (int)val_len, val);
        return -EINVAL;
    }

    return 0;
}

void LogEndpoint::_handle_logging_state(LoggingState new_state)
{

    if (_logging_state == new_state) {
        return;
    }

    _remove_state_timeout();

    switch (new_state) {
    case LoggingState::starting:
        log_info("[LOGGING] Starting..");
        _logging_state = new_state;
        if (!_do_start()) {
            _handle_logging_state(LoggingState::error);
        } else {
            _logging_start_timeout();
            _start_state_timeout(STARTING_TIMEOUT_MS);
        }
        break;
    case LoggingState::started:
        log_info("[LOGGING] Started");
        _logging_state = new_state;
        _start_state_timeout(ALIVE_TIMEOUT_MS);
        break;
    case LoggingState::stopping:
        log_info("[LOGGING] Stopping..");
        _logging_state = new_state;
        _start_state_timeout(STOPPING_TIMEOUT_MS);
        break;
    case LoggingState::stopped:
        log_info("[LOGGING] Stopped -> Flushing..");
        _logging_state = new_state;
        flush_pending_msgs();
        _do_stop();
        _handle_logging_state(LoggingState::idle);
        break;
    case LoggingState::idle:
        log_info("[LOGGING] Idle");
        _logging_state = new_state;
        break;
    case LoggingState::error:
        log_error("[LOGGING] Error");
        _logging_state = new_state;
        break;
    }
}

bool LogEndpoint::_is_logging_waiting_for_start()
{
    std::lock_guard<std::recursive_mutex> lock(_state_mtx);
    return (_logging_state == LoggingState::starting);
}

bool LogEndpoint::_is_logging_start_initiated()
{
    std::lock_guard<std::recursive_mutex> lock(_state_mtx);
    return (_logging_state == LoggingState::started || _logging_state == LoggingState::starting);
}

bool LogEndpoint::_is_logging_error()
{
    std::lock_guard<std::recursive_mutex> lock(_state_mtx);
    return (_logging_state == LoggingState::error);
}

bool LogEndpoint::is_logging_idle()
{
    std::lock_guard<std::recursive_mutex> lock(_state_mtx);
    return (_logging_state == LoggingState::idle);
}
