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
#include "ulog.h"

#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <common/log.h>
#include <common/util.h>

#define ULOG_HEADER_SIZE 16
#define ULOG_MAGIC                               \
    {                                            \
        0x55, 0x4C, 0x6F, 0x67, 0x01, 0x12, 0x35 \
    }

#define NO_FIRST_MSG_OFFSET 255

struct _packed_ ulog_msg_header {
    uint16_t msg_size;
    uint8_t msg_type;
};

bool ULog::_logging_start_timeout()
{
    mavlink_message_t msg;
    mavlink_command_long_t cmd;

    bzero(&cmd, sizeof(cmd));
    cmd.command = MAV_CMD_LOGGING_START;
    cmd.target_component = MAV_COMP_ID_ALL;
    cmd.target_system = _target_system_id;

    mavlink_msg_command_long_encode(LOG_ENDPOINT_SYSTEM_ID, MAV_COMP_ID_ALL, &msg, &cmd);
    _send_msg(&msg, _target_system_id);

    return true;
}

bool ULog::start()
{
    if (!LogEndpoint::start()) {
        return false;
    }

    _waiting_header = true;
    _waiting_first_msg_offset = false;
    _expected_seq = 0;
    _buffer_len = 0;
    _buffer_index = 0;
    _buffer_partial_len = 0;

    _expected_data_seq = 0;
    _data_waiting_first_msg_offset = false;
    _data_buffer_len = 0;
    _data_buffer_index = 0;
    _data_buffer_partial_len = 0;
    return true;
}

void ULog::stopping()
{
    mavlink_message_t msg;
    mavlink_command_long_t cmd;

    if (_file == -1) {
        log_info("ULog not started");
        return;
    }
    if (_closing) {
        return;
    }
    _closing = true;

    bzero(&cmd, sizeof(cmd));
    cmd.command = MAV_CMD_LOGGING_STOP;
    cmd.target_component = MAV_COMP_ID_ALL;
    cmd.target_system = _target_system_id;

    mavlink_msg_command_long_encode(LOG_ENDPOINT_SYSTEM_ID, MAV_COMP_ID_ALL, &msg, &cmd);
    _send_msg(&msg, _target_system_id);

    if (_force_stop) {
        stop();
    }
    _force_stop = false;
    LogEndpoint::stopping();
}

void ULog::stop()
{
    _buffer_len = 0;
    _data_buffer_len = 0;
    log_info("Log stop send, flushing...");
    /* Write the last partial message to avoid corrupt the end of the file */
    while (_buffer_partial_len) {
        if (!_logging_flush()) {
            break;
        }
    }
    while (_data_buffer_partial_len) {
        if (!_logging_flush_data()) {
            break;
        }
    }
    LogEndpoint::stop();
    _closing = false;
}

int ULog::write_msg(const struct buffer *buffer)
{
    const bool mavlink2 = buffer->data[0] == MAVLINK_STX;
    uint8_t trimmed_zeros;

    /* set the expected system id to the first autopilot that we get a heartbeat from */
    if (_target_system_id == -1 && buffer->curr.msg_id == MAVLINK_MSG_ID_HEARTBEAT
        && buffer->curr.src_compid == MAV_COMP_ID_AUTOPILOT1) {
        _target_system_id = buffer->curr.src_sysid;
    }

    /* Check if we should start or stop logging */
    _handle_auto_start_stop(buffer);

    /* Check if we are interested in this msg_id */
    if (buffer->curr.msg_id != MAVLINK_MSG_ID_COMMAND_ACK
        && buffer->curr.msg_id != MAVLINK_MSG_ID_LOGGING_DATA_ACKED
        && buffer->curr.msg_id != MAVLINK_MSG_ID_LOGGING_DATA) {
        return buffer->len;
    }

    const mavlink_msg_entry_t *msg_entry = mavlink_get_msg_entry(buffer->curr.msg_id);
    if (!msg_entry) {
        return buffer->len;
    }

    uint16_t payload_len = buffer->curr.payload_len;
    if (payload_len > msg_entry->max_msg_len) {
        payload_len = msg_entry->max_msg_len;
    }

    if (mavlink2) {
        trimmed_zeros = get_trimmed_zeros(msg_entry, buffer);
    } else {
        trimmed_zeros = 0;
    }

    /* Handle messages */
    switch (buffer->curr.msg_id) {
    case MAVLINK_MSG_ID_COMMAND_ACK: {
        mavlink_command_ack_t cmd;

        memcpy(&cmd, buffer->curr.payload, payload_len);
        if (trimmed_zeros) {
            memset(((uint8_t *)&cmd) + payload_len, 0, trimmed_zeros);
        }

        if (!_timeout.logging_start || cmd.command != MAV_CMD_LOGGING_START) {
            return buffer->len;
        }

        if (cmd.result == MAV_RESULT_ACCEPTED) {
            log_info("Logging request accepted by target device");
            _remove_logging_start_timeout();
            if (!_start_alive_timeout()) {
                log_warning("Could not start liveness timeout - mavlink router log won't be able "
                            "to detect if flight stack stopped");
            }
        } else {
            log_error("MAV_CMD_LOGGING_START result(%u) is different than accepted", cmd.result);
        }
        break;
    }
    case MAVLINK_MSG_ID_LOGGING_DATA_ACKED: {
        auto *ulog_data_acked = (mavlink_logging_data_acked_t *)buffer->curr.payload;
        mavlink_message_t msg;
        mavlink_logging_ack_t ack;

        ack.sequence = ulog_data_acked->sequence;
        ack.target_component = MAV_COMP_ID_ALL;
        ack.target_system = _target_system_id;
        mavlink_msg_logging_ack_encode(LOG_ENDPOINT_SYSTEM_ID, MAV_COMP_ID_ALL, &msg, &ack);
        _send_msg(&msg, _target_system_id);
        /* message will be handled by MAVLINK_MSG_ID_LOGGING_DATA case */

        if (trimmed_zeros) {
            mavlink_logging_data_t ulog_data;
            memcpy(&ulog_data, buffer->curr.payload, payload_len);
            memset(((uint8_t *)&ulog_data) + payload_len, 0, trimmed_zeros);
            _logging_process(&ulog_data);
        } else {
            auto *ulog_data = (mavlink_logging_data_t *)buffer->curr.payload;
            _logging_process(ulog_data);
        }
        break;
    }
    case MAVLINK_MSG_ID_LOGGING_DATA: {
        if (trimmed_zeros) {
            mavlink_logging_data_t ulog_data;
            memcpy(&ulog_data, buffer->curr.payload, payload_len);
            memset(((uint8_t *)&ulog_data) + payload_len, 0, trimmed_zeros);
            _logging_data_process(&ulog_data);
        } else {
            auto *ulog_data = (mavlink_logging_data_t *)buffer->curr.payload;
            _logging_data_process(ulog_data);
        }
        break;
    }
    }

    _stat.write.total++;
    _stat.write.bytes += buffer->len;

    return buffer->len;
}

/*
 * Return true if the message with seq should be handled.
 */
bool ULog::_logging_seq(uint16_t seq, bool *drop, uint16_t *expected_seq)
{
    if (*expected_seq == seq) {
        (*expected_seq)++;
        *drop = false;
        return true;
    }

    if (seq > *expected_seq) {
        const uint16_t diff = seq - *expected_seq;
        if (diff > (UINT16_MAX / 2)) {
            /* _expected_seq wrapped and a re-transmission of a non-wrapped message happened */
            return false;
        }
    } else {
        const uint16_t diff = *expected_seq - seq;
        if (diff < (UINT16_MAX / 2)) {
            /* re-transmission */
            return false;
        }
    }

    *drop = true;
    *expected_seq = seq + 1;
    return true;
}

void ULog::_logging_process(mavlink_logging_data_t *msg)
{
    /* Waiting for ULog header? */
    if (_waiting_header) {
        const uint8_t magic[] = ULOG_MAGIC;

        if (msg->length < ULOG_HEADER_SIZE) {
            /* This should never happen */
            log_error("ULog header is not complete, restarting ULog...");
            _force_stop = true;
            stopping();
            start();
            return;
        }

        if (memcmp(magic, msg->data, sizeof(magic))) {
            log_error("Invalid ULog Magic number, restarting ULog...");
            _force_stop = true;
            stopping();
            start();
            return;
        }

        _buffer_partial_len = ULOG_HEADER_SIZE;
        memcpy(_buffer_partial, msg->data, ULOG_HEADER_SIZE);

        memmove(msg->data, &msg->data[ULOG_HEADER_SIZE], msg->length);
        msg->length -= ULOG_HEADER_SIZE;
        _waiting_header = false;
    }

    bool drops = false;

    if (!_logging_seq(msg->sequence, &drops, &_expected_seq)) {
        return;
    }

    if (drops) {
        _logging_flush();

        _buffer_len = 0;
        _buffer_index = 0;
        _waiting_first_msg_offset = true;
    }

    /*
     * Do not cause a buffer overflow, it should only happens if a ULog message
     * don't fit in _msg_buffer
     */
    if ((_buffer_len + msg->length) > BUFFER_LEN) {
        log_warning("Header Buffer full, dropping everything on buffer");

        _buffer_len = 0;
        _waiting_first_msg_offset = true;
    }

    /*
     * ULog message fits on _buffer but it need move all valid data to
     * the being of buffer.
     */
    if ((_buffer_index + _buffer_len + msg->length) > BUFFER_LEN) {
        memmove(_buffer, &_buffer[_buffer_index], _buffer_len);
        _buffer_index = 0;
    }

    uint8_t begin = 0;

    if (_waiting_first_msg_offset) {
        if (msg->first_message_offset == NO_FIRST_MSG_OFFSET) {
            /* no useful information in this message */
            return;
        }

        _waiting_first_msg_offset = false;
        begin = msg->first_message_offset;
    }

    if (!msg->length) {
        return;
    }

    msg->length = msg->length - begin;
    memcpy(&_buffer[_buffer_index + _buffer_len], &msg->data[begin], msg->length);
    _buffer_len += msg->length;
    _logging_flush();
}

void ULog::_logging_data_process(mavlink_logging_data_t *msg)
{
    bool drops = false;

    if (!_logging_seq(msg->sequence, &drops, &_expected_data_seq)) {
        return;
    }

    if (drops) {
        _logging_flush_data();

        _data_buffer_len = 0;
        _data_buffer_index = 0;
        _data_waiting_first_msg_offset = true;
    }

    /*
     * Do not cause a buffer overflow, it should only happens if a ULog message
     * don't fit in _msg_buffer
     */
    if ((_data_buffer_len + msg->length) > BUFFER_LEN) {
        log_warning("Data buffer full, dropping everything on buffer");

        _data_buffer_len = 0;
        _data_waiting_first_msg_offset = true;
    }

    /*
     * ULog message fits on _buffer but it need move all valid data to
     * the being of buffer.
     */
    if ((_data_buffer_index + _data_buffer_len + msg->length) > BUFFER_LEN) {
        memmove(_data_buffer, &_data_buffer[_data_buffer_index], _data_buffer_len);
        _data_buffer_index = 0;
    }

    uint8_t begin = 0;

    if (_data_waiting_first_msg_offset) {
        if (msg->first_message_offset == NO_FIRST_MSG_OFFSET) {
            /* no useful information in this message */
            return;
        }

        _data_waiting_first_msg_offset = false;
        begin = msg->first_message_offset;
    }

    if (!msg->length) {
        return;
    }

    msg->length = msg->length - begin;
    memcpy(&_data_buffer[_data_buffer_index + _data_buffer_len], &msg->data[begin], msg->length);
    _data_buffer_len += msg->length;
    _logging_flush_data();
}

bool ULog::_logging_flush_data()
{
    while (_data_buffer_partial_len) {
        const ssize_t r = write(_datafile, _data_buffer_partial, _data_buffer_partial_len);
        if (r == 0 || (r == -1 && errno == EAGAIN)) {
            return true;
        }
        if (r < 0) {
            log_error("Unable to write to ULog header file: (%m)");
            return false;
        }

        _data_buffer_partial_len -= r;
        memmove(_data_buffer_partial, &_data_buffer_partial[r], _data_buffer_partial_len);
    }

    while (_data_buffer_len >= sizeof(struct ulog_msg_header) && !_data_buffer_partial_len) {
        auto *header = (struct ulog_msg_header *)&_data_buffer[_data_buffer_index];
        const uint16_t full_msg_size = header->msg_size + sizeof(struct ulog_msg_header);

        if (full_msg_size > _data_buffer_len) {
            break;
        }

        const ssize_t r = write(_datafile, header, full_msg_size);
        if (r == full_msg_size) {
            _data_buffer_len -= full_msg_size;
            _data_buffer_index += full_msg_size;
            continue;
        }
        if (r == 0 || (r == -1 && errno == EAGAIN)) {
            break;
        }
        if (r < 0) {
            log_error("Unable to write to ULog file: (%m)");
            return false;
        }

        /* Handle partial write */
        _data_buffer_partial_len = full_msg_size - r;

        if (_data_buffer_partial_len > sizeof(_data_buffer_partial)) {
            _data_buffer_partial_len = 0;
            log_error("Partial buffer is not big enough to store the "
                      "ULog entry(type=%c len=%u), ULog file is now corrupt.",
                      header->msg_type,
                      full_msg_size);
            break;
        }

        memcpy(_data_buffer_partial,
               &_data_buffer[_data_buffer_index + r],
               _data_buffer_partial_len);

        _data_buffer_len -= full_msg_size;
        _data_buffer_index += full_msg_size;
        break;
    }

    return true;
}

bool ULog::_logging_flush()
{
    while (_buffer_partial_len) {
        const ssize_t r = write(_file, _buffer_partial, _buffer_partial_len);
        if (r == 0 || (r == -1 && errno == EAGAIN)) {
            return true;
        }
        if (r < 0) {
            log_error("Unable to write to ULog file: (%m)");
            return false;
        }

        _buffer_partial_len -= r;
        memmove(_buffer_partial, &_buffer_partial[r], _buffer_partial_len);
    }

    while (_buffer_len >= sizeof(struct ulog_msg_header) && !_buffer_partial_len) {
        auto *header = (struct ulog_msg_header *)&_buffer[_buffer_index];
        const uint16_t full_msg_size = header->msg_size + sizeof(struct ulog_msg_header);

        if (full_msg_size > _buffer_len) {
            break;
        }

        const ssize_t r = write(_file, header, full_msg_size);
        if (r == full_msg_size) {
            _buffer_len -= full_msg_size;
            _buffer_index += full_msg_size;
            continue;
        }
        if (r == 0 || (r == -1 && errno == EAGAIN)) {
            break;
        }
        if (r < 0) {
            log_error("Unable to write to ULog file: (%m)");
            return false;
        }

        /* Handle partial write */
        _buffer_partial_len = full_msg_size - r;

        if (_buffer_partial_len > sizeof(_buffer_partial)) {
            _buffer_partial_len = 0;
            log_error("Partial buffer is not big enough to store the "
                      "ULog entry(type=%c len=%u), ULog file is now corrupt.",
                      header->msg_type,
                      full_msg_size);
            break;
        }

        memcpy(_buffer_partial, &_buffer[_buffer_index + r], _buffer_partial_len);

        _buffer_len -= full_msg_size;
        _buffer_index += full_msg_size;
        break;
    }

    return true;
}
