#include <cstdint>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include <fuzzer/FuzzedDataProvider.h>

#include "mavlink.h"
#include "mavlink_msg_heartbeat.h"
#include "mavlink_types.h"
#include "protocol.h"

static void handle_new_message(const mavlink_message_t *msg)
{
    if (msg->msgid == MAVLINK_MSG_ID_HEARTBEAT) {
        mavlink_heartbeat_t heartbeat{};
        mavlink_msg_heartbeat_decode(msg, &heartbeat);
        //printf("HEARTBEAT:\n"
        //       "\tmavlink_version: %u\n"
        //       "\ttype: %u\n",
        //       heartbeat.mavlink_version,
        //       heartbeat.type);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 32) {
        return -1;
    }
    FuzzedDataProvider fdp(data, size);

    mavlink_message_t msg{};
    mavlink_status_t status{};

    uint8_t choice = fdp.ConsumeIntegral<uint8_t>();
    switch (fdp.ConsumeIntegralInRange(0, 4)) {
    case 0: {
        while (fdp.remaining_bytes() > 0) {
            char c = fdp.ConsumeIntegral<char>();
            mavlink_frame_char_buffer(&msg, &status, c, nullptr, nullptr);
        }
        break;
    }
    case 1: {
        for (size_t i = 0; i < fdp.remaining_bytes(); i++) {
            char c = fdp.ConsumeIntegral<char>();
            mavlink_parse_char(MAVLINK_COMM_0, c, &msg, &status);
        }
        break;
    }
    case 2: {
        uint8_t buf[MAVLINK_MAX_PACKET_LEN];
        if (fdp.remaining_bytes() >= MAVLINK_CORE_HEADER_LEN + 1) {
            fdp.ConsumeData(&msg.magic, sizeof(msg.magic));
            msg.len = fdp.ConsumeIntegral<uint8_t>();
            msg.incompat_flags = fdp.ConsumeIntegral<uint8_t>();
            msg.compat_flags = fdp.ConsumeIntegral<uint8_t>();
            msg.seq = fdp.ConsumeIntegral<uint8_t>();
            msg.sysid = fdp.ConsumeIntegral<uint8_t>();
            msg.compid = fdp.ConsumeIntegral<uint8_t>();
            msg.msgid = fdp.ConsumeIntegral<uint32_t>();
            fdp.ConsumeData((void *)_MAV_PAYLOAD(&msg), msg.len);
            mavlink_msg_to_send_buffer(buf, &msg);
        }
        break;
    }
    case 3: {
        mavlink_signing_t signing;
        mavlink_signing_streams_t signing_streams;
        memset(&signing, 0, sizeof(signing));
        memset(&signing_streams, 0, sizeof(signing_streams));
        signing.flags = MAVLINK_SIGNING_FLAG_SIGN_OUTGOING;
        if (fdp.remaining_bytes() >= sizeof(signing.secret_key)) {
            fdp.ConsumeData(&signing.secret_key, sizeof(signing.secret_key));
            uint8_t signature[MAVLINK_SIGNATURE_BLOCK_LEN];
            mavlink_sign_packet(&signing,
                                signature,
                                (const uint8_t *)&msg.magic,
                                MAVLINK_CORE_HEADER_LEN,
                                (const uint8_t *)_MAV_PAYLOAD(&msg),
                                msg.len,
                                msg.ck);
            mavlink_signature_check(&signing, &signing_streams, &msg);
        }
        break;
    }
    case 4: {
        for (size_t i = 0; i < fdp.remaining_bytes(); i++) {
            char c = fdp.ConsumeIntegral<char>();
            if (mavlink_parse_char(MAVLINK_COMM_0, c, &msg, &status)) {
                handle_new_message(&msg);
            }
        }
        break;
    }
    }

    return 0;
}
