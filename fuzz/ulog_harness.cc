#include "logendpoint.h"
#include "mainloop.h"
#include "ulog.h"

#include <cstdint>
#include <cstdio>
#include <fuzzer/FuzzedDataProvider.h>
#include <iomanip>
#include <iostream>

void vis_buf(buffer *buf)
{
    printf("Dump of buffer struct:\n");
    printf("  Data: ");
    for (uint i = 0; i < buf->len; i++) {
        printf("%02x ", buf->data[i]);
    }
    printf("\n  Length: %d\n", buf->len);
    printf("  msg_id: %d\n", buf->curr.msg_id);
    printf("  target_sysid: %d\n", buf->curr.target_sysid);
    printf("  target_compid: %d\n", buf->curr.target_compid);
    printf("  src_sysid: %d\n", buf->curr.src_sysid);
    printf("  src_compid: %d\n", buf->curr.src_compid);
    printf("  curr.payload: ");
    for (uint i = 0; i < buf->curr.payload_len; i++) {
        printf("%02x ", buf->curr.payload[i]);
    }
    printf("\n  curr.payload_len: %d\n", buf->curr.payload_len);
}

void hexdump(const void *data, size_t size)
{
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex
                  << (int)((const unsigned char *)data)[i];
        if (((const unsigned char *)data)[i] >= ' ' && ((const unsigned char *)data)[i] <= '~') {
            ascii[i % 16] = ((const unsigned char *)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            std::cout << ' ';
            if ((i + 1) % 16 == 0) {
                std::cout << "|  " << ascii << std::endl;
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    std::cout << ' ';
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    std::cout << "   ";
                }
                std::cout << "|  " << ascii << std::endl;
            }
        }
    }
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    // We need this to avoid an assertion in the ULog::write_msg()
    Mainloop::init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{

    FuzzedDataProvider provider(data, size);

    LogOptions conf;
    conf.logs_dir = "/tmp/log_trash/";

    conf.log_mode
        = provider.PickValueInArray({LogMode::always, LogMode::while_armed, LogMode::disabled});
    conf.mavlink_dialect = provider.PickValueInArray({LogOptions::MavDialect::Auto,
                                                      LogOptions::MavDialect::Common,
                                                      LogOptions::MavDialect::Ardupilotmega});
    conf.min_free_space = provider.ConsumeIntegralInRange<unsigned long>(0, 1000000);
    conf.max_log_files = provider.ConsumeIntegralInRange<unsigned long>(1, 100);
    conf.fcu_id = provider.ConsumeIntegral<int>();

    ULog ulog{conf};

    while (provider.remaining_bytes() > 0) {
        size_t buffer_size = provider.ConsumeIntegral<size_t>();
        std::vector<uint8_t> buffer_data = provider.ConsumeBytes<uint8_t>(buffer_size);

        struct buffer buffer;
        buffer.data = buffer_data.data();
        buffer.len = buffer_data.size();

        buffer.curr.msg_id = provider.ConsumeIntegral<uint32_t>();
        buffer.curr.target_sysid = provider.ConsumeIntegral<int>();
        buffer.curr.target_compid = provider.ConsumeIntegral<int>();
        buffer.curr.src_sysid = provider.ConsumeIntegral<uint8_t>();
        buffer.curr.src_compid = provider.ConsumeIntegral<uint8_t>();

        if (provider.ConsumeBool()) {
            std::vector<uint8_t> cpl
                = provider.ConsumeBytes<uint8_t>(provider.ConsumeIntegral<uint64_t>());
            buffer.curr.payload = cpl.data();
            buffer.curr.payload_len = cpl.size();

        } else {
            buffer.curr.payload_len = provider.ConsumeIntegral<uint8_t>();

            std::vector<uint8_t> cpl = provider.ConsumeRemainingBytes<uint8_t>();
            buffer.curr.payload = cpl.data();
        }

        //vis_buf(&buffer);
        //std::this_thread::sleep_for(std::chrono::milliseconds(10));
        ulog.write_msg(&buffer);
        //std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    return 0;
}
