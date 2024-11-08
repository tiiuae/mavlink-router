#include "binlog.h"
#include "logendpoint.h"
#include "mainloop.h"

#include <fuzzer/FuzzedDataProvider.h>

void vis_buf(buffer *buf)
{
    printf("Dump of buffer struct:\n");
    //printf("Data: ");
    //for (uint i = 0; i < buf->len; i++) {
    //    printf("%02x ", buf->data[i]);
    //}
    printf("\n Length: %d\n", buf->len);
    printf("  msg_id: %d\n", buf->curr.msg_id);
    printf("  target_sysid: %d\n", buf->curr.target_sysid);
    printf("  target_compid: %d\n", buf->curr.target_compid);
    printf("  src_sysid: %d\n", buf->curr.src_sysid);
    printf("  src_compid: %d\n", buf->curr.src_compid);
    //printf("  curr.payload: ");
    //for (uint i = 0; i < buf->curr.payload_len; i++) {
    //    printf("%02x ", buf->curr.payload[i]);
    //}
    printf("\n  curr.payload_len: %d\n", buf->curr.payload_len);
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    Mainloop::init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{

    FuzzedDataProvider provider(data, size);

    LogOptions conf;
    conf.logs_dir = "/tmp/log_trash/";

    BinLog blog{conf};
    //blog.start();

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

    // Call the write_msg function with the fuzzed buffer
    //vis_buf(&buffer);
    //std::this_thread::sleep_for(std::chrono::milliseconds(10));
    blog.write_msg(&buffer);
    //std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    //blog.stop();

    return 0;
}
