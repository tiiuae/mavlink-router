#include "autolog.h"
#include "logendpoint.h"
#include "mainloop.h"

#include <fuzzer/FuzzedDataProvider.h>

void vis_buf(buffer *buf)
{
    printf("Dump of buffer struct:\n");
    printf("Data: ");
    for (uint i = 0; i < buf->len; i++) {
        printf("%02x ", buf->data[i]);
    }
    printf("\n Length: %d\n", buf->len);
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

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    Mainloop::init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{

    // We'll use this to store our vectors to maintain their lifetime
    struct TestState {
        std::vector<uint8_t> buffer_data;
        std::vector<uint8_t> payload_data;
    } state;

    FuzzedDataProvider provider(data, size);

    LogOptions conf;
    conf.logs_dir = "/tmp/log_trash/";

    AutoLog alog{conf};

    size_t buffer_size = provider.ConsumeIntegral<size_t>();
    state.buffer_data = provider.ConsumeBytes<uint8_t>(buffer_size);

    struct buffer buffer;
    buffer.data = state.buffer_data.data();
    buffer.len = state.buffer_data.size();

    buffer.curr.msg_id = provider.ConsumeIntegral<uint32_t>();
    buffer.curr.target_sysid = provider.ConsumeIntegral<int>();
    buffer.curr.target_compid = provider.ConsumeIntegral<int>();
    buffer.curr.src_sysid = provider.ConsumeIntegral<uint8_t>();
    buffer.curr.src_compid = provider.ConsumeIntegral<uint8_t>();

    if (provider.ConsumeBool()) {
        uint64_t requested_size = provider.ConsumeIntegral<uint64_t>();
        state.payload_data = provider.ConsumeBytes<uint8_t>(requested_size);
        buffer.curr.payload = state.payload_data.data();
        buffer.curr.payload_len = state.payload_data.size();
    } else {
        size_t vec_sz = provider.remaining_bytes();
        state.payload_data = provider.ConsumeBytes<uint8_t>(vec_sz);
        buffer.curr.payload = state.payload_data.data();
        buffer.curr.payload_len = state.payload_data.size();
    }

    alog.write_msg(&buffer);
    return 0;
}
