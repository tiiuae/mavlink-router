#include "conf_file.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <string>
#include <vector>

struct ComplexConfig {
    char *str_option;
    bool bool_option;
    int int_option;
    unsigned long ul_option;
    unsigned long long ull_option;
    std::string stdstr_option;
    std::vector<uint8_t> uint8vec_option;
    std::vector<uint32_t> uint32vec_option;
    char str_buf[128];
};

class ConfigManager {
private:
    ComplexConfig config;
    std::string filename;

public:
    ConfigManager(const std::string &fname)
        : filename(fname)
    {
    }

    ~ConfigManager()
    {
        if (!filename.empty()) {
            remove(filename.c_str());
        }
    }

    ComplexConfig *get() { return &config; }
    const std::string &getFilename() const { return filename; }
};

class MemoryBuffer {
private:
    std::vector<uint8_t> buffer;

public:
    void write(const std::string &content) { buffer.assign(content.begin(), content.end()); }

    const uint8_t *data() const { return buffer.data(); }
    size_t size() const { return buffer.size(); }
};

static const ConfFile::OptionsTable OPTIONS_TABLE[]
    = {{"str_option",
        true,
        ConfFile::parse_str_dup,
        {offsetof(ComplexConfig, str_option), sizeof(char *)}},
       {"bool_option",
        false,
        ConfFile::parse_bool,
        {offsetof(ComplexConfig, bool_option), sizeof(bool)}},
       {"int_option", false, ConfFile::parse_i, {offsetof(ComplexConfig, int_option), sizeof(int)}},
       {"ul_option",
        false,
        ConfFile::parse_ul,
        {offsetof(ComplexConfig, ul_option), sizeof(unsigned long)}},
       {"ull_option",
        false,
        ConfFile::parse_ull,
        {offsetof(ComplexConfig, ull_option), sizeof(unsigned long long)}},
       {"stdstr_option",
        false,
        ConfFile::parse_stdstring,
        {offsetof(ComplexConfig, stdstr_option), sizeof(std::string)}},
       {"uint8vec_option",
        false,
        ConfFile::parse_uint8_vector,
        {offsetof(ComplexConfig, uint8vec_option), sizeof(std::vector<uint8_t>)}},
       {"uint32vec_option",
        false,
        ConfFile::parse_uint32_vector,
        {offsetof(ComplexConfig, uint32vec_option), sizeof(std::vector<uint32_t>)}},
       {"str_buf",
        false,
        ConfFile::parse_str_buf,
        {offsetof(ComplexConfig, str_buf), sizeof(ComplexConfig::str_buf)}},
       {nullptr, false, nullptr, {0, 0}}};

std::string generate_section_name(uint32_t index)
{
    return "section_" + std::to_string(index);
}

std::string generate_section_content(FuzzedDataProvider &fdp)
{
    static const size_t MAX_VECTOR_ELEMENTS = 128;

    std::string content;
    size_t num_options = fdp.ConsumeIntegralInRange<size_t>(1, 128);

    for (size_t i = 0; i < num_options; i++) {
        switch (fdp.ConsumeIntegralInRange<int>(0, 8)) {
        case 0:
            content += "str_option=" + fdp.ConsumeRandomLengthString() + "\n";
            break;
        case 1:
            content += "bool_option=" + std::to_string(fdp.ConsumeBool()) + "\n";
            break;
        case 2:
            content += "int_option=" + std::to_string(fdp.ConsumeIntegral<int>()) + "\n";
            break;
        case 3:
            content += "ul_option=" + std::to_string(fdp.ConsumeIntegral<unsigned long>()) + "\n";
            break;
        case 4:
            content
                += "ull_option=" + std::to_string(fdp.ConsumeIntegral<unsigned long long>()) + "\n";
            break;
        case 5:
            content += "stdstr_option=" + fdp.ConsumeRandomLengthString() + "\n";
            break;
        case 6: {
            std::string vec;
            size_t count = fdp.ConsumeIntegralInRange<size_t>(1, MAX_VECTOR_ELEMENTS);
            for (size_t j = 0; j < count; j++) {
                if (j > 0)
                    vec += ",";
                vec += std::to_string(fdp.ConsumeIntegral<uint8_t>());
            }
            content += "uint8vec_option=" + vec + "\n";
            break;
        }
        case 7: {
            std::string vec;
            size_t count = fdp.ConsumeIntegralInRange<size_t>(1, MAX_VECTOR_ELEMENTS);
            for (size_t j = 0; j < count; j++) {
                if (j > 0)
                    vec += ",";
                vec += std::to_string(fdp.ConsumeIntegral<uint32_t>());
            }
            content += "uint32vec_option=" + vec + "\n";
            break;
        }
        case 8:
            content += "str_buf=" + fdp.ConsumeRandomLengthString() + "\n";
            break;
        }
    }
    return content;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    //if (size < 8) {
    //    return -1;
    //}

    FuzzedDataProvider fdp(data, size);

    // Create unique filename using hash of input data
    uint32_t file_id = fdp.ConsumeIntegral<uint32_t>();
    std::string filename = "/dev/shm/fuzz_conf_" + std::to_string(file_id) + ".txt";

    ConfigManager config_mgr(filename);

    std::string content;
    size_t num_sections = fdp.ConsumeIntegralInRange<size_t>(1, 64);

    // Generate regular sections
    for (size_t i = 0; i < num_sections; i++) {
        content += "[" + fdp.ConsumeRandomLengthString() + "]\n";
        content += generate_section_content(fdp);
        content += "\n";
    }

    // Add edge cases with controlled probability
    if (fdp.ConsumeBool()) {
        content += "[incomplete_section\n";
    }
    if (fdp.ConsumeBool()) {
        content += "key_without_section=value\n";
    }
    if (fdp.ConsumeBool()) {
        content += "[section with spaces]\n";
    }

    FILE *f = fopen(filename.c_str(), "wb");
    if (!f)
        return 0;

    size_t written = fwrite(content.data(), 1, content.size(), f);
    fclose(f);

    if (written != content.size())
        return 0;

    // Parse and process config
    ConfFile conf;
    if (conf.parse(filename) != 0)
        return 0;

    // Process sections
    ConfFile::section_iter iter = {};
    while (conf.get_sections("*", &iter) == 0) {
        conf.extract_options(&iter, OPTIONS_TABLE, config_mgr.get());
    }

    // Process specific sections
    for (size_t i = 0; i < num_sections; i++) {
        std::string section = generate_section_name(i);
        conf.extract_options(section.c_str(), OPTIONS_TABLE, config_mgr.get());
    }

    conf.release_all();

    return 0;
}
