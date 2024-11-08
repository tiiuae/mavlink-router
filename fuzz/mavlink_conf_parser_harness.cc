#include "conf_file.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
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

    ComplexConfig()
        : str_option(nullptr)
        , bool_option(false)
        , int_option(0)
        , ul_option(0)
        , ull_option(0)
    {
        memset(str_buf, 0, sizeof(str_buf));
    }

    void cleanup()
    {
        if (str_option) {
            free(str_option);
            str_option = nullptr;
        }
        bool_option = false;
        int_option = 0;
        ul_option = 0;
        ull_option = 0;
        stdstr_option.clear();
        uint8vec_option.clear();
        uint32vec_option.clear();
        memset(str_buf, 0, sizeof(str_buf));
    }

    ~ComplexConfig() { cleanup(); }
};

// Global to prevent sanitizer false positives
static ComplexConfig config_data;

// Helper to create various test section contents
std::string generate_section_content(FuzzedDataProvider &fdp)
{
    std::string content;

    size_t num_options = fdp.ConsumeIntegralInRange<size_t>(1, 16);

    for (size_t i = 0; i < num_options; i++) {
        switch (fdp.ConsumeIntegralInRange<int>(0, 8)) {
        case 0:
            content += "str_option=" + fdp.ConsumeRandomLengthString(32) + "\n";
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
            content += "stdstr_option=" + fdp.ConsumeRandomLengthString(64) + "\n";
            break;
        case 6: {
            std::string vec;
            size_t count = fdp.ConsumeIntegralInRange<size_t>(1, 10);
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
            size_t count = fdp.ConsumeIntegralInRange<size_t>(1, 10);
            for (size_t j = 0; j < count; j++) {
                if (j > 0)
                    vec += ",";
                vec += std::to_string(fdp.ConsumeIntegral<uint32_t>());
            }
            content += "uint32vec_option=" + vec + "\n";
            break;
        }
        case 8:
            content += "str_buf=" + fdp.ConsumeRandomLengthString(256) + "\n";
            break;
        }
    }
    return content;
}

// Generate a complete config file with multiple sections
std::string generate_config_file(FuzzedDataProvider &fdp)
{
    std::string content;
    size_t num_sections = fdp.ConsumeIntegralInRange<size_t>(1, 5);

    for (size_t i = 0; i < num_sections; i++) {
        std::string section_name = "section_" + std::to_string(i);
        content += "[" + section_name + "]\n";
        content += generate_section_content(fdp);
        content += "\n";
    }

    // Add some malformed sections and edge cases
    if (fdp.ConsumeBool()) {
        content += "[incomplete_section\n";
    }
    if (fdp.ConsumeBool()) {
        content += "key_without_section=value\n";
    }
    if (fdp.ConsumeBool()) {
        content += "[section with spaces]\n";
    }
    if (fdp.ConsumeBool()) {
        content += "=empty_key\n";
    }

    return content;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 4) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    // Create unique filename for this fuzzing iteration
    std::string filename
        = "/tmp/fuzz_conf2_" + std::to_string(fdp.ConsumeIntegral<uint32_t>()) + ".txt";

    // Generate and write config file
    std::string fileContent = generate_config_file(fdp);
    FILE *f = fopen(filename.c_str(), "wb");
    if (!f) {
        return 0;
    }
    fwrite(fileContent.data(), 1, fileContent.size(), f);
    fclose(f);

    ConfFile conf;
    conf.parse(filename);

    // Define options table testing all parser types
    const ConfFile::OptionsTable options[]
        = {{"str_option",
            true,
            ConfFile::parse_str_dup,
            {offsetof(ComplexConfig, str_option), sizeof(char *)}},
           {"bool_option",
            false,
            ConfFile::parse_bool,
            {offsetof(ComplexConfig, bool_option), sizeof(bool)}},
           {"int_option",
            false,
            ConfFile::parse_i,
            {offsetof(ComplexConfig, int_option), sizeof(int)}},
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
            {offsetof(ComplexConfig, str_buf), sizeof(config_data.str_buf)}},
           {nullptr, false, nullptr, {0, 0}}};

    ConfFile::section_iter iter = {};
    while (conf.get_sections("*", &iter) == 0) {
        conf.extract_options(&iter, options, &config_data);
    }

    for (int i = 0; i < 5; i++) {
        std::string section = "section_" + std::to_string(i);
        conf.extract_options(section.c_str(), options, &config_data);
    }

    conf.release_all();
    remove(filename.c_str());

    return 0;
}
