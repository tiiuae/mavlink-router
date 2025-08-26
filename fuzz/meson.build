# For an AFL++ fuzzing build
# meson setup builddir --native-file afl.ini -Dfuzzing=true
# For a libfuzzer fuzzing build
# meson setup builddir --native-file libfuzzer.ini -Dfuzzing=true
# Finally, call ninja -C builddir 

src_common = include_directories('../src/common')
mavlink_extra =  [
    include_directories('../modules/mavlink_c_library_v2'),
    include_directories('../modules/mavlink_c_library_v2/minimal')
]


mavlink_parse_char_harness = executable(
    'mavlink_parse_char_harness',
    'mavlink_parse_char_harness.cc',
    include_directories: [src_inc, mavlink_inc, mavlink_extra],
    dependencies: [
        dep_math,
        dep_rt,
        dep_thread
    ],
    cpp_args: fuzzer_flags,
    link_args: fuzzer_link_flags,
    install: false
)



mavlink_conf_parser_harness = executable(
    'mavlink_conf_parser_harness',
    'mavlink_conf_parser_harness.cc',
    [
        '../src/common/conf_file.cpp',
        '../src/common/util.cpp',
        '../src/common/log.cpp',
    ],
    include_directories: [src_inc, mavlink_inc, mavlink_extra, src_common],
    dependencies: [
        dep_math,
        dep_rt,
        dep_thread
    ],
    cpp_args: fuzzer_flags,
    link_args: fuzzer_link_flags,
    install: false
)



ulog_harness = executable(
    'ulog_harness',
    [
        'ulog_harness.cc',
        '../src/endpoint.cpp',
        '../src/logendpoint.cpp',
        '../src/ulog.cpp',
        '../src/pollable.cpp',
        '../src/dedup.cpp',
        '../src/autolog.cpp',
        '../src/binlog.cpp',
        '../src/timeout.cpp',
        '../src/mainloop.cpp',
    ],
    include_directories: [src_inc, mavlink_inc, mavlink_extra],
    link_with: libcommon_private,
    dependencies: [
        dep_math,
        dep_rt,
        dep_thread
    ],
    cpp_args: fuzzer_flags,
    link_args: fuzzer_link_flags,
    install: false
)


alog_harness = executable(
    'alog_harness',
    [
        'alog_harness.cc',
        '../src/endpoint.cpp',
        '../src/logendpoint.cpp',
        '../src/ulog.cpp',
        '../src/pollable.cpp',
        '../src/dedup.cpp',
        '../src/autolog.cpp',
        '../src/binlog.cpp',
        '../src/timeout.cpp',
        '../src/mainloop.cpp',
    ],
    include_directories: [src_inc, mavlink_inc, mavlink_extra],
    link_with: libcommon_private,
    dependencies: [
        dep_math,
        dep_rt,
        dep_thread
    ],
    cpp_args: fuzzer_flags,
    link_args: fuzzer_link_flags,
    install: false
)

blog_harness = executable(
    'blog_harness',
    [
        'binlog_harness.cc',
        '../src/endpoint.cpp',
        '../src/logendpoint.cpp',
        '../src/ulog.cpp',
        '../src/pollable.cpp',
        '../src/dedup.cpp',
        '../src/autolog.cpp',
        '../src/binlog.cpp',
        '../src/timeout.cpp',
        '../src/mainloop.cpp',
    ],
    include_directories: [src_inc, mavlink_inc, mavlink_extra],
    link_with: libcommon_private,
    dependencies: [
        dep_math,
        dep_rt,
        dep_thread
    ],
    cpp_args: fuzzer_flags,
    link_args: fuzzer_link_flags,
    install: false
)

