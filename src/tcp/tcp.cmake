# Add this OPTIONAL backend to a POSIX or ESP-IDF component target. All include
# paths are private: its namespaced lwIP must not replace platform lwIP headers.
function(tsc_add_tcp target)
    set(tcp_dir "${CMAKE_CURRENT_FUNCTION_LIST_DIR}")
    set(tcp_sources
        "${tcp_dir}/tcp.c"
        "${tcp_dir}/lwip/core/init.c"
        "${tcp_dir}/lwip/core/def.c"
        "${tcp_dir}/lwip/core/inet_chksum.c"
        "${tcp_dir}/lwip/core/ip.c"
        "${tcp_dir}/lwip/core/mem.c"
        "${tcp_dir}/lwip/core/memp.c"
        "${tcp_dir}/lwip/core/netif.c"
        "${tcp_dir}/lwip/core/pbuf.c"
        "${tcp_dir}/lwip/core/stats.c"
        "${tcp_dir}/lwip/core/tcp.c"
        "${tcp_dir}/lwip/core/tcp_in.c"
        "${tcp_dir}/lwip/core/tcp_out.c"
        "${tcp_dir}/lwip/core/ipv4/ip4.c"
        "${tcp_dir}/lwip/core/ipv4/ip4_addr.c")
    # Per-source include paths keep this private lwIP off native platform files.
    # Keeping the sources on the component also supports build frontends such as
    # PlatformIO, which otherwise omit nested CMake OBJECT library targets.
    target_sources(${target} PRIVATE ${tcp_sources})
    set_property(SOURCE ${tcp_sources} APPEND PROPERTY INCLUDE_DIRECTORIES
        "${tcp_dir}/port" "${tcp_dir}/lwip/include" "${tcp_dir}/../../include")
endfunction()
