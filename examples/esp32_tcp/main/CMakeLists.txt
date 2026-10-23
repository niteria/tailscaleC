get_filename_component(TSC_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
idf_component_register(SRCS "main.c" "${TSC_ROOT}/tests/test_tcp.c"
    INCLUDE_DIRS "." "${TSC_ROOT}/tests"
    REQUIRES tailscalec esp_netif esp_timer lwip)
set_source_files_properties("${TSC_ROOT}/tests/test_tcp.c" PROPERTIES
    COMPILE_DEFINITIONS "main=tsc_tcp_vectors_main")
