get_filename_component(TSC_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
idf_component_register(SRCS "main.c" "${TSC_ROOT}/tests/test_crypto.c"
    INCLUDE_DIRS "." "${TSC_ROOT}/tests"
    REQUIRES tailscalec bootloader_support esp_timer)
set_source_files_properties("${TSC_ROOT}/tests/test_crypto.c" PROPERTIES
    COMPILE_DEFINITIONS "main=tsc_crypto_vectors_main")
