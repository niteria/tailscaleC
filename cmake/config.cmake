function(tsc_configure_target target)
    if(NOT DEFINED TSC_CONFIG_HEADER OR TSC_CONFIG_HEADER STREQUAL "")
        set(TSC_CONFIG_HEADER "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../config.h")
    endif()
    get_filename_component(header "${TSC_CONFIG_HEADER}" ABSOLUTE
        BASE_DIR "${CMAKE_SOURCE_DIR}")
    if(NOT EXISTS "${header}")
        message(FATAL_ERROR "Configuration header does not exist: ${header}")
    endif()
    # These limits affect public structs and private TCP pools. PlatformIO's
    # SCons scanner does not reliably follow '#include TSC_CONFIG_HEADER', so
    # include the contents in the public compile flags as well as CMake's
    # configure dependencies. Every consumer then rebuilds with the same ABI.
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${header}")
    file(SHA256 "${header}" config_digest)
    target_compile_definitions(${target} PUBLIC
        "$<BUILD_INTERFACE:TSC_CONFIG_HEADER=\"${header}\">"
        "$<BUILD_INTERFACE:TSC_CONFIG_DIGEST=\"${config_digest}\">"
        "$<INSTALL_INTERFACE:TSC_CONFIG_HEADER=\"tailscalec/build_config.h\">")
    set_property(TARGET ${target} PROPERTY TSC_CONFIG_HEADER "${header}")
    target_compile_features(${target} PUBLIC c_std_11)
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
endfunction()
