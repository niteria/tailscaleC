idf_component_register(SRCS "main.c" INCLUDE_DIRS "." "${CMAKE_BINARY_DIR}/private"
    REQUIRES tailscalec esp_netif esp_eth esp_event nvs_flash bootloader_support)
