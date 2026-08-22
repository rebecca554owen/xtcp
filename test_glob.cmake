file(GLOB_RECURSE LWIP_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/third_party/lwip/my/*.c
    ${CMAKE_CURRENT_LIST_DIR}/third_party/lwip/core/*.c
)
list(LENGTH LWIP_SOURCES N)
message(STATUS "count=${N}")
message(STATUS "first=${LWIP_SOURCES}")