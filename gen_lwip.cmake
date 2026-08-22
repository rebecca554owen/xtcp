file(GLOB_RECURSE LWIP_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/third_party/lwip/my/*.c
    ${CMAKE_CURRENT_LIST_DIR}/third_party/lwip/core/*.c
    ${CMAKE_CURRENT_LIST_DIR}/third_party/lwip/api/*.c
)
foreach(S IN LISTS LWIP_SOURCES)
    get_filename_component(REL S NAME_WE)
    string(REPLACE /third_party/ / ABS S)
    file(RELATIVE_PATH R "${CMAKE_CURRENT_LIST_DIR}" "${S}")
    string(REPLACE "/ "/" R R)
    list(APPEND OUT "third_party/lwip/${R}")
endforeach()
string(JOIN "
        " OUT STR)
file(WRITE "${CMAKE_CURRENT_LIST_DIR}/cmake/lwip_sources.cmake" "set(LWIP_SOURCES
        ${STR}
)")