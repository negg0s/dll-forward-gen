cmake_minimum_required(VERSION 3.20)
project(VERSION_proxy LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (MSVC)
    add_compile_options(/W4 /permissive-)
endif()

add_library(VERSION SHARED
    dllmain.cpp
)

set_target_properties(VERSION PROPERTIES
    OUTPUT_NAME "VERSION"
    PREFIX ""
    SUFFIX ".dll"
)

if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/exports.def")
    set_target_properties(VERSION PROPERTIES
        LINK_FLAGS "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/exports.def"
    )
endif()
