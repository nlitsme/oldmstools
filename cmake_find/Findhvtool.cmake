if (TARGET reglib)
    return()
endif()
find_path(HVTOOL_PATH NAMES registryutils/regfileparser.cpp PATHS symlinks/hvtool)
if(HVTOOL_PATH STREQUAL "HVTOOL_PATH-NOTFOUND")
    include(FetchContent)
    FetchContent_Populate(hvtool
        GIT_REPOSITORY https://github.com/nlitsme/hvtool.git)
    set(HVTOOL_PATH  ${hvtool_SOURCE_DIR})
else()
    set(hvtool_BINARY_DIR ${CMAKE_BINARY_DIR}/hvtool-build)
endif()

add_subdirectory(${HVTOOL_PATH} ${hvtool_BINARY_DIR})

