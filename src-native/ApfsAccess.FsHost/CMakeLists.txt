cmake_minimum_required(VERSION 3.20)
project(ApfsAccessFsHost LANGUAGES CXX)
include(CTest)

set(APFSACCESS_MSVC_PGO_MODE "" CACHE STRING "MSVC profile-guided optimization mode: empty, Instrument, or Optimize")
set_property(CACHE APFSACCESS_MSVC_PGO_MODE PROPERTY STRINGS "" "Instrument" "Optimize")
set(APFSACCESS_MSVC_PGO_PGD "" CACHE STRING "MSVC PGO database path")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(ApfsAccess.FsHost
    src/main.cpp
)

target_compile_definitions(ApfsAccess.FsHost PRIVATE
    UNICODE
    _UNICODE
    NOMINMAX
)

if(MSVC)
    target_compile_options(ApfsAccess.FsHost PRIVATE
        /W4
        /permissive-
        $<$<CONFIG:Release>:/Oi>
        $<$<CONFIG:Release>:/Ot>
        $<$<CONFIG:Release>:/Gy>
        $<$<CONFIG:Release>:/Gw>
    )
    target_link_options(ApfsAccess.FsHost PRIVATE
        $<$<CONFIG:Release>:/OPT:REF>
        $<$<CONFIG:Release>:/OPT:ICF>
        $<$<CONFIG:Release>:/PDBALTPATH:%_PDB%>
    )
    set_property(TARGET ApfsAccess.FsHost PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
    if(CMAKE_BUILD_TYPE STREQUAL "Release" AND APFSACCESS_MSVC_PGO_MODE)
        if(APFSACCESS_MSVC_PGO_MODE STREQUAL "Instrument")
            target_link_options(ApfsAccess.FsHost PRIVATE /GENPROFILE)
        elseif(APFSACCESS_MSVC_PGO_MODE STREQUAL "Optimize")
            target_link_options(ApfsAccess.FsHost PRIVATE /USEPROFILE)
        else()
            message(FATAL_ERROR "Unsupported APFSACCESS_MSVC_PGO_MODE: ${APFSACCESS_MSVC_PGO_MODE}")
        endif()
        if(APFSACCESS_MSVC_PGO_PGD)
            target_link_options(ApfsAccess.FsHost PRIVATE "/PGD:${APFSACCESS_MSVC_PGO_PGD}")
        endif()
    endif()
endif()

# Prefer vendored WinFsp headers to avoid requiring a local SDK installation.
set(_winfsp_vendor_inc "${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/winfsp/include")
set(_winfsp_hints
    "${_winfsp_vendor_inc}"
    "$ENV{ProgramFiles}/WinFsp/inc"
    "$ENV{ProgramW6432}/WinFsp/inc"
    "C:/Program Files (x86)/WinFsp/inc"
)
find_path(WINFSP_INCLUDE_DIR winfsp/winfsp.h PATHS ${_winfsp_hints})
if(WINFSP_INCLUDE_DIR)
    target_compile_definitions(ApfsAccess.FsHost PRIVATE APFSACCESS_HAS_WINFSP=1)
    target_include_directories(ApfsAccess.FsHost PRIVATE ${WINFSP_INCLUDE_DIR})
else()
    message(FATAL_ERROR "winfsp/winfsp.h not found. Ensure third_party/winfsp/include is present.")
endif()

set(_rw_engine_dir "${CMAKE_CURRENT_SOURCE_DIR}/../ApfsAccess.ApfsRwEngine")
if(EXISTS "${_rw_engine_dir}/CMakeLists.txt")
    add_subdirectory("${_rw_engine_dir}" "${CMAKE_BINARY_DIR}/ApfsAccess.ApfsRwEngine")
    target_link_libraries(ApfsAccess.FsHost PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_definitions(ApfsAccess.FsHost PRIVATE APFSACCESS_HAS_RW_ENGINE=1)
endif()

option(APFSACCESS_BUILD_FSHOST_TESTS "Build FsHost semantic tests" ON)
if(APFSACCESS_BUILD_FSHOST_TESTS)
    add_executable(ApfsAccess.FsHost.SemanticsTests
        tests/FsHostSemanticsTests.cpp
    )

    target_compile_definitions(ApfsAccess.FsHost.SemanticsTests PRIVATE
        UNICODE
        _UNICODE
        NOMINMAX
        APFSACCESS_FSHOST_UNIT_TEST=1
    )
    target_include_directories(ApfsAccess.FsHost.SemanticsTests PRIVATE ${WINFSP_INCLUDE_DIR})

    if(MSVC)
        target_compile_options(ApfsAccess.FsHost.SemanticsTests PRIVATE /W4 /permissive-)
        set_property(TARGET ApfsAccess.FsHost.SemanticsTests PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
    endif()

    if(TARGET ApfsAccess.ApfsRwEngine)
        target_link_libraries(ApfsAccess.FsHost.SemanticsTests PRIVATE ApfsAccess.ApfsRwEngine)
        target_compile_definitions(ApfsAccess.FsHost.SemanticsTests PRIVATE APFSACCESS_HAS_RW_ENGINE=1)
    endif()

    if(BUILD_TESTING)
        add_test(NAME ApfsAccess.FsHost.Semantics COMMAND ApfsAccess.FsHost.SemanticsTests)
    endif()
endif()
