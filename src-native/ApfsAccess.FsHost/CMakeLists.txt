cmake_minimum_required(VERSION 3.20)
project(ApfsAccessFsHost LANGUAGES CXX)
include(CTest)

if(WIN32 AND BUILD_TESTING)
    add_executable(ApfsAccess.FsHost.StandardShareModesTests tests/NativeStandardShareModesTests.cpp)
    target_include_directories(ApfsAccess.FsHost.StandardShareModesTests PRIVATE src)
    target_compile_features(ApfsAccess.FsHost.StandardShareModesTests PRIVATE cxx_std_20)
    target_compile_definitions(ApfsAccess.FsHost.StandardShareModesTests PRIVATE NOMINMAX)
    if(MSVC)
        target_compile_options(ApfsAccess.FsHost.StandardShareModesTests PRIVATE /W4 /WX /utf-8)
    endif()
    add_test(NAME ApfsAccess.FsHost.StandardShareModes
        COMMAND ApfsAccess.FsHost.StandardShareModesTests "${CMAKE_CURRENT_BINARY_DIR}/standard-native-share-ctest")
    set_tests_properties(ApfsAccess.FsHost.StandardShareModes PROPERTIES TIMEOUT 30 RUN_SERIAL TRUE)
    add_executable(ApfsAccess.FsHost.StandardLocksTests tests/NativeStandardLocksTests.cpp)
    target_include_directories(ApfsAccess.FsHost.StandardLocksTests PRIVATE src)
    target_compile_features(ApfsAccess.FsHost.StandardLocksTests PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(ApfsAccess.FsHost.StandardLocksTests PRIVATE /W4 /WX /utf-8)
    endif()
    add_test(NAME ApfsAccess.FsHost.StandardLocks
        COMMAND ApfsAccess.FsHost.StandardLocksTests "${CMAKE_CURRENT_BINARY_DIR}/standard-native-lock-ctest")
    set_tests_properties(ApfsAccess.FsHost.StandardLocks PROPERTIES TIMEOUT 30 RUN_SERIAL TRUE)
endif()

set(APFSACCESS_MSVC_PGO_MODE "" CACHE STRING "MSVC profile-guided optimization mode: empty, Instrument, or Optimize")
set_property(CACHE APFSACCESS_MSVC_PGO_MODE PROPERTY STRINGS "" "Instrument" "Optimize")
set(APFSACCESS_MSVC_PGO_PGD "" CACHE STRING "MSVC PGO database path")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(ApfsAccess.FsHost
    src/main.cpp
)
target_compile_features(ApfsAccess.FsHost PRIVATE cxx_std_20)

# Candidate only: parent must pass the consistent-source and mounted gates.
option(APFSACCESS_ENABLE_NATIVE_CLONE_CONTROL "Enable experimental private clone Control protocol" OFF)
option(APFSACCESS_ENABLE_STANDARD_HARDLINK "Enable hard links for admitted standard-share image owners" ON)
option(APFSACCESS_ENABLE_STANDARD_SPARSE "Enable sparse controls for admitted standard-share image owners" ON)
option(APFSACCESS_ENABLE_STANDARD_CLONE_RANGE "Enable range cloning for admitted standard-share image owners" ON)
target_compile_definitions(ApfsAccess.FsHost PRIVATE
    APFSACCESS_ENABLE_NATIVE_CLONE_CONTROL=$<BOOL:${APFSACCESS_ENABLE_NATIVE_CLONE_CONTROL}>
    APFSACCESS_ENABLE_STANDARD_HARDLINK=$<BOOL:${APFSACCESS_ENABLE_STANDARD_HARDLINK}>
    APFSACCESS_ENABLE_STANDARD_SPARSE=$<BOOL:${APFSACCESS_ENABLE_STANDARD_SPARSE}>
    APFSACCESS_ENABLE_STANDARD_CLONE_RANGE=$<BOOL:${APFSACCESS_ENABLE_STANDARD_CLONE_RANGE}>)
add_executable(ApfsAccess.CloneCopy tools/CloneCopy.cpp)
target_compile_features(ApfsAccess.CloneCopy PRIVATE cxx_std_20)
target_compile_definitions(ApfsAccess.CloneCopy PRIVATE UNICODE _UNICODE NOMINMAX)

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
option(APFSACCESS_BUILD_NATIVE_FILE_CONTROLS "Build private native file controls tool" OFF)
if(APFSACCESS_BUILD_NATIVE_FILE_CONTROLS)
    add_executable(ApfsAccess.NativeFileControls tools/NativeFileControls.cpp)
    target_compile_features(ApfsAccess.NativeFileControls PRIVATE cxx_std_20)
    target_compile_definitions(ApfsAccess.NativeFileControls PRIVATE UNICODE _UNICODE NOMINMAX)
    target_include_directories(ApfsAccess.NativeFileControls PRIVATE "${_rw_engine_dir}/include")
endif()
if(EXISTS "${_rw_engine_dir}/CMakeLists.txt")
    add_subdirectory("${_rw_engine_dir}" "${CMAKE_BINARY_DIR}/ApfsAccess.ApfsRwEngine")
    target_link_libraries(ApfsAccess.FsHost PRIVATE ApfsAccess.ApfsRwEngine ApfsAccess.EncryptedReadTransport)
    target_compile_definitions(ApfsAccess.FsHost PRIVATE APFSACCESS_HAS_RW_ENGINE=1)
endif()

option(APFSACCESS_BUILD_FSHOST_TESTS "Build FsHost semantic tests" ON)
if(APFSACCESS_BUILD_FSHOST_TESTS)
    if(TARGET ApfsAccess.ApfsRwEngine)
        add_executable(ApfsAccess.FsHost.ManifestStartupTerminalTests tests/ManifestStartupTerminalTests.cpp)
        target_compile_features(ApfsAccess.FsHost.ManifestStartupTerminalTests PRIVATE cxx_std_20)
        target_compile_definitions(ApfsAccess.FsHost.ManifestStartupTerminalTests PRIVATE UNICODE _UNICODE NOMINMAX)
        target_include_directories(ApfsAccess.FsHost.ManifestStartupTerminalTests PRIVATE "${_rw_engine_dir}/include")
        target_link_libraries(ApfsAccess.FsHost.ManifestStartupTerminalTests PRIVATE ApfsAccess.ApfsRwEngine)
        add_test(NAME ApfsAccess.FsHost.ManifestStartupTerminalTests COMMAND ${CMAKE_COMMAND}
            "-DTEST_EXE=$<TARGET_FILE:ApfsAccess.FsHost.ManifestStartupTerminalTests>"
            "-DEVIDENCE_ROOT=${CMAKE_CURRENT_BINARY_DIR}/manifest-startup-terminal-evidence"
            "-DTEST_ARGUMENTS=--all"
            -P "${_rw_engine_dir}/tests/RunFreshNativeFileTest.cmake")
    endif()
    add_executable(ApfsAccess.FsHost.SemanticsTests
        tests/FsHostSemanticsTests.cpp
    )

    target_compile_definitions(ApfsAccess.FsHost.SemanticsTests PRIVATE
        UNICODE
        _UNICODE
        NOMINMAX
        APFSACCESS_FSHOST_UNIT_TEST=1
        APFSACCESS_ENABLE_NATIVE_CLONE_CONTROL=1
    )
    target_include_directories(ApfsAccess.FsHost.SemanticsTests PRIVATE ${WINFSP_INCLUDE_DIR})
    # Shared synthetic fixture builder (test-only writer) from the engine tests.
    target_include_directories(ApfsAccess.FsHost.SemanticsTests PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/../ApfsAccess.ApfsRwEngine/tests")

    if(MSVC)
        target_compile_options(ApfsAccess.FsHost.SemanticsTests PRIVATE /W4 /permissive-)
        set_property(TARGET ApfsAccess.FsHost.SemanticsTests PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
    endif()

    if(TARGET ApfsAccess.ApfsRwEngine)
        target_link_libraries(ApfsAccess.FsHost.SemanticsTests PRIVATE ApfsAccess.ApfsRwEngine ApfsAccess.EncryptedReadTransport)
        target_compile_definitions(ApfsAccess.FsHost.SemanticsTests PRIVATE APFSACCESS_HAS_RW_ENGINE=1)
    endif()

    if(BUILD_TESTING)
        add_test(NAME ApfsAccess.FsHost.Semantics COMMAND ApfsAccess.FsHost.SemanticsTests)
        # The aggregate includes hundreds of callback and recovery scenarios.
        set_tests_properties(ApfsAccess.FsHost.Semantics PROPERTIES TIMEOUT 5400)
        add_test(NAME ApfsAccess.FsHost.Clone513 COMMAND ApfsAccess.FsHost.SemanticsTests native-clone-host-500)
    endif()
    add_executable(ApfsAccess.FsHost.SnapshotMountTests tests/SnapshotMountTests.cpp)
    if(TARGET ApfsAccess.ApfsRwEngine)
        add_executable(ApfsAccess.FsHost.LiveSnapshotControlTests tests/LiveSnapshotControlTests.cpp)
        target_compile_definitions(ApfsAccess.FsHost.LiveSnapshotControlTests PRIVATE
            UNICODE _UNICODE NOMINMAX APFSACCESS_HAS_RW_ENGINE=1 APFSACCESS_ENABLE_NATIVE_CLONE_CONTROL=1)
        target_include_directories(ApfsAccess.FsHost.LiveSnapshotControlTests PRIVATE
            ${WINFSP_INCLUDE_DIR} "${_rw_engine_dir}/tests")
        target_compile_features(ApfsAccess.FsHost.LiveSnapshotControlTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.FsHost.LiveSnapshotControlTests PRIVATE /utf-8 /bigobj)
        endif()
        target_link_libraries(ApfsAccess.FsHost.LiveSnapshotControlTests PRIVATE
            ApfsAccess.ApfsRwEngine ApfsAccess.EncryptedReadTransport)
        if(BUILD_TESTING)
            add_test(NAME ApfsAccess.FsHost.LiveSnapshotControl COMMAND ${CMAKE_COMMAND}
                "-DTEST_EXE=$<TARGET_FILE:ApfsAccess.FsHost.LiveSnapshotControlTests>"
                "-DEVIDENCE_ROOT=${CMAKE_CURRENT_BINARY_DIR}/live-snapshot-evidence"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/RunFreshHostFeatureTest.cmake")
            set_tests_properties(ApfsAccess.FsHost.LiveSnapshotControl PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
        endif()
        add_executable(ApfsAccess.FsHost.LiveVolumeVerificationTests tests/LiveVolumeVerificationTests.cpp)
        target_compile_definitions(ApfsAccess.FsHost.LiveVolumeVerificationTests PRIVATE
            UNICODE _UNICODE NOMINMAX APFSACCESS_HAS_RW_ENGINE=1 APFSACCESS_ENABLE_NATIVE_CLONE_CONTROL=1)
        target_include_directories(ApfsAccess.FsHost.LiveVolumeVerificationTests PRIVATE
            ${WINFSP_INCLUDE_DIR} "${_rw_engine_dir}/tests")
        target_compile_features(ApfsAccess.FsHost.LiveVolumeVerificationTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.FsHost.LiveVolumeVerificationTests PRIVATE /utf-8 /bigobj)
        endif()
        target_link_libraries(ApfsAccess.FsHost.LiveVolumeVerificationTests PRIVATE
            ApfsAccess.ApfsRwEngine ApfsAccess.EncryptedReadTransport)
        if(BUILD_TESTING)
            add_test(NAME ApfsAccess.FsHost.LiveVolumeVerification COMMAND ${CMAKE_COMMAND}
                "-DTEST_EXE=$<TARGET_FILE:ApfsAccess.FsHost.LiveVolumeVerificationTests>"
                "-DEVIDENCE_ROOT=${CMAKE_CURRENT_BINARY_DIR}/live-verification-evidence"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/RunFreshHostFeatureTest.cmake")
            set_tests_properties(ApfsAccess.FsHost.LiveVolumeVerification PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
        endif()
        add_executable(ApfsAccess.FsHost.BasicInfoNoopTests tests/BasicInfoNoopCleanupTests626.cpp)
        target_compile_definitions(ApfsAccess.FsHost.BasicInfoNoopTests PRIVATE
            UNICODE _UNICODE NOMINMAX APFSACCESS_HAS_RW_ENGINE=1 APFSACCESS_ENABLE_NATIVE_CLONE_CONTROL=1)
        target_include_directories(ApfsAccess.FsHost.BasicInfoNoopTests PRIVATE
            ${WINFSP_INCLUDE_DIR} "${_rw_engine_dir}/tests")
        target_compile_features(ApfsAccess.FsHost.BasicInfoNoopTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.FsHost.BasicInfoNoopTests PRIVATE /utf-8 /bigobj)
        endif()
        target_link_libraries(ApfsAccess.FsHost.BasicInfoNoopTests PRIVATE ApfsAccess.ApfsRwEngine ApfsAccess.EncryptedReadTransport)
        if(BUILD_TESTING)
            foreach(_basic_case noop change-only other-writer no-noop failed-noop other-handle
                    explicit-time same-time attributes write resize rename delete)
                add_test(NAME ApfsAccess.FsHost.BasicInfoNoop.${_basic_case}
                    COMMAND ApfsAccess.FsHost.BasicInfoNoopTests ${_basic_case})
            endforeach()
        endif()
        add_executable(ApfsAccess.FsHost.VolumeRenameTests tests/VolumeRenameHostTests.cpp)
        target_compile_definitions(ApfsAccess.FsHost.VolumeRenameTests PRIVATE
            UNICODE _UNICODE NOMINMAX APFSACCESS_HAS_RW_ENGINE=1 APFSACCESS_ENABLE_NATIVE_CLONE_CONTROL=1)
        target_include_directories(ApfsAccess.FsHost.VolumeRenameTests PRIVATE
            ${WINFSP_INCLUDE_DIR} "${_rw_engine_dir}/tests")
        target_compile_features(ApfsAccess.FsHost.VolumeRenameTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.FsHost.VolumeRenameTests PRIVATE /utf-8 /bigobj)
        endif()
        target_link_libraries(ApfsAccess.FsHost.VolumeRenameTests PRIVATE ApfsAccess.ApfsRwEngine ApfsAccess.EncryptedReadTransport)
        if(BUILD_TESTING)
            foreach(_rename_case success invalid acceptance-failure publication-failure
                    label-isolation refresh-isolation display-boundary shell-isolation shutdown container-status)
                add_test(NAME ApfsAccess.FsHost.VolumeRename.${_rename_case}
                    COMMAND ApfsAccess.FsHost.VolumeRenameTests ${_rename_case})
            endforeach()
        endif()
    endif()
    target_compile_definitions(ApfsAccess.FsHost.SnapshotMountTests PRIVATE
        UNICODE _UNICODE NOMINMAX APFSACCESS_HAS_RW_ENGINE=1)
    target_include_directories(ApfsAccess.FsHost.SnapshotMountTests PRIVATE
        ${WINFSP_INCLUDE_DIR} "${_rw_engine_dir}/tests")
    target_link_libraries(ApfsAccess.FsHost.SnapshotMountTests PRIVATE ApfsAccess.ApfsRwEngine ApfsAccess.EncryptedReadTransport)
    add_executable(ApfsAccess.FsHost.SingleVolumeCensusTests tests/SingleVolumeCensusTests.cpp)
    target_compile_definitions(ApfsAccess.FsHost.SingleVolumeCensusTests PRIVATE
        UNICODE _UNICODE NOMINMAX APFSACCESS_HAS_RW_ENGINE=1)
    target_include_directories(ApfsAccess.FsHost.SingleVolumeCensusTests PRIVATE
        ${WINFSP_INCLUDE_DIR} "${_rw_engine_dir}/tests")
    target_compile_features(ApfsAccess.FsHost.SingleVolumeCensusTests PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(ApfsAccess.FsHost.SingleVolumeCensusTests PRIVATE /utf-8 /bigobj)
    endif()
    target_link_libraries(ApfsAccess.FsHost.SingleVolumeCensusTests PRIVATE
        ApfsAccess.ApfsRwEngine ApfsAccess.EncryptedReadTransport)
    if(BUILD_TESTING)
        add_test(NAME ApfsAccess.FsHost.SingleVolumeCensus COMMAND ApfsAccess.FsHost.SingleVolumeCensusTests
            "${CMAKE_CURRENT_BINARY_DIR}/single-volume-census-evidence")
        set_tests_properties(ApfsAccess.FsHost.SingleVolumeCensus PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
    endif()
    add_executable(ApfsAccess.FsHost.FusionMountTests tests/FusionMountTests.cpp
        ${_rw_engine_dir}/src/ApfsFusionStore.cpp)
    target_compile_definitions(ApfsAccess.FsHost.FusionMountTests PRIVATE
        UNICODE _UNICODE NOMINMAX APFSACCESS_HAS_RW_ENGINE=1 APFS_FUSION_STORE_TESTING)
    target_include_directories(ApfsAccess.FsHost.FusionMountTests PRIVATE
        ${WINFSP_INCLUDE_DIR} "${_rw_engine_dir}/tests")
    target_compile_features(ApfsAccess.FsHost.FusionMountTests PRIVATE cxx_std_20)
    target_link_libraries(ApfsAccess.FsHost.FusionMountTests PRIVATE ApfsAccess.ApfsRwEngine ApfsAccess.EncryptedReadTransport)
    if(MSVC)
        target_compile_options(ApfsAccess.FsHost.FusionMountTests PRIVATE /utf-8 /bigobj)
    endif()
    set(APFSACCESS_FUSION_HOST_TEST_ROOT "" CACHE PATH "Private ordinary-file Fusion callback fixtures")
    if(BUILD_TESTING AND APFSACCESS_FUSION_HOST_TEST_ROOT)
        add_test(NAME ApfsAccess.FsHost.FusionSetup COMMAND ApfsAccess.FsHost.FusionMountTests --setup "${APFSACCESS_FUSION_HOST_TEST_ROOT}")
        set_tests_properties(ApfsAccess.FsHost.FusionSetup PROPERTIES FIXTURES_SETUP FusionHostImages RUN_SERIAL TRUE)
        add_test(NAME ApfsAccess.FsHost.FusionCallbacks COMMAND ApfsAccess.FsHost.FusionMountTests --callbacks "${APFSACCESS_FUSION_HOST_TEST_ROOT}")
        set_tests_properties(ApfsAccess.FsHost.FusionCallbacks PROPERTIES FIXTURES_REQUIRED FusionHostImages RUN_SERIAL TRUE TIMEOUT 600)
    endif()
    add_executable(ApfsAccess.FsHost.EncryptedMountTests tests/EncryptedMountTests.cpp
        ${_rw_engine_dir}/src/ApfsEncryptedReadSession.cpp
        ${_rw_engine_dir}/src/ApfsKeybagUnlock.cpp ${_rw_engine_dir}/src/ApfsCrypto.cpp)
    target_compile_definitions(ApfsAccess.FsHost.EncryptedMountTests PRIVATE
        UNICODE _UNICODE NOMINMAX APFSACCESS_HAS_RW_ENGINE=1 APFSACCESS_CRYPTO_TESTING)
    target_include_directories(ApfsAccess.FsHost.EncryptedMountTests PRIVATE
        ${WINFSP_INCLUDE_DIR} "${_rw_engine_dir}/tests")
    target_link_libraries(ApfsAccess.FsHost.EncryptedMountTests PRIVATE ApfsAccess.ApfsRwEngine ApfsAccess.EncryptedReadTransport)
    if(MSVC)
        target_compile_options(ApfsAccess.FsHost.EncryptedMountTests PRIVATE /utf-8 /bigobj)
    endif()
    if(BUILD_TESTING)
        add_test(NAME ApfsAccess.FsHost.EncryptedMount COMMAND ApfsAccess.FsHost.EncryptedMountTests)
        add_test(NAME ApfsAccess.FsHost.EncryptedBudgetRecovery COMMAND ApfsAccess.FsHost.EncryptedMountTests --review-budget)
        add_test(NAME ApfsAccess.FsHost.EncryptedCallbackBoundaries COMMAND ApfsAccess.FsHost.EncryptedMountTests --review-boundaries)
    endif()
    if(BUILD_TESTING)
        add_test(NAME ApfsAccess.FsHost.SnapshotMount COMMAND ApfsAccess.FsHost.SnapshotMountTests)
    endif()
endif()
