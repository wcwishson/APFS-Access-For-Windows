cmake_minimum_required(VERSION 3.20)
project(ApfsAccessApfsRwEngine LANGUAGES CXX)
include(CTest)

add_library(ApfsAccess.ApfsRwEngine STATIC
    src/ApfsObjectMapStore.cpp
    src/ApfsSpacemanStore.cpp
    src/ApfsVolumeTreeStore.cpp
    src/BtreeMutationCodec.cpp
    src/BlockDevice.cpp
    src/CheckpointDelta.cpp
    src/ExtentAllocator.cpp
    src/MetadataStore.cpp
    src/MutationCompactor.cpp
    src/NativeApfsReader.cpp
    src/PayloadSpool.cpp
    src/TransactionManager.cpp
    src/WriteAheadLog.cpp
    src/WritePipeline.cpp
)

target_include_directories(ApfsAccess.ApfsRwEngine
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(ApfsAccess.ApfsRwEngine PUBLIC cxx_std_20)

if(MSVC)
    target_compile_options(ApfsAccess.ApfsRwEngine PRIVATE
        /W4
        /permissive-
        $<$<CONFIG:Release>:/Oi>
        $<$<CONFIG:Release>:/Ot>
        $<$<CONFIG:Release>:/Gy>
        $<$<CONFIG:Release>:/Gw>
    )
    set_property(TARGET ApfsAccess.ApfsRwEngine PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
endif()

if(BUILD_TESTING)
    add_executable(ApfsAccess.ApfsRwEngine.Tests
        tests/MetadataStorePersistenceTests.cpp
    )
    add_executable(ApfsAccess.ApfsRwEngine.CanonicalStoreTests
        tests/CanonicalStoreTests.cpp
    )
    add_executable(ApfsAccess.ApfsRwEngine.ConformanceTests
        tests/MetadataStoreConformanceTests.cpp
    )
    add_executable(ApfsAccess.ApfsRwEngine.ConformanceFaultTests
        tests/MetadataStoreConformanceFaultTests.cpp
    )
    add_executable(ApfsAccess.ApfsRwEngine.FaultTests
        tests/MetadataStoreFaultInjectionTests.cpp
    )
    add_executable(ApfsAccess.ApfsRwEngine.TransactionTests
        tests/TransactionManagerTests.cpp
    )
    add_executable(ApfsAccess.ApfsRwEngine.PayloadSpoolTests
        tests/PayloadSpoolTests.cpp
    )
    add_executable(ApfsAccess.ApfsRwEngine.MutationCompactorTests
        tests/MutationCompactorTests.cpp
    )
    add_executable(ApfsAccess.ApfsRwEngine.ExtentAllocatorTests
        tests/ExtentAllocatorTests.cpp
    )
    add_executable(ApfsAccess.ApfsRwEngine.CheckpointDeltaTests
        tests/CheckpointDeltaTests.cpp
    )
    add_executable(ApfsAccess.ApfsRwEngine.WriteAheadLogTests
        tests/WriteAheadLogTests.cpp
    )
    add_executable(ApfsAccess.ApfsRwEngine.WritePipelineTests
        tests/WritePipelineTests.cpp
    )

    target_link_libraries(ApfsAccess.ApfsRwEngine.Tests
        PRIVATE
            ApfsAccess.ApfsRwEngine
    )
    target_link_libraries(ApfsAccess.ApfsRwEngine.CanonicalStoreTests
        PRIVATE
            ApfsAccess.ApfsRwEngine
    )
    target_link_libraries(ApfsAccess.ApfsRwEngine.ConformanceTests
        PRIVATE
            ApfsAccess.ApfsRwEngine
    )
    target_link_libraries(ApfsAccess.ApfsRwEngine.ConformanceFaultTests
        PRIVATE
            ApfsAccess.ApfsRwEngine
    )
    target_link_libraries(ApfsAccess.ApfsRwEngine.FaultTests
        PRIVATE
            ApfsAccess.ApfsRwEngine
    )
    target_link_libraries(ApfsAccess.ApfsRwEngine.TransactionTests
        PRIVATE
            ApfsAccess.ApfsRwEngine
    )
    target_link_libraries(ApfsAccess.ApfsRwEngine.PayloadSpoolTests
        PRIVATE
            ApfsAccess.ApfsRwEngine
    )
    target_link_libraries(ApfsAccess.ApfsRwEngine.MutationCompactorTests
        PRIVATE
            ApfsAccess.ApfsRwEngine
    )
    target_link_libraries(ApfsAccess.ApfsRwEngine.ExtentAllocatorTests
        PRIVATE
            ApfsAccess.ApfsRwEngine
    )
    target_link_libraries(ApfsAccess.ApfsRwEngine.CheckpointDeltaTests
        PRIVATE
            ApfsAccess.ApfsRwEngine
    )
    target_link_libraries(ApfsAccess.ApfsRwEngine.WriteAheadLogTests
        PRIVATE
            ApfsAccess.ApfsRwEngine
    )
    target_link_libraries(ApfsAccess.ApfsRwEngine.WritePipelineTests
        PRIVATE
            ApfsAccess.ApfsRwEngine
    )

    target_include_directories(ApfsAccess.ApfsRwEngine.Tests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_include_directories(ApfsAccess.ApfsRwEngine.CanonicalStoreTests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_include_directories(ApfsAccess.ApfsRwEngine.ConformanceTests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_include_directories(ApfsAccess.ApfsRwEngine.ConformanceFaultTests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_include_directories(ApfsAccess.ApfsRwEngine.FaultTests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_include_directories(ApfsAccess.ApfsRwEngine.TransactionTests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_include_directories(ApfsAccess.ApfsRwEngine.PayloadSpoolTests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_include_directories(ApfsAccess.ApfsRwEngine.MutationCompactorTests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_include_directories(ApfsAccess.ApfsRwEngine.ExtentAllocatorTests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_include_directories(ApfsAccess.ApfsRwEngine.CheckpointDeltaTests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_include_directories(ApfsAccess.ApfsRwEngine.WriteAheadLogTests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_include_directories(ApfsAccess.ApfsRwEngine.WritePipelineTests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    target_compile_features(ApfsAccess.ApfsRwEngine.Tests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.CanonicalStoreTests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.ConformanceTests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.ConformanceFaultTests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.FaultTests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.TransactionTests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.PayloadSpoolTests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.MutationCompactorTests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.ExtentAllocatorTests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.CheckpointDeltaTests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.WriteAheadLogTests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.WritePipelineTests PRIVATE cxx_std_20)

    if(MSVC)
        target_compile_options(ApfsAccess.ApfsRwEngine.Tests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.CanonicalStoreTests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.ConformanceTests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.ConformanceFaultTests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.FaultTests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.TransactionTests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.PayloadSpoolTests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.MutationCompactorTests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.ExtentAllocatorTests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.CheckpointDeltaTests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.WriteAheadLogTests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.WritePipelineTests PRIVATE /W4 /permissive-)

        foreach(_apfsaccess_rw_test_target
            ApfsAccess.ApfsRwEngine.Tests
            ApfsAccess.ApfsRwEngine.CanonicalStoreTests
            ApfsAccess.ApfsRwEngine.ConformanceTests
            ApfsAccess.ApfsRwEngine.ConformanceFaultTests
            ApfsAccess.ApfsRwEngine.FaultTests
            ApfsAccess.ApfsRwEngine.TransactionTests
            ApfsAccess.ApfsRwEngine.PayloadSpoolTests
            ApfsAccess.ApfsRwEngine.MutationCompactorTests
            ApfsAccess.ApfsRwEngine.ExtentAllocatorTests
            ApfsAccess.ApfsRwEngine.CheckpointDeltaTests
            ApfsAccess.ApfsRwEngine.WriteAheadLogTests
            ApfsAccess.ApfsRwEngine.WritePipelineTests
        )
            set_property(TARGET ${_apfsaccess_rw_test_target} PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
        endforeach()
    endif()

    add_test(
        NAME ApfsAccess.ApfsRwEngine.MetadataStorePersistence
        COMMAND ApfsAccess.ApfsRwEngine.Tests
    )
    add_test(
        NAME ApfsAccess.ApfsRwEngine.CanonicalStores
        COMMAND ApfsAccess.ApfsRwEngine.CanonicalStoreTests
    )
    add_test(
        NAME ApfsAccess.ApfsRwEngine.MetadataStoreConformance
        COMMAND ApfsAccess.ApfsRwEngine.ConformanceTests
    )
    add_test(
        NAME ApfsAccess.ApfsRwEngine.MetadataStoreConformanceFaults
        COMMAND ApfsAccess.ApfsRwEngine.ConformanceFaultTests
    )
    add_test(
        NAME ApfsAccess.ApfsRwEngine.MetadataStoreFaultInjection
        COMMAND ApfsAccess.ApfsRwEngine.FaultTests
    )
    add_test(
        NAME ApfsAccess.ApfsRwEngine.TransactionLifecycle
        COMMAND ApfsAccess.ApfsRwEngine.TransactionTests
    )
    add_test(
        NAME ApfsAccess.ApfsRwEngine.PayloadSpool
        COMMAND ApfsAccess.ApfsRwEngine.PayloadSpoolTests
    )
    add_test(
        NAME ApfsAccess.ApfsRwEngine.MutationCompactor
        COMMAND ApfsAccess.ApfsRwEngine.MutationCompactorTests
    )
    add_test(
        NAME ApfsAccess.ApfsRwEngine.ExtentAllocator
        COMMAND ApfsAccess.ApfsRwEngine.ExtentAllocatorTests
    )
    add_test(
        NAME ApfsAccess.ApfsRwEngine.CheckpointDelta
        COMMAND ApfsAccess.ApfsRwEngine.CheckpointDeltaTests
    )
    add_test(
        NAME ApfsAccess.ApfsRwEngine.WriteAheadLog
        COMMAND ApfsAccess.ApfsRwEngine.WriteAheadLogTests
    )
    add_test(
        NAME ApfsAccess.ApfsRwEngine.WritePipeline
        COMMAND ApfsAccess.ApfsRwEngine.WritePipelineTests
    )
endif()
