cmake_minimum_required(VERSION 3.20)
project(ApfsAccessApfsRwEngine LANGUAGES C CXX)
include(CTest)

add_library(ApfsAccess.Utf8Proc STATIC
    ../../third_party/utf8proc/utf8proc.c
)

target_include_directories(ApfsAccess.Utf8Proc
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/utf8proc
)

target_compile_definitions(ApfsAccess.Utf8Proc PRIVATE UTF8PROC_EXPORTS)

add_library(ApfsAccess.ApfsRwEngine STATIC
    src/AppleCheckpointPublisher.cpp
    src/AppleSpacemanAllocator.cpp
    src/AppleTransactionCommit.cpp
    src/AppleVolumeTransaction.cpp
    src/ApfsContainerCatalog.cpp
    src/ApfsCompression.cpp
    src/ApfsExtendedRecordCodec.cpp
    src/ApfsFormat.cpp
    src/ApfsSharedSpace.cpp
    src/ApfsSnapshotStore.cpp
    src/ApfsNameCodec.cpp
    src/ApfsObjectMapStore.cpp
    src/ApfsSpacemanStore.cpp
    src/ApfsTransactionWriter.cpp
    src/ApfsVolumeTreeStore.cpp
    src/BtreeMutationCodec.cpp
    src/BlockDevice.cpp
    src/CheckpointDelta.cpp
    src/ContainerMountCoordinator.cpp
    src/ExtentAllocator.cpp
    src/MetadataStore.cpp
    src/MutationCompactor.cpp
    src/NativeApfsReader.cpp
    src/PayloadSpool.cpp
    src/TransactionManager.cpp
    src/WriteAheadLog.cpp
    src/WritePipeline.cpp
    ../../third_party/zlib/adler32.c
    ../../third_party/zlib/crc32.c
    ../../third_party/zlib/inflate.c
    ../../third_party/zlib/inffast.c
    ../../third_party/zlib/inftrees.c
    ../../third_party/zlib/zutil.c
    ../../third_party/lzfse/lzvn_decode_base.c
    ../../third_party/lzfse/apfsaccess_lzvn.c
    ../../third_party/lzfse/lzfse_decode_base.c
    ../../third_party/lzfse/lzfse_fse.c
    ../../third_party/lzfse/apfsaccess_lzfse.c
    ../../third_party/lzbitmap/apfsaccess_lzbitmap.c
)

target_include_directories(ApfsAccess.ApfsRwEngine
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/zlib
        ${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/lzfse
        ${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/lzbitmap
)

target_compile_features(ApfsAccess.ApfsRwEngine PUBLIC cxx_std_20)

target_compile_definitions(ApfsAccess.ApfsRwEngine PRIVATE UTF8PROC_EXPORTS Z_PREFIX)

if(WIN32)
    target_sources(ApfsAccess.ApfsRwEngine PRIVATE src/ApfsCrypto.cpp src/ApfsKeybag.cpp)
    target_link_libraries(ApfsAccess.ApfsRwEngine PRIVATE bcrypt)
endif()

target_link_libraries(ApfsAccess.ApfsRwEngine
    PRIVATE
        ApfsAccess.Utf8Proc
)

# Fixed repo-owned read-only APFS observer: emits C0a evidence records.
# Hashing adapter is platform-selected (CNG on Windows, portable elsewhere);
# the portable implementation is also unit-tested on every platform.
if(WIN32)
    set(APFSACCESS_OBSERVER_HASH_SRC tools/Sha256Win32.cpp)
else()
    set(APFSACCESS_OBSERVER_HASH_SRC tools/Sha256Portable.cpp)
endif()
add_executable(ApfsObserver
    tools/ApfsObserver.cpp
    ${APFSACCESS_OBSERVER_HASH_SRC}
)

target_link_libraries(ApfsObserver
    PRIVATE
        ApfsAccess.ApfsRwEngine
        $<$<PLATFORM_ID:Windows>:bcrypt>
)

target_compile_features(ApfsObserver PRIVATE cxx_std_20)

if(MSVC)
    target_compile_options(ApfsObserver PRIVATE /W4 /permissive-)
endif()

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
    if(WIN32)
        add_executable(ApfsAccess.ApfsRwEngine.CryptoFoundationTests
            tests/ApfsCryptoFoundationTests.cpp src/ApfsCrypto.cpp src/ApfsKeybag.cpp)
        target_compile_definitions(ApfsAccess.ApfsRwEngine.CryptoFoundationTests PRIVATE APFSACCESS_CRYPTO_TESTING)
        target_include_directories(ApfsAccess.ApfsRwEngine.CryptoFoundationTests PRIVATE tests)
        target_link_libraries(ApfsAccess.ApfsRwEngine.CryptoFoundationTests PRIVATE ApfsAccess.ApfsRwEngine bcrypt)
        target_compile_features(ApfsAccess.ApfsRwEngine.CryptoFoundationTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.CryptoFoundationTests PRIVATE /W4 /permissive-)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.CryptoFoundationTests COMMAND ApfsAccess.ApfsRwEngine.CryptoFoundationTests)
    endif()
    foreach(_snapshot_test ApfsSnapshotStoreTests SnapshotParserRedTests SnapshotProjectionTests SnapshotReadStoreTests)
        add_executable(ApfsAccess.ApfsRwEngine.${_snapshot_test} tests/${_snapshot_test}.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.${_snapshot_test} PRIVATE ApfsAccess.ApfsRwEngine)
        target_compile_features(ApfsAccess.ApfsRwEngine.${_snapshot_test} PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.${_snapshot_test} PRIVATE /W4 /permissive-)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.${_snapshot_test} COMMAND ApfsAccess.ApfsRwEngine.${_snapshot_test})
    endforeach()
    target_compile_definitions(ApfsAccess.ApfsRwEngine.SnapshotParserRedTests PRIVATE SNAPSHOT_STRICT_POLICY)
    foreach(_clone_test AppleCloneCowTests AppleCloneStoreTests AppleCloneWalTests NativeDurableCloneTests)
        add_executable(ApfsAccess.ApfsRwEngine.${_clone_test} tests/${_clone_test}.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.${_clone_test} PRIVATE ApfsAccess.ApfsRwEngine)
        target_compile_features(ApfsAccess.ApfsRwEngine.${_clone_test} PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.${_clone_test} PRIVATE /W4 /permissive-)
            set_property(TARGET ApfsAccess.ApfsRwEngine.${_clone_test} PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.${_clone_test} COMMAND ApfsAccess.ApfsRwEngine.${_clone_test})
    endforeach()
    target_sources(ApfsAccess.ApfsRwEngine.AppleCloneWalTests PRIVATE tools/Sha256Portable.cpp)
    add_executable(ApfsAccess.ApfsRwEngine.VolumeSpaceTests tests/ApfsVolumeSpaceTests.cpp)
    target_link_libraries(ApfsAccess.ApfsRwEngine.VolumeSpaceTests PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_features(ApfsAccess.ApfsRwEngine.VolumeSpaceTests PRIVATE cxx_std_20)
    add_test(NAME ApfsAccess.ApfsRwEngine.VolumeSpaceTests COMMAND ApfsAccess.ApfsRwEngine.VolumeSpaceTests)
    add_executable(ApfsAccess.ApfsRwEngine.AppleVolumeTransactionTests tests/AppleVolumeTransactionTests.cpp)
    target_link_libraries(ApfsAccess.ApfsRwEngine.AppleVolumeTransactionTests PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_features(ApfsAccess.ApfsRwEngine.AppleVolumeTransactionTests PRIVATE cxx_std_20)
    add_test(NAME ApfsAccess.ApfsRwEngine.AppleVolumeTransactionTests COMMAND ApfsAccess.ApfsRwEngine.AppleVolumeTransactionTests)
    add_executable(ApfsAccess.ApfsRwEngine.CompressionTests tests/ApfsCompressionTests.cpp)
    target_include_directories(ApfsAccess.ApfsRwEngine.CompressionTests PRIVATE
        ../../third_party/lzfse ../../third_party/lzbitmap)
    target_link_libraries(ApfsAccess.ApfsRwEngine.CompressionTests PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_features(ApfsAccess.ApfsRwEngine.CompressionTests PRIVATE cxx_std_20)
    add_test(NAME ApfsAccess.ApfsRwEngine.CompressionTests COMMAND ApfsAccess.ApfsRwEngine.CompressionTests)
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

    add_executable(ApfsAccess.ApfsRwEngine.CompatibilityTests
        tests/ApfsCompatibilityTests.cpp
        tools/Sha256Portable.cpp
    )
    add_executable(ApfsAccess.ApfsRwEngine.ContainerCoordinatorTests
        tests/ContainerMountCoordinatorTests.cpp
        tools/Sha256Portable.cpp
    )
    add_executable(ApfsAccess.ApfsRwEngine.AppleTransactionWriterTests
        tests/ApfsTransactionWriterTests.cpp
    )
    add_executable(ApfsAccess.ApfsRwEngine.AppleSpacemanAllocatorTests
        tests/AppleSpacemanAllocatorTests.cpp
    )
    add_executable(ApfsAccess.ApfsRwEngine.AppleCheckpointPublisherTests
        tests/AppleCheckpointPublisherTests.cpp
    )
    add_executable(ApfsAccess.ApfsRwEngine.NameCodecTests
        tests/ApfsNameCodecTests.cpp
    )
    add_executable(ApfsAccess.ApfsRwEngine.ExtendedRecordCodecTests
        tests/ApfsExtendedRecordCodecTests.cpp
    )

    target_link_libraries(ApfsAccess.ApfsRwEngine.AppleTransactionWriterTests
        PRIVATE
            ApfsAccess.ApfsRwEngine
    )
    target_link_libraries(ApfsAccess.ApfsRwEngine.AppleSpacemanAllocatorTests
        PRIVATE
            ApfsAccess.ApfsRwEngine
    )
    target_link_libraries(ApfsAccess.ApfsRwEngine.AppleCheckpointPublisherTests
        PRIVATE
            ApfsAccess.ApfsRwEngine
    )
    target_link_libraries(ApfsAccess.ApfsRwEngine.NameCodecTests
        PRIVATE
            ApfsAccess.ApfsRwEngine
    )
    target_link_libraries(ApfsAccess.ApfsRwEngine.ExtendedRecordCodecTests
        PRIVATE
            ApfsAccess.ApfsRwEngine
    )

    target_link_libraries(ApfsAccess.ApfsRwEngine.ContainerCoordinatorTests
        PRIVATE
            ApfsAccess.ApfsRwEngine
    )

    target_link_libraries(ApfsAccess.ApfsRwEngine.CompatibilityTests
        PRIVATE
            ApfsAccess.ApfsRwEngine
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

    target_include_directories(ApfsAccess.ApfsRwEngine.CompatibilityTests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
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
    target_include_directories(ApfsAccess.ApfsRwEngine.ContainerCoordinatorTests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_include_directories(ApfsAccess.ApfsRwEngine.AppleTransactionWriterTests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_include_directories(ApfsAccess.ApfsRwEngine.AppleSpacemanAllocatorTests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )
    target_include_directories(ApfsAccess.ApfsRwEngine.AppleCheckpointPublisherTests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )
    target_include_directories(ApfsAccess.ApfsRwEngine.NameCodecTests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_include_directories(ApfsAccess.ApfsRwEngine.ExtendedRecordCodecTests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    target_compile_features(ApfsAccess.ApfsRwEngine.CompatibilityTests PRIVATE cxx_std_20)
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
    target_compile_features(ApfsAccess.ApfsRwEngine.ContainerCoordinatorTests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.AppleTransactionWriterTests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.AppleSpacemanAllocatorTests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.AppleCheckpointPublisherTests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.NameCodecTests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.ExtendedRecordCodecTests PRIVATE cxx_std_20)

    if(MSVC)
        target_compile_options(ApfsAccess.ApfsRwEngine.CompatibilityTests PRIVATE /W4 /permissive-)
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
        target_compile_options(ApfsAccess.ApfsRwEngine.ContainerCoordinatorTests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.AppleTransactionWriterTests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.AppleSpacemanAllocatorTests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.AppleCheckpointPublisherTests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.NameCodecTests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.ExtendedRecordCodecTests PRIVATE /W4 /permissive-)

        foreach(_apfsaccess_rw_test_target
            ApfsAccess.ApfsRwEngine.CompatibilityTests
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
            ApfsAccess.ApfsRwEngine.ContainerCoordinatorTests
            ApfsAccess.ApfsRwEngine.AppleTransactionWriterTests
            ApfsAccess.ApfsRwEngine.AppleSpacemanAllocatorTests
            ApfsAccess.ApfsRwEngine.AppleCheckpointPublisherTests
            ApfsAccess.ApfsRwEngine.NameCodecTests
            ApfsAccess.ApfsRwEngine.ExtendedRecordCodecTests
        )
            set_property(TARGET ${_apfsaccess_rw_test_target} PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
        endforeach()
    endif()

    add_test(
        NAME ApfsAccess.ApfsRwEngine.Compatibility
        COMMAND ApfsAccess.ApfsRwEngine.CompatibilityTests
    )
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
    add_test(
        NAME ApfsAccess.ApfsRwEngine.ContainerCoordinator
        COMMAND ApfsAccess.ApfsRwEngine.ContainerCoordinatorTests
    )
    add_test(
        NAME ApfsAccess.ApfsRwEngine.AppleTransactionWriter
        COMMAND ApfsAccess.ApfsRwEngine.AppleTransactionWriterTests
    )
    add_test(
        NAME ApfsAccess.ApfsRwEngine.AppleSpacemanAllocator
        COMMAND ApfsAccess.ApfsRwEngine.AppleSpacemanAllocatorTests
    )
    add_test(
        NAME ApfsAccess.ApfsRwEngine.AppleCheckpointPublisher
        COMMAND ApfsAccess.ApfsRwEngine.AppleCheckpointPublisherTests
    )
    add_test(
        NAME ApfsAccess.ApfsRwEngine.NameCodec
        COMMAND ApfsAccess.ApfsRwEngine.NameCodecTests
    )
    add_test(
        NAME ApfsAccess.ApfsRwEngine.ExtendedRecordCodec
        COMMAND ApfsAccess.ApfsRwEngine.ExtendedRecordCodecTests
    )
endif()
