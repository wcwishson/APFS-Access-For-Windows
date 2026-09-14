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
    src/ApfsFusionStore.cpp
    src/ApfsFusionReadSession.cpp
    src/ApfsFusionSpaceman.cpp
    src/ApfsFusionWriteSession.cpp
    src/ApfsFusionCheckpointTarget.cpp
    src/ApfsFirmlinkRouter.cpp
    src/ApfsFormat.cpp
    src/ApfsSharedSpace.cpp
    src/ApfsSnapshotStore.cpp
    src/ApfsVerifier.cpp
    src/ApfsRepair.cpp
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
    src/VolumeMetadata.cpp
    src/SnapshotRuntime.cpp
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
    target_sources(ApfsAccess.ApfsRwEngine PRIVATE src/ApfsCrypto.cpp src/ApfsKeybag.cpp src/ApfsKeybagUnlock.cpp
        src/ApfsEncryptedReadSession.cpp src/ApfsEncryptedWriteTransform.cpp)
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
    add_executable(SnapshotImage tools/SnapshotImage.cpp)
    target_link_libraries(SnapshotImage PRIVATE ApfsAccess.ApfsRwEngine bcrypt user32)
    target_compile_features(SnapshotImage PRIVATE cxx_std_20)
    add_executable(VolumeRenameImage tools/VolumeRenameImage.cpp)
    target_link_libraries(VolumeRenameImage PRIVATE ApfsAccess.ApfsRwEngine bcrypt user32)
    target_compile_features(VolumeRenameImage PRIVATE cxx_std_20)
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
        foreach(snapshot_test SnapshotRuntimeTests SnapshotRuntimeWalTests SnapshotPublishReviewTests SnapshotRuntimeReviewTests SnapshotRepairIntegrationTests QuotaRepairSnapshotIntegrationTests SnapshotOwnerBridgeTests)
            add_executable(ApfsAccess.ApfsRwEngine.${snapshot_test} tests/${snapshot_test}.cpp)
            target_link_libraries(ApfsAccess.ApfsRwEngine.${snapshot_test} PRIVATE ApfsAccess.ApfsRwEngine bcrypt user32)
            target_compile_features(ApfsAccess.ApfsRwEngine.${snapshot_test} PRIVATE cxx_std_20)
            add_test(NAME ApfsAccess.ApfsRwEngine.${snapshot_test} COMMAND ApfsAccess.ApfsRwEngine.${snapshot_test})
        endforeach()
        set(APFSACCESS_SNAPSHOT_OWNER_BRIDGE_ROOT "" CACHE PATH "Private D: snapshot owner-bridge process evidence directory")
        if(APFSACCESS_SNAPSHOT_OWNER_BRIDGE_ROOT)
            find_package(Python3 REQUIRED COMPONENTS Interpreter)
            add_test(NAME ApfsAccess.ApfsRwEngine.SnapshotOwnerBridgeProcesses COMMAND ${Python3_EXECUTABLE} -B
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/SnapshotOwnerBridgeProcesses.py
                --root ${APFSACCESS_SNAPSHOT_OWNER_BRIDGE_ROOT}
                --tool $<TARGET_FILE:SnapshotImage>
                --fixture-builder $<TARGET_FILE:ApfsAccess.ApfsRwEngine.SnapshotOwnerBridgeTests>)
            set_tests_properties(ApfsAccess.ApfsRwEngine.SnapshotOwnerBridgeProcesses PROPERTIES TIMEOUT 600 RUN_SERIAL TRUE)
        endif()
    endif()
    if(WIN32)
        add_executable(ApfsAccess.ApfsRwEngine.ApfsRepairTests tests/ApfsRepairTests.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.ApfsRepairTests PRIVATE ApfsAccess.ApfsRwEngine bcrypt user32)
        target_compile_features(ApfsAccess.ApfsRwEngine.ApfsRepairTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.ApfsRepairTests PRIVATE /utf-8 /bigobj)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.ApfsRepair COMMAND ApfsAccess.ApfsRwEngine.ApfsRepairTests
            "${CMAKE_CURRENT_BINARY_DIR}/repair-evidence")
    endif()
    if(WIN32)
        add_executable(ApfsAccess.ApfsRwEngine.VolumeRenameTests tests/VolumeRenameTests.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.VolumeRenameTests PRIVATE ApfsAccess.ApfsRwEngine bcrypt user32)
        target_compile_features(ApfsAccess.ApfsRwEngine.VolumeRenameTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.VolumeRenameTests PRIVATE /utf-8 /bigobj)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.VolumeRename COMMAND ApfsAccess.ApfsRwEngine.VolumeRenameTests
            "${CMAKE_CURRENT_BINARY_DIR}/volume-rename-evidence")
    endif()
    if(WIN32)
        foreach(_fusion_test ApfsFusionStoreTests ApfsFusionCatalogTests FusionWriteSessionTests ApfsFusionSpacemanTests)
            add_executable(ApfsAccess.ApfsRwEngine.${_fusion_test}
                tests/${_fusion_test}.cpp src/ApfsFusionStore.cpp)
            target_compile_definitions(ApfsAccess.ApfsRwEngine.${_fusion_test} PRIVATE APFS_FUSION_STORE_TESTING)
            target_link_libraries(ApfsAccess.ApfsRwEngine.${_fusion_test} PRIVATE ApfsAccess.ApfsRwEngine)
            target_compile_features(ApfsAccess.ApfsRwEngine.${_fusion_test} PRIVATE cxx_std_20)
            add_test(NAME ApfsAccess.ApfsRwEngine.${_fusion_test} COMMAND ApfsAccess.ApfsRwEngine.${_fusion_test})
        endforeach()
    endif()
    add_executable(ApfsAccess.ApfsRwEngine.VerifierTests tests/ApfsVerifierTests.cpp)
    target_link_libraries(ApfsAccess.ApfsRwEngine.VerifierTests PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_features(ApfsAccess.ApfsRwEngine.VerifierTests PRIVATE cxx_std_20)
    add_test(NAME ApfsAccess.ApfsRwEngine.Verifier COMMAND ApfsAccess.ApfsRwEngine.VerifierTests)
    add_executable(ApfsAccess.ApfsRwEngine.VerifierCensusTests tests/ApfsVerifierCensusTests.cpp)
    target_link_libraries(ApfsAccess.ApfsRwEngine.VerifierCensusTests PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_features(ApfsAccess.ApfsRwEngine.VerifierCensusTests PRIVATE cxx_std_20)
    add_test(NAME ApfsAccess.ApfsRwEngine.VerifierCensus COMMAND ApfsAccess.ApfsRwEngine.VerifierCensusTests)
    add_executable(ApfsAccess.ApfsRwEngine.BtreeRoutingTests tests/BtreeRoutingTests.cpp)
    target_link_libraries(ApfsAccess.ApfsRwEngine.BtreeRoutingTests PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_features(ApfsAccess.ApfsRwEngine.BtreeRoutingTests PRIVATE cxx_std_20)
    add_test(NAME ApfsAccess.ApfsRwEngine.BtreeRouting COMMAND ApfsAccess.ApfsRwEngine.BtreeRoutingTests)
    if(WIN32)
        add_executable(ApfsAccess.ApfsRwEngine.VerifierObserverTests
            tests/ApfsVerifierObserverTests.cpp tools/Sha256Win32.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.VerifierObserverTests PRIVATE ApfsAccess.ApfsRwEngine bcrypt)
        target_compile_features(ApfsAccess.ApfsRwEngine.VerifierObserverTests PRIVATE cxx_std_20)
        add_test(NAME ApfsAccess.ApfsRwEngine.VerifierObserver COMMAND ApfsAccess.ApfsRwEngine.VerifierObserverTests
            "${CMAKE_CURRENT_BINARY_DIR}/verifier-lease.test-image")
        add_executable(ApfsAccess.ApfsRwEngine.VerifierWireTests
            tests/ApfsVerifierWireTests.cpp tools/Sha256Win32.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.VerifierWireTests PRIVATE ApfsAccess.ApfsRwEngine bcrypt)
        target_include_directories(ApfsAccess.ApfsRwEngine.VerifierWireTests PRIVATE tests)
        target_compile_features(ApfsAccess.ApfsRwEngine.VerifierWireTests PRIVATE cxx_std_20)
        add_test(NAME ApfsAccess.ApfsRwEngine.VerifierWire COMMAND ApfsAccess.ApfsRwEngine.VerifierWireTests
            "${CMAKE_CURRENT_BINARY_DIR}/verifier-wire-fixtures")
        set_tests_properties(ApfsAccess.ApfsRwEngine.VerifierWire PROPERTIES TIMEOUT 60)
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
        add_executable(ApfsAccess.ApfsRwEngine.KeybagUnlockTests
            tests/ApfsKeybagUnlockTests.cpp src/ApfsKeybagUnlock.cpp src/ApfsCrypto.cpp)
        target_compile_definitions(ApfsAccess.ApfsRwEngine.KeybagUnlockTests PRIVATE APFSACCESS_CRYPTO_TESTING)
        target_include_directories(ApfsAccess.ApfsRwEngine.KeybagUnlockTests PRIVATE tests)
        target_link_libraries(ApfsAccess.ApfsRwEngine.KeybagUnlockTests PRIVATE ApfsAccess.ApfsRwEngine bcrypt)
        target_compile_features(ApfsAccess.ApfsRwEngine.KeybagUnlockTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.KeybagUnlockTests PRIVATE /W4 /permissive-)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.KeybagUnlockTests COMMAND ApfsAccess.ApfsRwEngine.KeybagUnlockTests)
        add_executable(ApfsAccess.ApfsRwEngine.EncryptedReadSessionTests
            tests/ApfsEncryptedReadSessionTests.cpp src/ApfsEncryptedReadSession.cpp
            src/ApfsKeybagUnlock.cpp src/ApfsCrypto.cpp)
        target_compile_definitions(ApfsAccess.ApfsRwEngine.EncryptedReadSessionTests PRIVATE APFSACCESS_CRYPTO_TESTING)
        target_include_directories(ApfsAccess.ApfsRwEngine.EncryptedReadSessionTests PRIVATE tests)
        target_link_libraries(ApfsAccess.ApfsRwEngine.EncryptedReadSessionTests PRIVATE ApfsAccess.ApfsRwEngine bcrypt)
        target_compile_features(ApfsAccess.ApfsRwEngine.EncryptedReadSessionTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.EncryptedReadSessionTests PRIVATE /W4 /permissive-)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.EncryptedReadSessionTests COMMAND ApfsAccess.ApfsRwEngine.EncryptedReadSessionTests)
        add_executable(ApfsAccess.ApfsRwEngine.EncryptedWriteTransformTests
            tests/EncryptedWriteTransformTests.cpp src/ApfsEncryptedWriteTransform.cpp
            src/ApfsKeybagUnlock.cpp src/ApfsCrypto.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.EncryptedWriteTransformTests PRIVATE ApfsAccess.ApfsRwEngine bcrypt)
        target_compile_features(ApfsAccess.ApfsRwEngine.EncryptedWriteTransformTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.EncryptedWriteTransformTests PRIVATE /W4 /permissive-)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.EncryptedWriteTransformTests COMMAND ApfsAccess.ApfsRwEngine.EncryptedWriteTransformTests)
    endif()
    foreach(_snapshot_test ApfsSnapshotStoreTests SnapshotParserRedTests SnapshotProjectionTests SnapshotReadStoreTests SnapshotRetentionTests EncryptedWriteRefusalTests)
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
    add_executable(ApfsAccess.ApfsRwEngine.FirmlinkRouterTests tests/ApfsFirmlinkRouterTests.cpp)
    target_link_libraries(ApfsAccess.ApfsRwEngine.FirmlinkRouterTests PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_features(ApfsAccess.ApfsRwEngine.FirmlinkRouterTests PRIVATE cxx_std_20)
    add_test(NAME ApfsAccess.ApfsRwEngine.FirmlinkRouterTests COMMAND ApfsAccess.ApfsRwEngine.FirmlinkRouterTests)
    add_executable(ApfsAccess.ApfsRwEngine.FirmlinkMarkerTests tests/ApfsFirmlinkMarkerTests.cpp)
    target_link_libraries(ApfsAccess.ApfsRwEngine.FirmlinkMarkerTests PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_features(ApfsAccess.ApfsRwEngine.FirmlinkMarkerTests PRIVATE cxx_std_20)
    add_test(NAME ApfsAccess.ApfsRwEngine.FirmlinkMarkerTests COMMAND ApfsAccess.ApfsRwEngine.FirmlinkMarkerTests)
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

# Narrow clean-layout Fusion member-image reader using production file leases.
if(WIN32)
    add_executable(ApfsFusionReadTool tools/ApfsFusionReadTool.cpp)
    target_link_libraries(ApfsFusionReadTool PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_definitions(ApfsFusionReadTool PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    if(MSVC)
        target_compile_options(ApfsFusionReadTool PRIVATE /W4 /permissive-)
    endif()
    if(BUILD_TESTING)

        add_executable(FusionReadToolFixtures tests/FusionReadToolFixtures.cpp)
        target_link_libraries(FusionReadToolFixtures PRIVATE ApfsAccess.ApfsRwEngine)
        target_compile_definitions(FusionReadToolFixtures PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
        set(APFSACCESS_FUSION_READ_INTEGRATION_ROOT "" CACHE PATH "Private D: Fusion image test artifacts")
        if(APFSACCESS_FUSION_READ_INTEGRATION_ROOT)
            find_package(Python3 REQUIRED COMPONENTS Interpreter)
            add_test(NAME FusionReadToolIntegration COMMAND ${Python3_EXECUTABLE} -B
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/FusionReadToolIntegration.py
                --root ${APFSACCESS_FUSION_READ_INTEGRATION_ROOT}
                --tool $<TARGET_FILE:ApfsFusionReadTool>
                --fixture-builder $<TARGET_FILE:FusionReadToolFixtures>)
            set_tests_properties(FusionReadToolIntegration PROPERTIES TIMEOUT 120 RUN_SERIAL TRUE)
        endif()
    endif()
endif()

# Bounded offline RCT2 (APSB regular-file count) repair operation. Single
# invocation drives prepare/display/confirm/apply/verify in-process so the
# confirmation token never crosses argv, environment, logs, or evidence.
# Ordinary single-store images only; Fusion/encrypted/whole-volume shapes
# refuse before any mutation. No mount admission.
if(WIN32)
    add_executable(ApfsVolumeRepairTool tools/ApfsVolumeRepairTool.cpp)
    target_link_libraries(ApfsVolumeRepairTool PRIVATE ApfsAccess.ApfsRwEngine bcrypt)
    target_compile_definitions(ApfsVolumeRepairTool PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    target_include_directories(ApfsVolumeRepairTool PRIVATE tools)
    if(MSVC)
        target_compile_options(ApfsVolumeRepairTool PRIVATE /W4 /permissive-)
    endif()
    if(BUILD_TESTING)
        add_executable(ApfsVolumeRepairToolTests
            tests/ApfsVolumeRepairToolTests.cpp src/ApfsFusionStore.cpp)
        target_compile_definitions(ApfsVolumeRepairToolTests PRIVATE
            APFS_VOLUME_REPAIR_TOOL_TESTING APFS_FUSION_STORE_TESTING NOMINMAX WIN32_LEAN_AND_MEAN)
        target_include_directories(ApfsVolumeRepairToolTests PRIVATE tools)
        target_link_libraries(ApfsVolumeRepairToolTests PRIVATE ApfsAccess.ApfsRwEngine bcrypt)
        if(MSVC)
            target_compile_options(ApfsVolumeRepairToolTests PRIVATE /utf-8 /bigobj)
        endif()
        add_test(NAME ApfsVolumeRepairToolTests COMMAND ApfsVolumeRepairToolTests)
        set_tests_properties(ApfsVolumeRepairToolTests PROPERTIES TIMEOUT 600 RUN_SERIAL TRUE)
    endif()
endif()

# Private one-command encrypted image inspection/read precursor; no mount admission.
if(WIN32)
    add_library(ApfsAccess.EncryptedReadTransport STATIC tools/EncryptedReadTransport.cpp)
    target_include_directories(ApfsAccess.EncryptedReadTransport PUBLIC tools)
    target_link_libraries(ApfsAccess.EncryptedReadTransport PUBLIC ApfsAccess.ApfsRwEngine PRIVATE bcrypt advapi32)
    target_compile_features(ApfsAccess.EncryptedReadTransport PUBLIC cxx_std_20)
    target_compile_definitions(ApfsAccess.EncryptedReadTransport PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    add_executable(ApfsEncryptedReadTool tools/ApfsEncryptedReadTool.cpp)
    target_link_libraries(ApfsEncryptedReadTool PRIVATE ApfsAccess.EncryptedReadTransport)
    target_compile_definitions(ApfsEncryptedReadTool PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    if(MSVC)
        target_compile_options(ApfsAccess.EncryptedReadTransport PRIVATE /W4 /permissive-)
        target_compile_options(ApfsEncryptedReadTool PRIVATE /W4 /permissive-)
    endif()
    if(BUILD_TESTING)

        add_executable(EncryptedReadToolFixtures tests/EncryptedReadToolFixtures.cpp)
        target_link_libraries(EncryptedReadToolFixtures PRIVATE ApfsAccess.ApfsRwEngine)
        target_compile_definitions(EncryptedReadToolFixtures PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
        # Caller selects a private artifact root; no fixture writes in the source tree.
        set(APFSACCESS_ENCRYPTED_READ_INTEGRATION_ROOT "" CACHE PATH "Private encrypted read integration artifacts")
        if(APFSACCESS_ENCRYPTED_READ_INTEGRATION_ROOT)
            find_package(Python3 REQUIRED COMPONENTS Interpreter)
            add_test(NAME EncryptedReadToolIntegration COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/EncryptedReadToolIntegration.py
                --root ${APFSACCESS_ENCRYPTED_READ_INTEGRATION_ROOT}
                --tool $<TARGET_FILE:ApfsEncryptedReadTool>
                --fixture-builder $<TARGET_FILE:EncryptedReadToolFixtures>
                --vectors ${CMAKE_CURRENT_SOURCE_DIR}/tests/ApfsKeybagUnlockVectors.h)
            set_tests_properties(EncryptedReadToolIntegration PROPERTIES TIMEOUT 120 FIXTURES_SETUP EncryptedReadFixture)
            add_test(NAME EncryptedReadToolReview COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/EncryptedReadToolReview.py
                --root ${APFSACCESS_ENCRYPTED_READ_INTEGRATION_ROOT}
                --tool $<TARGET_FILE:ApfsEncryptedReadTool> --label GREEN
                --observer $<TARGET_FILE:ApfsAccess.ApfsRwEngine.VerifierObserverTests>
                --vectors ${CMAKE_CURRENT_SOURCE_DIR}/tests/ApfsKeybagUnlockVectors.h)
            set_tests_properties(EncryptedReadToolReview PROPERTIES TIMEOUT 60 FIXTURES_REQUIRED EncryptedReadFixture)
        endif()
    endif()
endif()

# Private offline image management only; deliberately excluded by default.
option(APFSACCESS_BUILD_PRIVATE_VOLUME_QUOTA_TOOL "Build private image quota/reserve command" OFF)
if(WIN32 AND APFSACCESS_BUILD_PRIVATE_VOLUME_QUOTA_TOOL)
    add_executable(VolumeQuotaReserveImageTool tools/VolumeQuotaReserveImageTool.cpp)
    target_link_libraries(VolumeQuotaReserveImageTool PRIVATE ApfsAccess.ApfsRwEngine bcrypt)
    target_compile_features(VolumeQuotaReserveImageTool PRIVATE cxx_std_20)
    if(BUILD_TESTING)
        add_executable(VolumeQuotaReserveTests tests/VolumeQuotaReserveTests.cpp)
        target_link_libraries(VolumeQuotaReserveTests PRIVATE ApfsAccess.ApfsRwEngine bcrypt)
        target_compile_features(VolumeQuotaReserveTests PRIVATE cxx_std_20)
        set(APFSACCESS_PRIVATE_VOLUME_QUOTA_TEST_ROOT "" CACHE PATH "Private D: quota/reserve evidence directory")
        if(APFSACCESS_PRIVATE_VOLUME_QUOTA_TEST_ROOT)
            add_test(NAME VolumeQuotaReserveTests COMMAND VolumeQuotaReserveTests ${APFSACCESS_PRIVATE_VOLUME_QUOTA_TEST_ROOT})
            set_tests_properties(VolumeQuotaReserveTests PROPERTIES TIMEOUT 120 RUN_SERIAL TRUE)
        endif()
    endif()
endif()
