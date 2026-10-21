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
    src/ApfsFirmlinkTable.cpp
    src/ApfsFormat.cpp
    src/ApfsSharedSpace.cpp
    src/ApfsSpaceAccounting.cpp
    src/ApfsSnapshotStore.cpp
    src/ApfsVerifier.cpp
    src/ApfsVerificationJson.cpp
    src/CurrentPayloadObservation.cpp
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
    src/NativeHardLinkPlan.cpp
    src/NativeSparsePlan.cpp
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
    target_sources(ApfsAccess.ApfsRwEngine PRIVATE src/ApfsFirmlinkProducer.cpp
        src/ApfsCrypto.cpp src/ApfsKeybag.cpp src/ApfsKeybagUnlock.cpp
        src/ApfsEncryptedReadSession.cpp src/ApfsEncryptedWriteTransform.cpp src/ProtectedJournalEpoch.cpp
        src/EncryptedPublicationJournal.cpp src/ApfsEncryptedImageWriteSession.cpp src/EncryptedImageRuntime.cpp
        src/ProtectedJournalContinuation.cpp
        src/NativeHardLink.cpp src/NativeHardLinkMetadata.cpp
        src/NativeSparse.cpp src/NativeSparseV2.cpp src/NativeSparseMetadata.cpp
        src/NativeCloneRange.cpp src/NativeCloneRangePlan.cpp src/NativeCloneRangeMetadata.cpp
        src/ApfsFusionImageWriteSession.cpp
        src/FusionImageRuntime.cpp src/FusionPublicationJournal.cpp src/FusionJournalContinuation.cpp
        src/ApfsSoftwareKeybagMaintenance.cpp src/ApfsSoftwareKeybagPublication.cpp
        src/SoftwareVolumeTransition.cpp src/SoftwareTransitionPlainWriter.cpp
        src/SoftwareEncryptedRetentionAuthority.cpp
        src/VolumeManagement.cpp src/VolumeTopology.cpp src/VolumeKeeperHistory.cpp
        src/VolumeKeeperAdmission.cpp src/VolumeResize.cpp src/VolumeResizeKeeper.cpp
        src/VolumeFormat.cpp src/VolumeResizeRelocation.cpp src/VolumeResizeRelocationPlan.cpp
        src/VolumePhysicalMedia.cpp src/VolumePhysicalGeometry.cpp src/VolumeGptGeometry.cpp
        src/BackupRetainedSource.cpp src/BackupPhysicalWriteOwner.cpp src/BackupMutationContract.cpp)
    target_link_libraries(ApfsAccess.ApfsRwEngine PRIVATE bcrypt setupapi crypt32 uuid advapi32 ole32 oleaut32 wbemuuid)
endif()

target_link_libraries(ApfsAccess.ApfsRwEngine
    PRIVATE
        ApfsAccess.Utf8Proc
)

# Fixed repo-owned read-only APFS observer: emits C0a evidence records.
# Hashing adapter is platform-selected (CNG on Windows, portable elsewhere);
# the portable implementation is also unit-tested on every platform.
if(WIN32)
    foreach(geometry_tool VolumePhysicalObserve)
        add_executable(${geometry_tool} tools/${geometry_tool}.cpp)
        target_link_libraries(${geometry_tool} PRIVATE ApfsAccess.ApfsRwEngine bcrypt user32 advapi32 shell32)
        target_compile_features(${geometry_tool} PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(${geometry_tool} PRIVATE /utf-8 /bigobj)
        endif()
    endforeach()
    if(BUILD_TESTING)
        add_executable(ObserverReadCacheTests tests/ObserverReadCacheTests.cpp)
        target_link_libraries(ObserverReadCacheTests PRIVATE ApfsAccess.ApfsRwEngine)
        target_compile_features(ObserverReadCacheTests PRIVATE cxx_std_20)
        add_test(NAME ObserverReadCacheTests COMMAND ObserverReadCacheTests)
        set_tests_properties(ObserverReadCacheTests PROPERTIES TIMEOUT 30)
    endif()
    add_executable(VolumeManagementImage tools/VolumeManagementImage.cpp)
    target_link_libraries(VolumeManagementImage PRIVATE ApfsAccess.ApfsRwEngine bcrypt user32)
    target_compile_features(VolumeManagementImage PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(VolumeManagementImage PRIVATE /utf-8 /bigobj)
    endif()
    add_executable(SnapshotImage tools/SnapshotImage.cpp)
    target_link_libraries(SnapshotImage PRIVATE ApfsAccess.ApfsRwEngine bcrypt user32)
    target_compile_features(SnapshotImage PRIVATE cxx_std_20)
    add_executable(VolumeRenameImage tools/VolumeRenameImage.cpp)
    target_link_libraries(VolumeRenameImage PRIVATE ApfsAccess.ApfsRwEngine bcrypt user32)
    target_compile_features(VolumeRenameImage PRIVATE cxx_std_20)
    add_executable(MintAppleFixtureImage tools/MintAppleFixtureImage.cpp)
    target_link_libraries(MintAppleFixtureImage PRIVATE ApfsAccess.ApfsRwEngine bcrypt user32)
    target_include_directories(MintAppleFixtureImage PRIVATE tests)
    target_compile_features(MintAppleFixtureImage PRIVATE cxx_std_20)
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
        foreach(management_test VolumeManagementTests VolumeManagementImageTests VolumeManagementObservationTests VolumeKeeperAdmissionTests VolumeKeeperHistoryTests)
            add_executable(ApfsAccess.ApfsRwEngine.${management_test} tests/${management_test}.cpp)
            target_link_libraries(ApfsAccess.ApfsRwEngine.${management_test} PRIVATE ApfsAccess.ApfsRwEngine bcrypt user32)
            target_compile_features(ApfsAccess.ApfsRwEngine.${management_test} PRIVATE cxx_std_20)
            if(MSVC)
                target_compile_options(ApfsAccess.ApfsRwEngine.${management_test} PRIVATE /utf-8 /bigobj)
            endif()
            add_test(NAME ApfsAccess.ApfsRwEngine.${management_test} COMMAND ${CMAKE_COMMAND}
                "-DTEST_EXE=$<TARGET_FILE:ApfsAccess.ApfsRwEngine.${management_test}>"
                "-DEVIDENCE_ROOT=${CMAKE_CURRENT_BINARY_DIR}/volume-management-evidence/${management_test}"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/RunFreshVolumeManagementTest.cmake")
            set_tests_properties(ApfsAccess.ApfsRwEngine.${management_test} PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
        endforeach()
        foreach(snapshot_test SnapshotRuntimeTests SnapshotRuntimeWalTests SnapshotPublishReviewTests SnapshotRuntimeReviewTests SnapshotRepairIntegrationTests QuotaRepairSnapshotIntegrationTests SnapshotOwnerBridgeTests)
            add_executable(ApfsAccess.ApfsRwEngine.${snapshot_test} tests/${snapshot_test}.cpp)
            target_link_libraries(ApfsAccess.ApfsRwEngine.${snapshot_test} PRIVATE ApfsAccess.ApfsRwEngine bcrypt user32)
            target_compile_features(ApfsAccess.ApfsRwEngine.${snapshot_test} PRIVATE cxx_std_20)
            add_test(NAME ApfsAccess.ApfsRwEngine.${snapshot_test} COMMAND ApfsAccess.ApfsRwEngine.${snapshot_test})
        endforeach()
        set(APFSACCESS_SNAPSHOT_OWNER_BRIDGE_ROOT "" CACHE PATH "Private D: snapshot owner-bridge process evidence directory")
        add_executable(ApfsAccess.ApfsRwEngine.RawSnapshotRuntimeTests
            tests/RawSnapshotRuntimeTests.cpp tests/RawSnapshotRuntimeTestDevice.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.RawSnapshotRuntimeTests PRIVATE ApfsAccess.ApfsRwEngine bcrypt user32)
        target_compile_features(ApfsAccess.ApfsRwEngine.RawSnapshotRuntimeTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.RawSnapshotRuntimeTests PRIVATE /utf-8 /bigobj)
        endif()
        set(APFSACCESS_RAW_SNAPSHOT_RUNTIME_TEST_ROOT "" CACHE PATH "Private D: raw snapshot loopback evidence directory")
        if(APFSACCESS_RAW_SNAPSHOT_RUNTIME_TEST_ROOT)
            add_test(NAME ApfsAccess.ApfsRwEngine.RawSnapshotRuntimeTests
                COMMAND ApfsAccess.ApfsRwEngine.RawSnapshotRuntimeTests ${APFSACCESS_RAW_SNAPSHOT_RUNTIME_TEST_ROOT})
            set_tests_properties(ApfsAccess.ApfsRwEngine.RawSnapshotRuntimeTests PROPERTIES TIMEOUT 600 RUN_SERIAL TRUE)
        endif()
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
        add_executable(ApfsAccess.ApfsRwEngine.RawDeviceAdmissionTests tests/RawDeviceAdmissionTests.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.RawDeviceAdmissionTests PRIVATE ApfsAccess.ApfsRwEngine bcrypt user32)
        target_compile_features(ApfsAccess.ApfsRwEngine.RawDeviceAdmissionTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.RawDeviceAdmissionTests PRIVATE /utf-8 /bigobj)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.RawDeviceAdmission COMMAND ApfsAccess.ApfsRwEngine.RawDeviceAdmissionTests)
        add_executable(ApfsAccess.ApfsRwEngine.BlockDeviceVerificationTests tests/BlockDeviceVerificationTests.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.BlockDeviceVerificationTests PRIVATE ApfsAccess.ApfsRwEngine bcrypt user32)
        target_compile_features(ApfsAccess.ApfsRwEngine.BlockDeviceVerificationTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.BlockDeviceVerificationTests PRIVATE /utf-8 /bigobj)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.BlockDeviceVerification COMMAND ${CMAKE_COMMAND}
            "-DTEST_EXE=$<TARGET_FILE:ApfsAccess.ApfsRwEngine.BlockDeviceVerificationTests>"
            "-DEVIDENCE_ROOT=${CMAKE_CURRENT_BINARY_DIR}/block-device-verification"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/RunFreshVolumeManagementTest.cmake")
        set_tests_properties(ApfsAccess.ApfsRwEngine.BlockDeviceVerification PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
        add_executable(ApfsAccess.ApfsRwEngine.BlockDeviceCacheRangesTests tests/BlockDeviceCacheRangesTests.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.BlockDeviceCacheRangesTests PRIVATE ApfsAccess.ApfsRwEngine bcrypt user32)
        target_compile_features(ApfsAccess.ApfsRwEngine.BlockDeviceCacheRangesTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.BlockDeviceCacheRangesTests PRIVATE /utf-8 /bigobj)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.BlockDeviceCacheRanges COMMAND ${CMAKE_COMMAND}
            "-DTEST_EXE=$<TARGET_FILE:ApfsAccess.ApfsRwEngine.BlockDeviceCacheRangesTests>"
            "-DEVIDENCE_ROOT=${CMAKE_CURRENT_BINARY_DIR}/block-device-cache-ranges"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/RunFreshVolumeManagementTest.cmake")
        set_tests_properties(ApfsAccess.ApfsRwEngine.BlockDeviceCacheRanges PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
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
        add_executable(ApfsAccess.ApfsRwEngine.FusionExtentCoalescingTests
            tests/FusionExtentCoalescingTests.cpp)
        target_include_directories(ApfsAccess.ApfsRwEngine.FusionExtentCoalescingTests PRIVATE src)
        target_link_libraries(ApfsAccess.ApfsRwEngine.FusionExtentCoalescingTests PRIVATE ApfsAccess.ApfsRwEngine)
        target_compile_features(ApfsAccess.ApfsRwEngine.FusionExtentCoalescingTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.FusionExtentCoalescingTests PRIVATE /W4 /WX /utf-8 /bigobj)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.FusionExtentCoalescing
            COMMAND ApfsAccess.ApfsRwEngine.FusionExtentCoalescingTests)
    endif()
    add_executable(ApfsAccess.ApfsRwEngine.VerifierTests tests/ApfsVerifierTests.cpp)
    target_link_libraries(ApfsAccess.ApfsRwEngine.VerifierTests PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_features(ApfsAccess.ApfsRwEngine.VerifierTests PRIVATE cxx_std_20)
    add_test(NAME ApfsAccess.ApfsRwEngine.Verifier COMMAND ApfsAccess.ApfsRwEngine.VerifierTests)
    add_executable(ApfsAccess.ApfsRwEngine.VerifierProfileJsonTests tests/ApfsVerifierProfileJsonTests.cpp)
    target_link_libraries(ApfsAccess.ApfsRwEngine.VerifierProfileJsonTests PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_features(ApfsAccess.ApfsRwEngine.VerifierProfileJsonTests PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(ApfsAccess.ApfsRwEngine.VerifierProfileJsonTests PRIVATE /W4 /utf-8)
    endif()
    if(WIN32)
        set(profile_json_evidence_root "D:/ApfsAccessScratch/p/ProfileJson")
    else()
        set(profile_json_evidence_root "${CMAKE_CURRENT_BINARY_DIR}/profile-json-evidence")
    endif()
    add_test(NAME ApfsAccess.ApfsRwEngine.VerifierProfileJson COMMAND ${CMAKE_COMMAND}
        "-DTEST_EXE=$<TARGET_FILE:ApfsAccess.ApfsRwEngine.VerifierProfileJsonTests>"
        "-DEVIDENCE_ROOT=${profile_json_evidence_root}" "-DTEST_TIMEOUT=120"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/RunFreshNativeFileTest.cmake")
    set_tests_properties(ApfsAccess.ApfsRwEngine.VerifierProfileJson PROPERTIES TIMEOUT 150)
    add_executable(ApfsAccess.ApfsRwEngine.VerifierCensusTests tests/ApfsVerifierCensusTests.cpp)
    target_link_libraries(ApfsAccess.ApfsRwEngine.VerifierCensusTests PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_features(ApfsAccess.ApfsRwEngine.VerifierCensusTests PRIVATE cxx_std_20)
    add_test(NAME ApfsAccess.ApfsRwEngine.VerifierCensus COMMAND ApfsAccess.ApfsRwEngine.VerifierCensusTests)
    add_executable(ApfsAccess.ApfsRwEngine.VerifierCloneHintTests tests/ApfsVerifierCloneHintTests.cpp)
    target_link_libraries(ApfsAccess.ApfsRwEngine.VerifierCloneHintTests PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_features(ApfsAccess.ApfsRwEngine.VerifierCloneHintTests PRIVATE cxx_std_20)
    add_test(NAME ApfsAccess.ApfsRwEngine.VerifierCloneHint COMMAND ApfsAccess.ApfsRwEngine.VerifierCloneHintTests)
    add_executable(ApfsAccess.ApfsRwEngine.VerifierHistoryTests tests/ApfsVerifierHistoryTests.cpp)
    target_link_libraries(ApfsAccess.ApfsRwEngine.VerifierHistoryTests PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_features(ApfsAccess.ApfsRwEngine.VerifierHistoryTests PRIVATE cxx_std_20)
    add_test(NAME ApfsAccess.ApfsRwEngine.VerifierHistory COMMAND ApfsAccess.ApfsRwEngine.VerifierHistoryTests)
    add_executable(ApfsAccess.ApfsRwEngine.VerifierRetainedOwnershipTests tests/ApfsVerifierRetainedOwnershipTests.cpp)
    target_link_libraries(ApfsAccess.ApfsRwEngine.VerifierRetainedOwnershipTests PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_features(ApfsAccess.ApfsRwEngine.VerifierRetainedOwnershipTests PRIVATE cxx_std_20)
    add_test(NAME ApfsAccess.ApfsRwEngine.VerifierRetainedOwnership
        COMMAND ApfsAccess.ApfsRwEngine.VerifierRetainedOwnershipTests)
    add_executable(ApfsAccess.ApfsRwEngine.BtreeRoutingTests tests/BtreeRoutingTests.cpp)
    target_link_libraries(ApfsAccess.ApfsRwEngine.BtreeRoutingTests PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_features(ApfsAccess.ApfsRwEngine.BtreeRoutingTests PRIVATE cxx_std_20)
    add_test(NAME ApfsAccess.ApfsRwEngine.BtreeRouting COMMAND ApfsAccess.ApfsRwEngine.BtreeRoutingTests)
    if(WIN32)
        add_executable(ApfsAccess.ApfsRwEngine.VerifierRetainedJsonTests tests/ApfsVerifierRetainedJsonTests.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.VerifierRetainedJsonTests PRIVATE
            ApfsAccess.ApfsRwEngine bcrypt)
        target_compile_features(ApfsAccess.ApfsRwEngine.VerifierRetainedJsonTests PRIVATE cxx_std_20)
        add_test(NAME ApfsAccess.ApfsRwEngine.VerifierRetainedJson COMMAND ${CMAKE_COMMAND}
            "-DTEST_EXE=$<TARGET_FILE:ApfsAccess.ApfsRwEngine.VerifierRetainedJsonTests>"
            "-DEVIDENCE_ROOT=${CMAKE_BINARY_DIR}/verifier-retained-json"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/RunFreshNativeFileTest.cmake")
        set_tests_properties(ApfsAccess.ApfsRwEngine.VerifierRetainedJson PROPERTIES TIMEOUT 270)
        add_executable(ApfsAccess.ApfsRwEngine.VerifierDescriptorMagicTests tests/ApfsVerifierDescriptorMagicTests.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.VerifierDescriptorMagicTests PRIVATE ApfsAccess.ApfsRwEngine)
        target_compile_features(ApfsAccess.ApfsRwEngine.VerifierDescriptorMagicTests PRIVATE cxx_std_20)
        add_test(NAME ApfsAccess.ApfsRwEngine.VerifierDescriptorMagic COMMAND ${CMAKE_COMMAND}
            "-DTEST_EXE=$<TARGET_FILE:ApfsAccess.ApfsRwEngine.VerifierDescriptorMagicTests>"
            "-DEVIDENCE_ROOT=${CMAKE_BINARY_DIR}/verifier-descriptor-magic"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/RunFreshNativeFileTest.cmake")
        set_tests_properties(ApfsAccess.ApfsRwEngine.VerifierDescriptorMagic PROPERTIES TIMEOUT 270)
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
        foreach(protected_test ProtectedJournalEpochTests ProtectedJournalReadPassTests ProtectedWriteAheadLogTests ProtectedPayloadSpoolTests)
            add_executable(ApfsAccess.ApfsRwEngine.${protected_test}
                tests/${protected_test}.cpp src/ApfsCrypto.cpp src/ProtectedJournalEpoch.cpp)
            target_compile_definitions(ApfsAccess.ApfsRwEngine.${protected_test} PRIVATE
                APFSACCESS_CRYPTO_TESTING APFSACCESS_PROTECTED_JOURNAL_TESTING)
            target_include_directories(ApfsAccess.ApfsRwEngine.${protected_test} PRIVATE tests)
            target_link_libraries(ApfsAccess.ApfsRwEngine.${protected_test} PRIVATE
                ApfsAccess.ApfsRwEngine bcrypt crypt32 advapi32 user32)
            target_compile_features(ApfsAccess.ApfsRwEngine.${protected_test} PRIVATE cxx_std_20)
        endforeach()
        target_sources(ApfsAccess.ApfsRwEngine.ProtectedWriteAheadLogTests PRIVATE src/WriteAheadLog.cpp)
        target_sources(ApfsAccess.ApfsRwEngine.ProtectedJournalReadPassTests PRIVATE src/WriteAheadLog.cpp)
        target_sources(ApfsAccess.ApfsRwEngine.ProtectedPayloadSpoolTests PRIVATE src/PayloadSpool.cpp)
        target_compile_definitions(ApfsAccess.ApfsRwEngine.ProtectedPayloadSpoolTests PRIVATE
            APFSACCESS_PROTECTED_SPOOL_TESTING)
        add_executable(ApfsAccess.ApfsRwEngine.ProtectedTransactionTests tests/ProtectedTransactionTests.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.ProtectedTransactionTests PRIVATE
            ApfsAccess.ApfsRwEngine bcrypt crypt32 advapi32 user32)
        target_compile_features(ApfsAccess.ApfsRwEngine.ProtectedTransactionTests PRIVATE cxx_std_20)
        set(APFSACCESS_PROTECTED_TEST_ROOT "D:/ApfsAccessScratch/p" CACHE PATH
            "Short private root for bounded protected-persistence test paths")
        foreach(protected_test ProtectedJournalEpochTests ProtectedJournalReadPassTests ProtectedWriteAheadLogTests ProtectedPayloadSpoolTests ProtectedTransactionTests)
            string(REGEX REPLACE "^Protected|Tests$" "" protected_test_directory "${protected_test}")
            set(protected_test_timeout 240)
            if(protected_test STREQUAL "ProtectedWriteAheadLogTests" OR protected_test STREQUAL "ProtectedPayloadSpoolTests")
                # Exhaustive DPAPI replay, real capacity reuse and durable
                # maintenance cuts exceed the ordinary Windows file-test budget.
                set(protected_test_timeout 900)
            endif()
            if(MSVC)
                target_compile_options(ApfsAccess.ApfsRwEngine.${protected_test} PRIVATE /W4 /permissive- /utf-8)
            endif()
            add_test(NAME ApfsAccess.ApfsRwEngine.${protected_test} COMMAND ${CMAKE_COMMAND}
                "-DTEST_EXE=$<TARGET_FILE:ApfsAccess.ApfsRwEngine.${protected_test}>"
                "-DEVIDENCE_ROOT=${APFSACCESS_PROTECTED_TEST_ROOT}/${protected_test_directory}"
                "-DTEST_TIMEOUT=${protected_test_timeout}"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/RunFreshNativeFileTest.cmake")
            math(EXPR protected_ctest_timeout "${protected_test_timeout} + 30")
            set_tests_properties(ApfsAccess.ApfsRwEngine.${protected_test} PROPERTIES TIMEOUT ${protected_ctest_timeout} RUN_SERIAL TRUE)
        endforeach()
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
    foreach(_snapshot_test ApfsSnapshotStoreTests SnapshotParserRedTests SnapshotProjectionTests SnapshotReadStoreTests SnapshotCompressionReadTests SnapshotRetentionTests EncryptedWriteRefusalTests)
        add_executable(ApfsAccess.ApfsRwEngine.${_snapshot_test} tests/${_snapshot_test}.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.${_snapshot_test} PRIVATE ApfsAccess.ApfsRwEngine)
        target_compile_features(ApfsAccess.ApfsRwEngine.${_snapshot_test} PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.${_snapshot_test} PRIVATE /W4 /permissive-)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.${_snapshot_test} COMMAND ApfsAccess.ApfsRwEngine.${_snapshot_test})
    endforeach()
    target_compile_definitions(ApfsAccess.ApfsRwEngine.SnapshotParserRedTests PRIVATE SNAPSHOT_STRICT_POLICY)
    if(WIN32)
        set(APFSACCESS_SNAPSHOT_LIVE_BUDGET_IMAGE "" CACHE FILEPATH "Read-only high-record snapshot regression image")
        add_executable(ApfsAccess.ApfsRwEngine.SnapshotLiveBudgetTests tests/SnapshotLiveBudgetTests.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.SnapshotLiveBudgetTests PRIVATE ApfsAccess.ApfsRwEngine bcrypt user32)
        target_compile_features(ApfsAccess.ApfsRwEngine.SnapshotLiveBudgetTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.SnapshotLiveBudgetTests PRIVATE /utf-8 /bigobj)
        endif()
        if(APFSACCESS_SNAPSHOT_LIVE_BUDGET_IMAGE)
            add_test(NAME ApfsAccess.ApfsRwEngine.SnapshotLiveBudget
                COMMAND ApfsAccess.ApfsRwEngine.SnapshotLiveBudgetTests "${APFSACCESS_SNAPSHOT_LIVE_BUDGET_IMAGE}")
            set_tests_properties(ApfsAccess.ApfsRwEngine.SnapshotLiveBudget PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE)
        endif()
    endif()
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
    if(WIN32)
        foreach(_plain_test Layout Replay)
            set(_plain_target ApfsAccess.ApfsRwEngine.PlainExtent${_plain_test}Tests)
            add_executable(${_plain_target} tests/PlainExtent${_plain_test}Tests.cpp)
            target_link_libraries(${_plain_target} PRIVATE ApfsAccess.ApfsRwEngine bcrypt)
            target_compile_features(${_plain_target} PRIVATE cxx_std_20)
            if(MSVC)
                target_compile_options(${_plain_target} PRIVATE /utf-8 /bigobj)
            endif()
            add_test(NAME ${_plain_target} COMMAND ${CMAKE_COMMAND}
                "-DTEST_EXE=$<TARGET_FILE:${_plain_target}>"
                "-DMODE=${_plain_test}"
                "-DEVIDENCE_ROOT=${CMAKE_CURRENT_BINARY_DIR}/plain-extent-evidence"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/RunPlainExtentTest.cmake")
            set_tests_properties(${_plain_target} PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
        endforeach()
        add_executable(ApfsAccess.ApfsRwEngine.NativeHardLinkAcceptanceTests tests/NativeHardLinkAcceptanceTests.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.NativeHardLinkAcceptanceTests PRIVATE ApfsAccess.ApfsRwEngine bcrypt)
        target_compile_features(ApfsAccess.ApfsRwEngine.NativeHardLinkAcceptanceTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.NativeHardLinkAcceptanceTests PRIVATE /utf-8 /bigobj)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.NativeHardLinkAcceptanceTests COMMAND ${CMAKE_COMMAND}
            "-DTEST_EXE=$<TARGET_FILE:ApfsAccess.ApfsRwEngine.NativeHardLinkAcceptanceTests>"
            "-DEVIDENCE_ROOT=${CMAKE_CURRENT_BINARY_DIR}/hard-link-evidence"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/RunFreshNativeFileTest.cmake")
        set_tests_properties(ApfsAccess.ApfsRwEngine.NativeHardLinkAcceptanceTests PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
        add_executable(ApfsAccess.ApfsRwEngine.NativeSparseTransactionTests tests/NativeSparseTransactionTests.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.NativeSparseTransactionTests PRIVATE ApfsAccess.ApfsRwEngine bcrypt)
        target_compile_features(ApfsAccess.ApfsRwEngine.NativeSparseTransactionTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.NativeSparseTransactionTests PRIVATE /utf-8 /bigobj)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.NativeSparseTransactionTests COMMAND ${CMAKE_COMMAND}
            "-DTEST_EXE=$<TARGET_FILE:ApfsAccess.ApfsRwEngine.NativeSparseTransactionTests>"
            "-DEVIDENCE_ROOT=${CMAKE_CURRENT_BINARY_DIR}/native-sparse-evidence"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/RunFreshNativeFileTest.cmake")
        set_tests_properties(ApfsAccess.ApfsRwEngine.NativeSparseTransactionTests PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
        add_executable(ApfsAccess.ApfsRwEngine.NativeSparseScaleTests tests/NativeSparseScaleTests.cpp)
        add_library(ApfsAccess.ApfsRwEngine.SparseMeasuredDevice OBJECT src/BlockDevice.cpp)
        target_include_directories(ApfsAccess.ApfsRwEngine.SparseMeasuredDevice PRIVATE include)
        target_compile_features(ApfsAccess.ApfsRwEngine.SparseMeasuredDevice PRIVATE cxx_std_20)
        target_compile_definitions(ApfsAccess.ApfsRwEngine.SparseMeasuredDevice PRIVATE NOMINMAX)
        target_sources(ApfsAccess.ApfsRwEngine.NativeSparseScaleTests PRIVATE
            $<TARGET_OBJECTS:ApfsAccess.ApfsRwEngine.SparseMeasuredDevice>)
        target_link_libraries(ApfsAccess.ApfsRwEngine.NativeSparseScaleTests PRIVATE ApfsAccess.ApfsRwEngine bcrypt)
        target_compile_features(ApfsAccess.ApfsRwEngine.NativeSparseScaleTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.NativeSparseScaleTests PRIVATE /utf-8 /bigobj)
            target_compile_options(ApfsAccess.ApfsRwEngine.SparseMeasuredDevice PRIVATE
                "/FI${CMAKE_CURRENT_SOURCE_DIR}/tests/NativeSparseScaleIoShim.h" /utf-8)
        else()
            target_compile_options(ApfsAccess.ApfsRwEngine.SparseMeasuredDevice PRIVATE
                -include "${CMAKE_CURRENT_SOURCE_DIR}/tests/NativeSparseScaleIoShim.h")
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.NativeSparseScaleTests COMMAND ${CMAKE_COMMAND}
            "-DTEST_EXE=$<TARGET_FILE:ApfsAccess.ApfsRwEngine.NativeSparseScaleTests>"
            "-DEVIDENCE_ROOT=${CMAKE_CURRENT_BINARY_DIR}/native-sparse-scale-evidence"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/RunNativeSparseScaleTest.cmake")
        set_tests_properties(ApfsAccess.ApfsRwEngine.NativeSparseScaleTests PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
    endif()
    add_executable(ApfsAccess.ApfsRwEngine.VolumeSpaceTests tests/ApfsVolumeSpaceTests.cpp)
    target_link_libraries(ApfsAccess.ApfsRwEngine.VolumeSpaceTests PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_features(ApfsAccess.ApfsRwEngine.VolumeSpaceTests PRIVATE cxx_std_20)
    add_test(NAME ApfsAccess.ApfsRwEngine.VolumeSpaceTests COMMAND ApfsAccess.ApfsRwEngine.VolumeSpaceTests)
    add_executable(ApfsAccess.ApfsRwEngine.SpaceAccountingTests tests/ApfsSpaceAccountingTests.cpp)
    target_link_libraries(ApfsAccess.ApfsRwEngine.SpaceAccountingTests PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_features(ApfsAccess.ApfsRwEngine.SpaceAccountingTests PRIVATE cxx_std_20)
    add_test(NAME ApfsAccess.ApfsRwEngine.SpaceAccountingTests COMMAND ApfsAccess.ApfsRwEngine.SpaceAccountingTests)
    add_executable(ApfsAccess.ApfsRwEngine.SnapshotAttributionTests tests/ApfsSnapshotAttributionTests.cpp)
    target_link_libraries(ApfsAccess.ApfsRwEngine.SnapshotAttributionTests PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_features(ApfsAccess.ApfsRwEngine.SnapshotAttributionTests PRIVATE cxx_std_20)
    add_test(NAME ApfsAccess.ApfsRwEngine.SnapshotAttributionTests
        COMMAND ApfsAccess.ApfsRwEngine.SnapshotAttributionTests)
    if(WIN32)
        add_executable(ApfsAccess.ApfsRwEngine.SpaceAccountingObserverFixtures tests/ApfsSpaceAccountingObserverFixtures.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.SpaceAccountingObserverFixtures PRIVATE ApfsAccess.ApfsRwEngine)
        target_compile_features(ApfsAccess.ApfsRwEngine.SpaceAccountingObserverFixtures PRIVATE cxx_std_20)
        set(APFSACCESS_SNAPSHOT_SPACE_OBSERVER_TEST_ROOT "" CACHE PATH "Private snapshot-space observer test artifacts")
        if(APFSACCESS_SNAPSHOT_SPACE_OBSERVER_TEST_ROOT)
            find_package(Python3 REQUIRED COMPONENTS Interpreter)
            add_test(NAME ApfsAccess.ApfsRwEngine.SpaceAccountingObserver COMMAND ${Python3_EXECUTABLE} -B
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/ApfsSpaceAccountingObserverTests.py
                --root ${APFSACCESS_SNAPSHOT_SPACE_OBSERVER_TEST_ROOT}
                --observer $<TARGET_FILE:ApfsObserver>
                --fixture-builder $<TARGET_FILE:ApfsAccess.ApfsRwEngine.SpaceAccountingObserverFixtures>)
            set_tests_properties(ApfsAccess.ApfsRwEngine.SpaceAccountingObserver PROPERTIES TIMEOUT 120 RUN_SERIAL TRUE)
        endif()
    endif()
    if(WIN32)
        add_executable(ApfsAccess.ApfsRwEngine.NativeCheckpointHandoffTests tests/NativeCheckpointHandoffTests.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.NativeCheckpointHandoffTests PRIVATE ApfsAccess.ApfsRwEngine bcrypt)
        target_compile_features(ApfsAccess.ApfsRwEngine.NativeCheckpointHandoffTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.NativeCheckpointHandoffTests PRIVATE /utf-8 /bigobj)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.NativeCheckpointHandoffTests COMMAND ApfsAccess.ApfsRwEngine.NativeCheckpointHandoffTests)
        set_tests_properties(ApfsAccess.ApfsRwEngine.NativeCheckpointHandoffTests PROPERTIES
            ENVIRONMENT "APFSACCESS_PERF_COUNTERS=1" TIMEOUT 120)
        add_executable(ApfsAccess.ApfsRwEngine.CanonicalStagingCapacityTests tests/CanonicalStagingCapacityTests.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.CanonicalStagingCapacityTests PRIVATE ApfsAccess.ApfsRwEngine bcrypt)
        target_compile_features(ApfsAccess.ApfsRwEngine.CanonicalStagingCapacityTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.CanonicalStagingCapacityTests PRIVATE /utf-8 /bigobj)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.CanonicalStagingCapacityTests COMMAND ApfsAccess.ApfsRwEngine.CanonicalStagingCapacityTests)
        set_tests_properties(ApfsAccess.ApfsRwEngine.CanonicalStagingCapacityTests PROPERTIES TIMEOUT 120)
    endif()
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

    add_executable(ApfsAccess.ApfsRwEngine.CurrentPayloadAdmissionTests tests/CurrentPayloadAdmissionTests.cpp)
    target_link_libraries(ApfsAccess.ApfsRwEngine.CurrentPayloadAdmissionTests PRIVATE ApfsAccess.ApfsRwEngine)
    target_compile_features(ApfsAccess.ApfsRwEngine.CurrentPayloadAdmissionTests PRIVATE cxx_std_20)
    add_test(NAME ApfsAccess.ApfsRwEngine.CurrentPayloadAdmissionTests COMMAND ApfsAccess.ApfsRwEngine.CurrentPayloadAdmissionTests)
    set_tests_properties(ApfsAccess.ApfsRwEngine.CurrentPayloadAdmissionTests PROPERTIES TIMEOUT 120)
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
    target_link_libraries(ApfsObserver PRIVATE ApfsAccess.EncryptedReadTransport)
    if(BUILD_TESTING)
        # Authentic-image cases require an explicit private image copy and the
        # protected credential pipe supplied by their orchestration runner.
        add_executable(ApfsAccess.ApfsRwEngine.EncryptedPublicationJournalTests
            tests/EncryptedPublicationJournalTests.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.EncryptedPublicationJournalTests PRIVATE
            ApfsAccess.EncryptedReadTransport bcrypt crypt32 advapi32 user32)
        target_compile_features(ApfsAccess.ApfsRwEngine.EncryptedPublicationJournalTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.EncryptedPublicationJournalTests PRIVATE /W4 /utf-8)
        endif()
        add_executable(ApfsAccess.ApfsRwEngine.EncryptedDeltaCoreTests tests/EncryptedDeltaCoreTests.cpp)
        target_include_directories(ApfsAccess.ApfsRwEngine.EncryptedDeltaCoreTests PRIVATE src)
        target_link_libraries(ApfsAccess.ApfsRwEngine.EncryptedDeltaCoreTests PRIVATE
            ApfsAccess.ApfsRwEngine bcrypt crypt32)
        target_compile_features(ApfsAccess.ApfsRwEngine.EncryptedDeltaCoreTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.EncryptedDeltaCoreTests PRIVATE /W4 /utf-8)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.EncryptedDeltaCore
            COMMAND ApfsAccess.ApfsRwEngine.EncryptedDeltaCoreTests)
        set_tests_properties(ApfsAccess.ApfsRwEngine.EncryptedDeltaCore PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE)
        foreach(image_test ApfsEncryptedImageWriteSessionTests ApfsEncryptedImageDeltaLifecycleTests
            EncryptedKeybagJournalTests EncryptedImageRuntimeTests ApfsFusionImageWriteSessionTests)
            add_executable(ApfsAccess.ApfsRwEngine.${image_test} tests/${image_test}.cpp)
            target_link_libraries(ApfsAccess.ApfsRwEngine.${image_test} PRIVATE
                ApfsAccess.EncryptedReadTransport bcrypt crypt32 advapi32 user32)
            target_compile_features(ApfsAccess.ApfsRwEngine.${image_test} PRIVATE cxx_std_20)
            if(MSVC)
                target_compile_options(ApfsAccess.ApfsRwEngine.${image_test} PRIVATE /W4 /utf-8)
            endif()
        endforeach()
    endif()
    add_executable(ApfsEncryptedReadTool tools/ApfsEncryptedReadTool.cpp)
    target_link_libraries(ApfsEncryptedReadTool PRIVATE ApfsAccess.EncryptedReadTransport)
    target_compile_definitions(ApfsEncryptedReadTool PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    add_executable(ApfsAccess.ApfsImageKeyManagementTool tools/ApfsImageKeyManagementTool.cpp)
    target_link_libraries(ApfsAccess.ApfsImageKeyManagementTool PRIVATE
        ApfsAccess.EncryptedReadTransport bcrypt crypt32 setupapi advapi32 user32 uuid ole32 shell32 version ws2_32)
    target_compile_features(ApfsAccess.ApfsImageKeyManagementTool PRIVATE cxx_std_20)
    target_compile_definitions(ApfsAccess.ApfsImageKeyManagementTool PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    if(MSVC)
        target_compile_options(ApfsAccess.ApfsImageKeyManagementTool PRIVATE /W4 /utf-8 /bigobj)
    endif()
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

# Bounded ordinary-image resize and format operations retain their own journals.
if(WIN32)
    target_sources(ApfsAccess.ApfsRwEngine PRIVATE
        src/VolumeResize.cpp src/VolumeResizeRelocation.cpp src/VolumeResizeRelocationPlan.cpp
        src/VolumeResizeKeeper.cpp src/VolumeFormat.cpp src/VolumeKeeperAdmission.cpp src/VolumePhysicalMedia.cpp)
    add_executable(VolumeKeeperInspect tools/VolumeKeeperInspect.cpp)
    target_link_libraries(VolumeKeeperInspect PRIVATE ApfsAccess.ApfsRwEngine bcrypt)
    target_compile_features(VolumeKeeperInspect PRIVATE cxx_std_20)
    if(MSVC)
        target_compile_options(VolumeKeeperInspect PRIVATE /utf-8 /bigobj)
    endif()
    foreach(family VolumeResize VolumeFormat)
        add_executable(${family}Image tools/${family}Image.cpp)
        target_link_libraries(${family}Image PRIVATE ApfsAccess.ApfsRwEngine bcrypt user32)
        target_compile_features(${family}Image PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(${family}Image PRIVATE /utf-8 /bigobj)
        endif()
    endforeach()
    if(BUILD_TESTING)
        add_executable(ApfsAccess.ApfsRwEngine.VolumeResizeGeometryTests tests/VolumeResizeGeometryTests.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.VolumeResizeGeometryTests PRIVATE
            ApfsAccess.ApfsRwEngine bcrypt user32)
        target_compile_features(ApfsAccess.ApfsRwEngine.VolumeResizeGeometryTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.VolumeResizeGeometryTests PRIVATE /utf-8 /bigobj)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.VolumeResizeGeometryTests COMMAND ${CMAKE_COMMAND}
            "-DTEST_EXE=$<TARGET_FILE:ApfsAccess.ApfsRwEngine.VolumeResizeGeometryTests>"
            "-DEVIDENCE_ROOT=${CMAKE_CURRENT_BINARY_DIR}/volume-image-evidence/VolumeResizeGeometry"
            "-DTEST_ARGUMENTS=--all"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/RunFreshNativeFileTest.cmake")
        set_tests_properties(ApfsAccess.ApfsRwEngine.VolumeResizeGeometryTests PROPERTIES
            TIMEOUT 270 RUN_SERIAL TRUE)
        add_executable(ApfsAccess.ApfsRwEngine.VolumeFormatGeometryTests tests/VolumeFormatGeometryTests.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.VolumeFormatGeometryTests PRIVATE
            ApfsAccess.ApfsRwEngine bcrypt user32)
        target_compile_features(ApfsAccess.ApfsRwEngine.VolumeFormatGeometryTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.VolumeFormatGeometryTests PRIVATE /utf-8 /bigobj)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.VolumeFormatGeometryTests COMMAND ${CMAKE_COMMAND}
            "-DTEST_EXE=$<TARGET_FILE:ApfsAccess.ApfsRwEngine.VolumeFormatGeometryTests>"
            "-DEVIDENCE_ROOT=${CMAKE_CURRENT_BINARY_DIR}/volume-image-evidence/VolumeFormatGeometry"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/RunFreshNativeFileTest.cmake")
        set_tests_properties(ApfsAccess.ApfsRwEngine.VolumeFormatGeometryTests PROPERTIES
            TIMEOUT 120 RUN_SERIAL TRUE)
        add_executable(ApfsAccess.ApfsRwEngine.VolumeFormatStreamedTests tests/VolumeFormatStreamedTests.cpp)
        target_link_libraries(ApfsAccess.ApfsRwEngine.VolumeFormatStreamedTests PRIVATE
            ApfsAccess.ApfsRwEngine bcrypt user32)
        target_compile_features(ApfsAccess.ApfsRwEngine.VolumeFormatStreamedTests PRIVATE cxx_std_20)
        if(MSVC)
            target_compile_options(ApfsAccess.ApfsRwEngine.VolumeFormatStreamedTests PRIVATE /utf-8 /bigobj)
        endif()
        add_test(NAME ApfsAccess.ApfsRwEngine.VolumeFormatStreamedTests COMMAND ${CMAKE_COMMAND}
            "-DTEST_EXE=$<TARGET_FILE:ApfsAccess.ApfsRwEngine.VolumeFormatStreamedTests>"
            "-DEVIDENCE_ROOT=${CMAKE_CURRENT_BINARY_DIR}/volume-image-evidence/VolumeFormatStreamed"
            "-DTEST_TIMEOUT=1200"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/RunFreshNativeFileTest.cmake")
        set_tests_properties(ApfsAccess.ApfsRwEngine.VolumeFormatStreamedTests PROPERTIES
            TIMEOUT 1260 RUN_SERIAL TRUE)
        foreach(family VolumeEraseStreamed VolumeResizeStreamed VolumeResizeRelocation VolumeResizeRelocationKeeper VolumeResizeRelocationHistory VolumeResizeFragmentedTail VolumeResizeSplitBootstrap VolumePhysicalKeeper VolumeKeeperRawAdmission VolumePhysicalWal VolumeResizeZonePolicy VolumeResizeZoneReset VolumePhysicalMetadataOwnership VolumePhysicalDispatch VolumePhysicalResize VolumePhysicalManagement WriteAheadLogEvidenceBudget)
            add_executable(ApfsAccess.ApfsRwEngine.${family}Tests tests/${family}Tests.cpp)
            if(family STREQUAL "VolumeKeeperRawAdmission")
                target_sources(ApfsAccess.ApfsRwEngine.${family}Tests PRIVATE tests/VolumeKeeperRawAdmissionTestBridge.cpp)
            endif()
            if(family STREQUAL "VolumePhysicalManagement")
                target_sources(ApfsAccess.ApfsRwEngine.${family}Tests PRIVATE tools/VolumePhysicalObserve.cpp)
                target_compile_definitions(ApfsAccess.ApfsRwEngine.${family}Tests PRIVATE APFS_VOLUME_PHYSICAL_OBSERVE_TESTING)
            endif()
            target_link_libraries(ApfsAccess.ApfsRwEngine.${family}Tests PRIVATE ApfsAccess.ApfsRwEngine bcrypt user32)
            target_compile_features(ApfsAccess.ApfsRwEngine.${family}Tests PRIVATE cxx_std_20)
            if(MSVC)
                target_compile_options(ApfsAccess.ApfsRwEngine.${family}Tests PRIVATE /utf-8 /bigobj)
            endif()
            add_test(NAME ApfsAccess.ApfsRwEngine.${family}Tests COMMAND ${CMAKE_COMMAND}
                "-DTEST_EXE=$<TARGET_FILE:ApfsAccess.ApfsRwEngine.${family}Tests>"
                "-DEVIDENCE_ROOT=${CMAKE_CURRENT_BINARY_DIR}/volume-image-evidence/${family}"
                "-DTEST_TIMEOUT=1800"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/RunFreshNativeFileTest.cmake")
            set_tests_properties(ApfsAccess.ApfsRwEngine.${family}Tests PROPERTIES TIMEOUT 1860 RUN_SERIAL TRUE)
        endforeach()
        foreach(family VolumeResize VolumeFormat)
            add_executable(ApfsAccess.ApfsRwEngine.${family}Tests tests/${family}Tests.cpp)
            target_link_libraries(ApfsAccess.ApfsRwEngine.${family}Tests PRIVATE ApfsAccess.ApfsRwEngine bcrypt user32)
            target_compile_features(ApfsAccess.ApfsRwEngine.${family}Tests PRIVATE cxx_std_20)
            if(MSVC)
                target_compile_options(ApfsAccess.ApfsRwEngine.${family}Tests PRIVATE /utf-8 /bigobj)
            endif()
            add_test(NAME ApfsAccess.ApfsRwEngine.${family}Tests COMMAND ${CMAKE_COMMAND}
                "-DTEST_EXE=$<TARGET_FILE:ApfsAccess.ApfsRwEngine.${family}Tests>"
                "-DEVIDENCE_ROOT=${CMAKE_CURRENT_BINARY_DIR}/volume-image-evidence/${family}"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/RunFreshVolumeManagementTest.cmake")
            set_tests_properties(ApfsAccess.ApfsRwEngine.${family}Tests PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
        endforeach()
    endif()
endif()

# Offline ordinary-image management; keep the normal build and publish default aligned.
if(WIN32 AND BUILD_TESTING)
    add_executable(VolumePhysicalInstanceTests tests/VolumePhysicalInstanceTests.cpp)
    target_link_libraries(VolumePhysicalInstanceTests PRIVATE ole32 oleaut32 wbemuuid)
    target_compile_features(VolumePhysicalInstanceTests PRIVATE cxx_std_20)
    add_test(NAME VolumePhysicalInstanceTests COMMAND VolumePhysicalInstanceTests)
endif()

option(APFSACCESS_BUILD_PRIVATE_VOLUME_QUOTA_TOOL "Build offline image quota/reserve command" ON)
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
