cmake_minimum_required(VERSION 3.20)
project(ApfsAccessApfsRwEngine LANGUAGES CXX)
include(CTest)

add_library(ApfsAccess.ApfsRwEngine STATIC
    src/ApfsObjectMapStore.cpp
    src/ApfsSpacemanStore.cpp
    src/ApfsVolumeTreeStore.cpp
    src/BtreeMutationCodec.cpp
    src/BlockDevice.cpp
    src/MetadataStore.cpp
    src/NativeApfsReader.cpp
    src/TransactionManager.cpp
)

target_include_directories(ApfsAccess.ApfsRwEngine
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(ApfsAccess.ApfsRwEngine PUBLIC cxx_std_20)

if(MSVC)
    target_compile_options(ApfsAccess.ApfsRwEngine PRIVATE /W4 /permissive-)
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

    target_compile_features(ApfsAccess.ApfsRwEngine.Tests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.CanonicalStoreTests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.ConformanceTests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.ConformanceFaultTests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.FaultTests PRIVATE cxx_std_20)
    target_compile_features(ApfsAccess.ApfsRwEngine.TransactionTests PRIVATE cxx_std_20)

    if(MSVC)
        target_compile_options(ApfsAccess.ApfsRwEngine.Tests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.CanonicalStoreTests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.ConformanceTests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.ConformanceFaultTests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.FaultTests PRIVATE /W4 /permissive-)
        target_compile_options(ApfsAccess.ApfsRwEngine.TransactionTests PRIVATE /W4 /permissive-)
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
endif()
