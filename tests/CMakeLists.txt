find_package(Catch2 3 REQUIRED)

link_libraries(Catch2::Catch2WithMain modifyexports)

add_executable(modift_test modify_test.cc)
target_link_libraries(modift_test PRIVATE user32)

include(CTest)
include(Catch)
catch_discover_tests(modift_test)