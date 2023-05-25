cmake_minimum_required(VERSION 3.0.0)
project(modifyexports VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 23)

add_library(modifyexports ModifyExports.cpp ModifyExprots.hpp)

add_subdirectory(tests)