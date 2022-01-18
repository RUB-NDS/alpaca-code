cmake_minimum_required(VERSION 3.0.0)
project(alpaca-gnutls VERSION 0.1.0)


set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(CMakeToolsHelpers OPTIONAL)
include(FeatureSummary)

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CheckCXXSourceCompiles)



add_subdirectory(client)
add_subdirectory(server)
