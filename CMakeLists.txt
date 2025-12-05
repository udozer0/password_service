cmake_minimum_required(VERSION 3.10)
project(password_service LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM libsodium REQUIRED)

# --- Простая загрузка single-header файлов в папку в build ---
set(THIRD_PARTY_DIR ${CMAKE_CURRENT_BINARY_DIR}/third_party)
file(MAKE_DIRECTORY ${THIRD_PARTY_DIR})

# httplib.h
set(HTTPLIB_URL "https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h")
set(HTTPLIB_FILE "${THIRD_PARTY_DIR}/httplib.h")
if(NOT EXISTS "${HTTPLIB_FILE}")
  message(STATUS "Downloading httplib.h to ${HTTPLIB_FILE}")
  file(DOWNLOAD "${HTTPLIB_URL}" "${HTTPLIB_FILE}" SHOW_PROGRESS STATUS dl_status)
  list(GET dl_status 0 dl_code)
  if(NOT dl_code EQUAL 0)
    message(FATAL_ERROR "Failed to download httplib.h (status: ${dl_status})")
  endif()
endif()

# json.hpp
set(JSON_URL "https://raw.githubusercontent.com/nlohmann/json/develop/single_include/nlohmann/json.hpp")
set(JSON_FILE "${THIRD_PARTY_DIR}/json.hpp")
if(NOT EXISTS "${JSON_FILE}")
  message(STATUS "Downloading json.hpp to ${JSON_FILE}")
  file(DOWNLOAD "${JSON_URL}" "${JSON_FILE}" SHOW_PROGRESS STATUS dl_status2)
  list(GET dl_status2 0 dl_code2)
  if(NOT dl_code2 EQUAL 0)
    message(FATAL_ERROR "Failed to download json.hpp (status: ${dl_status2})")
  endif()
endif()

# add include dir
include_directories(${THIRD_PARTY_DIR})
# -------------------------------------------------------------------

include_directories(${SODIUM_INCLUDE_DIRS})
link_directories(${SODIUM_LIBRARY_DIRS})

add_executable(password_service src/main.cpp)

target_link_libraries(password_service ${SODIUM_LIBRARIES})
