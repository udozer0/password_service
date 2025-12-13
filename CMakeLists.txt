cmake_minimum_required(VERSION 3.20)
project(password_service LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

find_package(cppgraphqlgen CONFIG REQUIRED)

add_executable(password_service
    src/main.cpp
    src/graphql/PasswordSchema.cpp
    src/graphql/GeneratedPasswordObject.cpp
    src/graphql/QueryObject.cpp
    src/graphql/MutationObject.cpp
    src/graphql/PasswordGraphQL.cpp
)

target_include_directories(password_service
    PRIVATE
        ${SODIUM_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/include/graphql
)


target_link_libraries(password_service
    PRIVATE
        ${SODIUM_LIBRARIES}
        graphqlservice
        graphqlpeg
        graphqlresponse
        graphqljson
        pthread
)
