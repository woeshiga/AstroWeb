cmake_minimum_required(VERSION 3.0)

project(AstroWeb)

set(CMAKE_CXX_STANDARD 11)

# SQLite
find_package(SQLite3 REQUIRED)
include_directories(${SQLite3_INCLUDE_DIRS})

# nlohmann/json
set(CMAKE_PREFIX_PATH "/usr/include/nlohmann-json_x64-linux")
find_package(nlohmann_json REQUIRED)
include_directories(${nlohmann_json_INCLUDE_DIRS})

# openssl
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

set(SOURCE_FILES AstroWeb.cpp)

add_executable(AstroWeb ${SOURCE_FILES})

target_link_libraries(AstroWeb ${SQLite3_LIBRARIES} ${nlohmann_json_LIBRARIES})
target_link_libraries(AstroWeb ${OPENSSL_LIBRARIES})

add_compile_options(-Wall -Wextra -Wpedantic)


# Запрашиваем значения для конфигурационного файла
set(DB_DEFAULT "main.db" CACHE STRING "Default database")
set(HOST_DEFAULT "http://localhost" CACHE STRING "Default host")
set(PORT_DEFAULT "8080" CACHE STRING "Default port")
set(TOKEN_LIFETIME_DEFAULT "300" CACHE STRING "Default token lifetime")
set(REGISTER_PATH_DEFAULT "/api/auth/register/" CACHE STRING "Default register path")
set(LOGIN_PATH_DEFAULT "/api/auth/login/" CACHE STRING "Default login path")
set(LOGOUT_PATH_DEFAULT "/api/auth/logout/" CACHE STRING "Default logout path")
set(GET_USER_PATH_DEFAULT "/api/users/get_user/" CACHE STRING "Default get user path")
set(GET_USERS_PATH_DEFAULT "/api/users/get_users/" CACHE STRING "Default get users path")
set(DELETE_USER_PATH_DEFAULT "/api/users/delete_user/" CACHE STRING "Default delete user path")

# Получаем путь к config.ini из аргумента командной строки
set(CONFIG_FILE_PATH ${CMAKE_BINARY_DIR} CACHE FILEPATH "Path to config.ini file")

# Получаем путь к фронтенду из агрумента командной строки
set(FRONT_PATH ${CMAKE_BINARY_DIR} CACHE STRING "Path to frontend dir")

# Create config.ini.in
file (WRITE ${FRONT_PATH}/scripts/config.js "const cfg = {DB:\"${DB_DEFAULT}\",HOST:\"${HOST_DEFAULT}\",PORT:\"${PORT_DEFAULT}\",REGISTER_PATH:\"${REGISTER_PATH_DEFAULT}\",LOGIN_PATH:\"${LOGIN_PATH_DEFAULT}\",LOGOUT_PATH:\"${LOGOUT_PATH_DEFAULT}\",GET_USER_PATH:\"${GET_USER_PATH_DEFAULT}\",GET_USERS_PATH:\"${GET_USERS_PATH_DEFAULT}\",DELETE_USER_PATH:\"${DELETE_USER_PATH_DEFAULT}\",MEDIA_ROOT:\"./src/\",IMAGES_DIR:\"images/\"}; if (cfg.PORT!=\"\"){cfg.PORT=\":\"+cfg.PORT;}")
file(WRITE ${CONFIG_FILE_PATH}/config.ini.in "[DataBase]\nDB=${DB_DEFAULT}\n\n[Server]\nHOST=${HOST_DEFAULT}\nPORT=${PORT_DEFAULT}\nTOKEN_LIFETIME=${TOKEN_LIFETIME_DEFAULT}\n\n[API]\nREGISTER_PATH=${REGISTER_PATH_DEFAULT}\nLOGIN_PATH=${LOGIN_PATH_DEFAULT}\nLOGOUT_PATH=${LOGOUT_PATH_DEFAULT}\nGET_USER_PATH=${GET_USER_PATH_DEFAULT}\nGET_USERS_PATH=${GET_USERS_PATH_DEFAULT}\nDELETE_USER_PATH=${DELETE_USER_PATH_DEFAULT}\n\n[Directories]\nMEDIA_ROOT=./src/\nIMAGES_DIR=images/")
configure_file(${CONFIG_FILE_PATH}/config.ini.in ${CMAKE_CURRENT_BINARY_DIR}/config.ini.in COPYONLY)

# Создаем конфигурационный файл
if (CONFIG_FILE_PATH)
  configure_file(
    "${CMAKE_CURRENT_BINARY_DIR}/config.ini.in"
    "${CONFIG_FILE_PATH}/config.ini"
    COPYONLY
  )
else()
  configure_file(
    "${CMAKE_BINARY_DIR}/config.ini.in"
    "${CMAKE_BINARY_DIR}/config.ini"
    COPYONLY
  )
endif()

if(OPENSSL_FOUND)
    message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
    # server.crt and server.key generation
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/server.crt
               ${CMAKE_CURRENT_BINARY_DIR}/server.key
        COMMAND openssl genpkey -algorithm RSA -out ${CMAKE_CURRENT_BINARY_DIR}/server.key
        COMMAND openssl req -new -key ${CMAKE_CURRENT_BINARY_DIR}/server.key -out ${CMAKE_CURRENT_BINARY_DIR}/server.csr
        COMMAND openssl x509 -req -in ${CMAKE_CURRENT_BINARY_DIR}/server.csr -signkey ${CMAKE_CURRENT_BINARY_DIR}/server.key -out ${CMAKE_CURRENT_BINARY_DIR}/server.crt
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating SSL certificate and key"
    )

    # Adding generation files to target
    add_custom_target(ssl_certificate DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/server.crt ${CMAKE_CURRENT_BINARY_DIR}/server.key)


    add_dependencies(AstroWeb ssl_certificate)
else()
    message(FATAL_ERROR "OpenSSL not found")
endif()

set(CMAKE_EXE_LINKER_FLAGS "-static-libstdc++ -static-libgcc")

set_target_properties(AstroWeb PROPERTIES OUTPUT_NAME "AstroWeb")
