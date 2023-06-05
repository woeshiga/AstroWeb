#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sqlite3.h>
#include <nlohmann/json.hpp>
#include <chrono>
#include <time.h>
#include <stdio.h>
#include <ctime>
#include <random>
#include <cstdio>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>

const int BACKLOG = 5;

std::string GetParameterValue(const std::string& key, int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string argument = argv[i];
        if (argument.find(key + "=") == 0) {
            return argument.substr(key.length() + 1);
        }
    }
    return "/usr/bin/local/config.ini";
}

std::string sha512(const std::string& password) {
    unsigned char digest[SHA512_DIGEST_LENGTH];
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    md = EVP_sha512();
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, password.c_str(), password.length());
    EVP_DigestFinal_ex(mdctx, digest, NULL);
    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    return ss.str();
}


std::map<std::string, std::string> open_ini_file(std::string cfg_path) {
    std::ifstream file(cfg_path);

    std::map<std::string, std::string> config;

    if (!file.is_open())
    {
        std::cout << "Failed to open file" << std::endl;
        return (config);
    }

    std::string line;
    while (std::getline(file, line))
    {
        // Ignore comments and empty strings
        if (line.empty() || line[0] == ';' || line[0] == '#')
            continue;
        // DB string on key and value
        auto pos = line.find('=');
        if (pos != std::string::npos)
        {
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);

            config[key] = value;
        }
    }

    file.close();

    return(config);
}

// Request parser function
std::map<std::string, std::string> parseQueryString(const std::string& queryString) {
    std::map<std::string, std::string> params;
    std::stringstream ss(queryString);
    std::string item;

    // Get path
    if (std::getline(ss, item, ' ')) {
        params["path"] = item;
    }

    // Get params
    while (std::getline(ss, item, '&')) {
        std::stringstream ss2(item);
        std::string key, value;
        if (std::getline(ss2, key, '=') && std::getline(ss2, value)) {
            params[key] = value;
        }
    }

    return params;
}

std::string get_token()
{
    const std::string alphanum = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<> dist(0, alphanum.size() - 1);
    std::string token;
    for (int i = 0; i < 50; i++)
        token += alphanum[dist(rng)];
    return token;
}

sqlite3* db = 0;

using Record = std::vector<std::string>;
using Records = std::vector<Record>;

int select_callback(void* p_data, int num_fields, char** p_fields, char** p_col_names)
{
    Records* records = static_cast<Records*>(p_data);
    try {
        records->emplace_back(p_fields, p_fields + num_fields);
    }
    catch (...) {
        // abort select on failure, don't let exception propogate thru sqlite3 call-stack
        return 1;
    }
    return 0;
}

static int callback(void* data, int argc, char** argv, char** azColName) {
    int i;
    fprintf(stderr, "%s: ", (const char*)data);

    for (i = 0; i < argc; i++) {
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }

    printf("\n");
    return 0;
}

Records select_stmt(const char* stmt)
{
    Records records;
    char* errmsg;
    int ret = sqlite3_exec(db, stmt, select_callback, &records, &errmsg);
    if (ret != SQLITE_OK) {
        std::cerr << "Error in select statement " << stmt << "[" << errmsg << "]\n";
    }
    else {
        std::cerr << records.size() << " records returned.\n";
    }

    return records;
}

void sql_stmt(const char* stmt)
{
    char* errmsg;
    int ret = sqlite3_exec(db, stmt, 0, 0, &errmsg);
    if (ret != SQLITE_OK) {
        std::cerr << "Error in select statement " << stmt << "[" << errmsg << "]\n";
    }
}

const char* SQL = "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, login VARCHAR(255) NOT NULL, password VARCHAR(255) NOT NULL, status INT DEFAULT 3, session_token VARCHAR(255) DEFAULT '0', session_time TEXT DEFAULT '0');";


void handleRequest(SSL* ssl, int clientSocket, char* err_db, std::map<std::string, std::string> cfg) {
    char buffer[4096];
    ssize_t bytesRead = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    std::stringstream resp;
    std::stringstream response_body;
    if (bytesRead > 0) {
        buffer[bytesRead] = '\0';

        std::string request(buffer);
        size_t pos = request.find_first_of("?");
        std::string path = request.substr(0, pos);
        std::string queryString = request.substr(pos + 1);
        std::map<std::string, std::string> params = parseQueryString(queryString);

        // Generate response
        nlohmann::json response;
        if (!params.empty() && path == cfg["HOST"] + ':' + cfg["PORT"] + cfg["REGISTER_PATH"]) {
            std::string query = ("SELECT * FROM users WHERE login = '" + params["login"] + "';").data();
            SQL = query.c_str();

            if (sqlite3_open(cfg["DB"].c_str(), &db))
                fprintf(stderr, "Error of open/create DB: %s\n", sqlite3_errmsg(db));

            Records records = select_stmt(SQL);
            if (records.size() == 0)
            {

                std::string query = ("INSERT INTO users (login, password) VALUES ('" + params["login"] + "', '" + sha512(params["password"]) + "');").data();
                SQL = query.c_str();
                if (sqlite3_open(cfg["DB"].c_str(), &db))
                    fprintf(stderr, "Error of open/create DB: %s\n", sqlite3_errmsg(db));
                else if (sqlite3_exec(db, SQL, 0, 0, &err_db))
                {
                    fprintf(stderr, "SQL error: %sn", err_db);
                    sqlite3_free(err_db);
                }
                response["status"] = "OK";
                response["code"] = 200;
                response["message"] = "User created";
                response_body << response;
            }
            else
            {
                nlohmann::json response;
                response["status"] = "ERROR";
                response["code"] = 500;
                response["error"] = "User is already exists!";
                response_body << response;
            }

            sqlite3_close(db);
        }
        else if (!params.empty() && path == cfg["HOST"] + ':' + cfg["PORT"] + cfg["LOGIN_PATH"]) {
            const char* data = "Callback function called";
            std::string query = ("SELECT login, password, status, session_token FROM users WHERE login = '" + params["login"] + "' AND password = '" + sha512(params["password"]) + "';").data();
            SQL = query.c_str();
            if (sqlite3_open(cfg["DB"].c_str(), &db))
                fprintf(stderr, "Open/create DB error: %s\n", sqlite3_errmsg(db));
            Records records = select_stmt(SQL);

            if (records.size() >= 1)
            {
                Record record = records[0];
                std::string token = get_token();

                const auto p1 = std::chrono::system_clock::now();
                int token_time = std::chrono::duration_cast<std::chrono::seconds>(p1.time_since_epoch()).count();

                std::string query = ("UPDATE users SET session_token = '" + token + "', session_time = '" + std::to_string(token_time) + "' WHERE login = '" + params["login"] + "';").data();
                SQL = query.c_str();

                if (sqlite3_exec(db, SQL, 0, 0, &err_db))
                {
                    fprintf(stderr, "SQL error: %sn", err_db);
                    sqlite3_free(err_db);
                }

                nlohmann::json user;

                user["login"] = record[0];
                user["status"] = record[2];
                user["token"] = token;

                response["status"] = "OK";
                response["code"] = 200;
                response["data"] = user;

                response_body << response;
            }
            else
            {
                nlohmann::json response;

                response["status"] = "ERROR";
                response["code"] = 500;
                response["error"] = "Incorrected password or login!";

                response_body << response;
            }
            sqlite3_close(db);
        }
        else if (!params.empty() && path == cfg["HOST"] + ':' + cfg["PORT"] + cfg["LOGOUT_PATH"]) {
            params["token"].erase(std::remove(params["token"].begin(), params["token"].end(), ' '), params["token"].end());
            params["token"].erase(std::remove(params["token"].begin(), params["token"].end(), '\r'), params["token"].end());
            std::string query = ("SELECT login, status, session_time FROM users WHERE session_token = '" + params["token"] + "';").data();
            SQL = query.c_str();
            if (sqlite3_open(cfg["DB"].c_str(), &db))
                fprintf(stderr, "Open/create DB error: %s\n", sqlite3_errmsg(db));
            Records records = select_stmt(SQL);
            sqlite3_close(db);
            if (records.size() > 0)
            {
                Record record = records[0];
                std::time_t t = std::time(nullptr);
                const auto p1 = std::chrono::system_clock::now();
                int now = std::chrono::duration_cast<std::chrono::seconds>(p1.time_since_epoch()).count();

                std::string query = ("UPDATE users SET session_token = '0', session_time = '0' WHERE session_token = " + params["token"] + "';").data();
                SQL = query.c_str();
                if (sqlite3_open(cfg["DB"].c_str(), &db))
                    fprintf(stderr, "Open/create DB error: %s\n", sqlite3_errmsg(db));

                if (sqlite3_exec(db, SQL, 0, 0, &err_db))
                {
                    fprintf(stderr, "SQL error: %sn", err_db);
                    sqlite3_free(err_db);
                }

                sqlite3_close(db);

                response["status"] = "OK";
                response["code"] = 200;
                response["message"] = "Logout Success!";

                response_body << response;

            }
            else
            {
                response["status"] = "ERROR";
                response["code"] = 500;
                response["error"] = "Not Auth!";

                response_body << response;
            }
        }
        else if (!params.empty() && path == cfg["HOST"] + ':' + cfg["PORT"] + cfg["GET_USER_PATH"]) {
            params["token"].erase(std::remove(params["token"].begin(), params["token"].end(), ' '), params["token"].end());
            params["token"].erase(std::remove(params["token"].begin(), params["token"].end(), '\r'), params["token"].end());
            std::string query = ("SELECT login, status, session_time FROM users WHERE session_token = '" + params["token"] + "';").data();
            SQL = query.c_str();
            if (sqlite3_open(cfg["DB"].c_str(), &db))
                fprintf(stderr, "Open/create DB error: %s\n", sqlite3_errmsg(db));
            // execute SQL
            Records records = select_stmt(SQL);
            sqlite3_close(db);
            if (records.size() > 0)
            {
                Record record = records[0];
                std::time_t t = std::time(nullptr);
                const auto p1 = std::chrono::system_clock::now();
                int now = std::chrono::duration_cast<std::chrono::seconds>(p1.time_since_epoch()).count();
                if (now - atoi(record[2].c_str()) >= std::stoi(cfg["TOKEN_LIFETIME"]))
                {
                    std::string query = ("UPDATE users SET session_token = '0', session_time = '0' WHERE login = '" + record[0] + "'").data();
                    SQL = query.c_str();
                    // open connection
                    if (sqlite3_open(cfg["DB"].c_str(), &db))
                        fprintf(stderr, "Open/create DB error: %s\n", sqlite3_errmsg(db));
                    // execute SQL
                    else if (sqlite3_exec(db, SQL, 0, 0, &err_db))
                    {
                        fprintf(stderr, "SQL error: %sn", err_db);
                        sqlite3_free(err_db);
                    }
                    // close connection
                    sqlite3_close(db);

                    response["status"] = "ERROR";
                    response["code"] = 501;
                    response["error"] = "Session is end!";

                    response_body << response;
                }
                else
                {
                    nlohmann::json user;

                    user["login"] = record[0];

                    response["status"] = "OK";
                    response["code"] = 200;
                    response["data"] = user;

                    response_body << response;
                }

            }
            else
            {

                response["status"] = "ERROR";
                response["code"] = 500;
                response["error"] = "Not Auth!";

                response_body << response;
            }
        }
        else if (!params.empty() && path == cfg["HOST"] + ':' + cfg["PORT"] + cfg["GET_USERS_PATH"]) {
            params["token"].erase(std::remove(params["token"].begin(), params["token"].end(), ' '), params["token"].end());
            params["token"].erase(std::remove(params["token"].begin(), params["token"].end(), '\r'), params["token"].end());
            std::string query = ("SELECT login, status, session_time FROM users WHERE session_token = '" + params["token"] + "';").data();
            SQL = query.c_str();
            if (sqlite3_open(cfg["DB"].c_str(), &db))
                fprintf(stderr, "Open/create DB error: %s\n", sqlite3_errmsg(db));
            Records records = select_stmt(SQL);
            sqlite3_close(db);
            if (records.size() > 0)
            {
                Record record = records[0];
                std::time_t t = std::time(nullptr);
                const auto p1 = std::chrono::system_clock::now();
                int now = std::chrono::duration_cast<std::chrono::seconds>(p1.time_since_epoch()).count();
                if (now - atoi(record[2].c_str()) >= std::stoi(cfg["TOKEN_LIFETIME"]))
                {
                    std::string query = ("UPDATE users SET session_token = '0', session_time = '0' WHERE login = '" + record[0] + "'").data();
                    SQL = query.c_str();
                    // open connection
                    if (sqlite3_open(cfg["DB"].c_str(), &db))
                        fprintf(stderr, "Open/create DB error: %s\n", sqlite3_errmsg(db));
                    // execute SQL
                    else if (sqlite3_exec(db, SQL, 0, 0, &err_db))
                    {
                        fprintf(stderr, "SQL error: %sn", err_db);
                        sqlite3_free(err_db);
                    }
                    // close connection
                    sqlite3_close(db);

                    response["status"] = "ERROR";
                    response["code"] = 501;
                    response["error"] = "Session is end!";

                    response_body << response;
                }
                else
                {
                    if (std::stoi(record[1]) == 0)
                    {
                        query = "SELECT * FROM users";
                        SQL = query.c_str();
                        if (sqlite3_open(cfg["DB"].c_str(), &db))
                            fprintf(stderr, "Open/create DB error: %s\n", sqlite3_errmsg(db));
                        records = select_stmt(SQL);
                        sqlite3_close(db);

                        std::vector<nlohmann::json> users;

                        response["status"] = "OK";
                        response["code"] = 200;

                        for (int i = 0; i < records.size(); i++)
                        {
                            nlohmann::json user;

                            user["id"] = records[i][0];
                            user["login"] = records[i][1];
                            user["status"] = records[i][3];
                            user["token"] = records[i][4];
                            user["time"] = records[i][5];

                            users.push_back(user);
                        }

                        response["data"] = users;
                        response_body << response;
                    }
                    else
                    {

                        response["status"] = "ERROR";
                        response["code"] = 502;
                        response["error"] = "Acces denied!";

                        response_body << response;
                    }
                }

            }
            else
            {
                response["status"] = "ERROR";
                response["code"] = 500;
                response["error"] = "Not Auth!";

                response_body << response;
            }
        }
        else if (!params.empty() && path == cfg["HOST"] + ':' + cfg["PORT"] + cfg["DELETE_USER_PATH"]) {
            params["token"].erase(std::remove(params["token"].begin(), params["token"].end(), ' '), params["token"].end());
            params["token"].erase(std::remove(params["token"].begin(), params["token"].end(), '\r'), params["token"].end());
            std::string query = ("SELECT login, status, session_time FROM users WHERE session_token = '" + params["token"] + "';").data();
            SQL = query.c_str();
            if (sqlite3_open(cfg["DB"].c_str(), &db))
                fprintf(stderr, "Open/create DB error: %s\n", sqlite3_errmsg(db));
            Records records = select_stmt(SQL);
            sqlite3_close(db);
            if (records.size() > 0)
            {
                Record record = records[0];
                std::time_t t = std::time(nullptr);
                const auto p1 = std::chrono::system_clock::now();
                int now = std::chrono::duration_cast<std::chrono::seconds>(p1.time_since_epoch()).count();
                if (now - atoi(record[2].c_str()) >= std::stoi(cfg["TOKEN_LIFETIME"]))
                {
                    std::string query = ("UPDATE users SET session_token = '0', session_time = '0' WHERE login = '" + record[0] + "'").data();
                    SQL = query.c_str();
                    // open connection
                    if (sqlite3_open(cfg["DB"].c_str(), &db))
                        fprintf(stderr, "Open/create DB error: %s\n", sqlite3_errmsg(db));
                    // execute SQL
                    else if (sqlite3_exec(db, SQL, 0, 0, &err_db))
                    {
                        fprintf(stderr, "SQL error: %sn", err_db);
                        sqlite3_free(err_db);
                    }
                    // close connection
                    sqlite3_close(db);

                    response["status"] = "ERROR";
                    response["code"] = 501;
                    response["error"] = "Session is end!";

                    response_body << response;
                }
                else
                {
                    if (std::stoi(record[1]) == 0)
                    {
                        query = "DELETE FROM users WHERE login = '" + params["login"] + "'";
                        SQL = query.c_str();
                        if (sqlite3_open(cfg["DB"].c_str(), &db))
                            fprintf(stderr, "Open/create DB error: %s\n", sqlite3_errmsg(db));
                        records = select_stmt(SQL);
                        sqlite3_close(db);

                        response["status"] = "OK";
                        response["code"] = 200;

                        response["message"] = "User deleted successfully";
                        response_body << response;
                    }
                    else
                    {

                        response["status"] = "ERROR";
                        response["code"] = 502;
                        response["error"] = "Acces denied!";

                        response_body << response;
                    }
                }

            }
            else
            {
                response["status"] = "ERROR";
                response["code"] = 500;
                response["error"] = "Not Auth!";

                response_body << response;
            }
        }
        else if (path == cfg["HOST"] + ':' + cfg["PORT"] + cfg["GET_IMAGE_PATH"]) {
            // Send image
            std::ifstream file(cfg["MEDIA_ROOT"] + cfg["IMAGES_DIR"] + "image.jpg", std::ios::binary | std::ios::ate);
            if (file.is_open()) {
                std::streamsize size = file.tellg();
                file.seekg(0, std::ios::beg);
                std::vector<char> buffer(size);
                if (file.read(buffer.data(), size)) {
                    std::string response = "HTTP/1.1 200 OK\nContent-Type: image/jpg\nAccess-Control-Allow-Origin: *\nContent-Length: " + std::to_string(size) + "\n\n";
                    write(clientSocket, response.c_str(), response.length());
                    write(clientSocket, buffer.data(), size);
                }
                file.close();
            }
        }
        resp << "HTTP/1.1 200 OK\r\n"
            << "Version: HTTP/1.1\r\n"
            << "Access-Control-Allow-Origin: *\r\n"
            << "Access-Control-Allow-Headers: *\r\n"
            << "Content-Type: application/json\r\n"
            << "Content-Length: " << response_body.str().length()
            << "\r\n\r\n"
            << response_body.str();
        write(clientSocket, resp.str().c_str(), resp.str().length());
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(clientSocket);
    }
    else
    {
        std::cerr << "Failed to read data from SSL connection!" << std::endl;
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(clientSocket);
        return;
    }
}

int main(int argc, char* argv[]) {

    sqlite3_stmt* stmt;
    char* err_db = 0;

    std::string cfg_path = GetParameterValue("-DCONFIG_FILE_PATH", argc, argv);

    std::map<std::string, std::string> cfg = open_ini_file(cfg_path);

    SSL_CTX* sslContext = SSL_CTX_new(SSLv23_server_method());
    if (!sslContext) {
        std::cerr << "Failed to create SSL context!" << std::endl;
        return 1;
    }

    // Set sert and key paths
    if (SSL_CTX_use_certificate_file(sslContext, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Failed to load server certificate!" << std::endl;
        SSL_CTX_free(sslContext);
        return 1;
    }

    if (SSL_CTX_use_PrivateKey_file(sslContext, "server.key", SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Failed to load server private key!" << std::endl;
        SSL_CTX_free(sslContext);
        return 1;
    }

    //SHA512 sha512;

    // Open connection
    if (sqlite3_open(cfg["DB"].c_str(), &db))
        fprintf(stderr, "Open/create DB error: %s\n", sqlite3_errmsg(db));
    // execute SQL
    else if (sqlite3_exec(db, SQL, 0, 0, &err_db))
    {
        fprintf(stderr, "SQL error: %sn", err_db);
        sqlite3_free(err_db);
    }
    // close connection
    sqlite3_close(db);


    int serverSocket, clientSocket;
    struct sockaddr_in serverAddress {}, clientAddress{};
    socklen_t clientLength;

    // Create socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        std::cerr << "Socket create error!" << std::endl;
        return 1;
    }

    // Bind socket to IP-address and port
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    serverAddress.sin_port = htons(std::stoi(cfg["PORT"]));
    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        std::cerr << "Socket binding error!" << std::endl;
        return 1;
    }

    // Listening connections
    if (listen(serverSocket, BACKLOG) < 0) {
        std::cerr << "Socket listening error!" << std::endl;
        return 1;
    }

    std::cout << "Server is running. Waiting for connections..." << std::endl;

    while (true) {
        clientLength = sizeof(clientAddress);
        // Accept connect
        clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientLength);
        SSL* ssl = SSL_new(sslContext);
        if (!ssl) {
            std::cerr << "Failed to create SSL structure!" << std::endl;
            close(clientSocket);
            return 1;
        }

        if (SSL_set_fd(ssl, clientSocket) == 0) {
            std::cerr << "Failed to set SSL file descriptor!" << std::endl;
            SSL_free(ssl);
            close(clientSocket);
            return 1;
        }

        if (SSL_accept(ssl) <= 0) {
            std::cerr << "SSL connection error!" << std::endl;
            SSL_free(ssl);
            close(clientSocket);
            return 1;
        }

        handleRequest(ssl, clientSocket, err_db, cfg);
    }

    close(serverSocket);
    return 0;
}
