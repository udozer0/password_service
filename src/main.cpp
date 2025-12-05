// main.cpp
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <filesystem>
#include <sstream>

#include "httplib.h"           // third_party/httplib.h
#include "json.hpp"            // third_party/json.hpp

#include <sodium.h>

using json = nlohmann::json;
namespace fs = std::filesystem;
#if defined(__unix__) || defined(__APPLE__)
  #include <termios.h>
  #include <unistd.h>
#endif

static constexpr const char* DB_FILE = "vault.json";
static constexpr size_t SALT_LEN = crypto_pwhash_SALTBYTES; // 16
static constexpr size_t KEY_LEN = crypto_secretbox_KEYBYTES; // 32
static constexpr size_t NONCE_LEN = crypto_secretbox_NONCEBYTES; // 24

// Base64 helpers (libsodium provides)
std::string b64_encode(const unsigned char* data, size_t len) {
    size_t out_len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    std::string out(out_len, '\0');
    sodium_bin2base64(out.data(), out_len, data, len, sodium_base64_VARIANT_ORIGINAL);
    // remove trailing \0
    if (!out.empty() && out.back() == '\0') out.pop_back();
    return out;
}

std::vector<unsigned char> b64_decode(const std::string &b64) {
    std::vector<unsigned char> out(b64.size()); // overalloc
    size_t out_len;
    if (sodium_base642bin(out.data(), out.size(),
                         b64.c_str(), b64.size(),
                         nullptr, &out_len, nullptr,
                         sodium_base64_VARIANT_ORIGINAL) != 0) {
        throw std::runtime_error("base64 decode failed");
    }
    out.resize(out_len);
    return out;
}

// Derive key from master password and salt
std::vector<unsigned char> derive_key(const std::string &master, const std::vector<unsigned char> &salt) {
    std::vector<unsigned char> key(KEY_LEN);
    if (crypto_pwhash(key.data(), key.size(),
                      master.data(), master.size(),
                      salt.data(),
                      crypto_pwhash_OPSLIMIT_MODERATE,
                      crypto_pwhash_MEMLIMIT_MODERATE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        throw std::runtime_error("crypto_pwhash failed (out of memory?)");
    }
    return key;
}

json load_and_decrypt_db(const std::vector<unsigned char>& key) {
    if (!fs::exists(DB_FILE)) {
        // return empty db
        return json::array();
    }
    std::ifstream f(DB_FILE);
    if (!f) throw std::runtime_error("can't open DB file");
    json packed;
    f >> packed;
    std::string nonce_b64 = packed.at("nonce").get<std::string>();
    std::string data_b64 = packed.at("data").get<std::string>();

    auto nonce = b64_decode(nonce_b64);
    auto data = b64_decode(data_b64);

    std::vector<unsigned char> plain(data.size() - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(plain.data(),
                                   data.data(), data.size(),
                                   nonce.data(), key.data()) != 0) {
        throw std::runtime_error("decryption failed: wrong master password or corrupted DB");
    }
    std::string s((char*)plain.data(), plain.size());
    return json::parse(s);
}

void encrypt_and_save_db(const json& j, const std::vector<unsigned char>& key) {
    std::string s = j.dump();
    std::vector<unsigned char> plain(s.begin(), s.end());
    std::vector<unsigned char> nonce(NONCE_LEN);
    randombytes_buf(nonce.data(), nonce.size());
    std::vector<unsigned char> cipher(plain.size() + crypto_secretbox_MACBYTES);

    crypto_secretbox_easy(cipher.data(), plain.data(), plain.size(), nonce.data(), key.data());

    json packed;
    packed["nonce"] = b64_encode(nonce.data(), nonce.size());
    packed["data"]  = b64_encode(cipher.data(), cipher.size());

    std::ofstream f(DB_FILE, std::ios::trunc);
    if (!f) throw std::runtime_error("can't write DB file");
    f << packed.dump(2);
}

// secure password generator using libsodium random
std::string generate_password(int length, bool up, bool low, bool digits, bool symbols) {
    std::string pool;
    if (low)    pool += "abcdefghijklmnopqrstuvwxyz";
    if (up)     pool += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (digits) pool += "0123456789";
    if (symbols)pool += "!@#$%^&*()-_=+[]{};:,.<>/?";

    if (pool.empty()) pool = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    std::string out;
    out.resize(length);
    std::vector<unsigned char> rnd(length);
    randombytes_buf(rnd.data(), rnd.size());
    for (int i = 0; i < length; ++i) {
        unsigned char r = rnd[i];
        out[i] = pool[r % pool.size()];
    }
    return out;
}

// helper: read master password from stdin without echo (POSIX)
std::string prompt_password(const std::string &prompt) {
#if defined(__unix__) || defined(__APPLE__)
    std::cout << prompt;
    std::cout.flush();

    struct termios oldt;
    if (tcgetattr(STDIN_FILENO, &oldt) != 0) {
        // Не получилось получить атрибуты — fallback на обычный ввод
        std::string pw;
        std::getline(std::cin, pw);
        return pw;
    }

    struct termios newt = oldt;
    newt.c_lflag &= ~ECHO;

    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) {
        // Не получилось выключить echo — fallback
        std::string pw;
        std::getline(std::cin, pw);
        return pw;
    }

    std::string pw;
    std::getline(std::cin, pw);

    // Восстановим старые атрибуты (в любом случае)
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << "\n";
    return pw;
#else
    // Windows или что-то ещё — простой ввод
    std::string pw;
    std::cout << prompt;
    std::getline(std::cin, pw);
    return pw;
#endif
}


int main() {
    if (sodium_init() < 0) {
        std::cerr << "sodium_init failed\n";
        return 1;
    }

    std::cout << "===== Simple Password Service (local) =====\n";
    std::string master = prompt_password("Enter master password: ");

    // If DB exists, read salt from file header; else create new salt and empty DB
    std::vector<unsigned char> salt(SALT_LEN);
    if (fs::exists(DB_FILE)) {
        // read salt from file if exists - but our format doesn't store salt separately.
        // To keep deterministic key derivation across runs, store salt in a separate file.
        // We'll use <DB_FILE>.salt
        std::ifstream sf(std::string(DB_FILE) + ".salt", std::ios::binary);
        if (!sf) {
            std::cerr << "Existing DB found but salt file missing. Aborting.\n";
            return 1;
        }
        sf.read((char*)salt.data(), salt.size());
    } else {
        randombytes_buf(salt.data(), salt.size());
        // save salt
        std::ofstream sf(std::string(DB_FILE) + ".salt", std::ios::binary | std::ios::trunc);
        sf.write((char*)salt.data(), salt.size());
    }

    auto key = derive_key(master, salt);

    // ensure DB exists (decrypt to check or create)
    json db;
    try {
        db = load_and_decrypt_db(key);
    } catch (const std::exception &e) {
        if (!fs::exists(DB_FILE)) {
            db = json::array();
            encrypt_and_save_db(db, key);
        } else {
            std::cerr << "Error opening DB: " << e.what() << "\n";
            return 1;
        }
    }

    httplib::Server svr;

    // Generate password
    svr.Post("/generate", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            auto j = json::parse(req.body);
            int length = j.value("length", 20);
            bool up = j.value("upper", true);
            bool low = j.value("lower", true);
            bool digits = j.value("digits", true);
            bool symbols = j.value("symbols", false);
            if (length < 4) length = 4;
            if (length > 1024) length = 1024;
            std::string pw = generate_password(length, up, low, digits, symbols);
            json out;
            out["password"] = pw;
            res.set_content(out.dump(), "application/json");
        } catch (std::exception &e) {
            res.status = 400;
            res.set_content(json{{"error", e.what()}}.dump(), "application/json");
        }
    });

    // Add entry (name, username, password)
    svr.Post("/add", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            auto j = json::parse(req.body);
            std::string name = j.at("name").get<std::string>();
            std::string username = j.value("username", "");
            std::string password = j.at("password").get<std::string>();

            // load db
            json current = load_and_decrypt_db(key);
            // add
            json entry;
            entry["name"] = name;
            entry["username"] = username;
            entry["password"] = password;
            entry["created"] = std::time(nullptr);
            current.push_back(entry);

            encrypt_and_save_db(current, key);
            res.set_content(json{{"ok", true}}.dump(), "application/json");
        } catch (std::exception &e) {
            res.status = 400;
            res.set_content(json{{"error", e.what()}}.dump(), "application/json");
        }
    });

    // List entries (no passwords)
    svr.Get("/list", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            json current = load_and_decrypt_db(key);
            json out = json::array();
            for (auto &it : current) {
                out.push_back(json{
                    {"name", it.value("name","")},
                    {"username", it.value("username","")},
                    {"created", it.value("created",0)}
                });
            }
            res.set_content(out.dump(2), "application/json");
        } catch (std::exception &e) {
            res.status = 500;
            res.set_content(json{{"error", e.what()}}.dump(), "application/json");
        }
    });

    // Get entry (including password) by name
    svr.Post("/get", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            auto j = json::parse(req.body);
            std::string name = j.at("name").get<std::string>();
            json current = load_and_decrypt_db(key);
            for (auto &it : current) {
                if (it.value("name","") == name) {
                    res.set_content(it.dump(2), "application/json");
                    return;
                }
            }
            res.status = 404;
            res.set_content(json{{"error","not found"}}.dump(), "application/json");
        } catch (std::exception &e) {
            res.status = 400;
            res.set_content(json{{"error", e.what()}}.dump(), "application/json");
        }
    });

    std::cout << "Server listening on http://0.0.0.0:8080\n";
    svr.listen("0.0.0.0", 8080);

    return 0;
}
