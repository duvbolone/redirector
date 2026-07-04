#include <iostream>
#include <string>
#include <fstream>
#include <chrono>
#include <sqlite3.h>
#include <unordered_map>
#include <signal.h>
#include <sstream>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"

#include "log.h"
#include "utils.h"
#include "rid.h"

sqlite3 *db;

void usage(char *exec) {
    std::cout << "Usage: " << exec << " [--port=PORT] [--host=HOST] [--ssl=true|false] [--cert=CERT] [--key=KEY] [--db=SQLITE_DATABASE] [--nfu=NF_URL]" << std::endl;
}

void fill_umap(std::unordered_map<std::string, std::string>*map, int argc, char **argv) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg.length() <= 2) {
            continue;
        }
        if (arg[0] != '-' && arg[1] != '-') {
            continue;
        }

        std::string name;
        std::string value;
        bool reading_value = false;
        for (long unsigned int j = 2; j < arg.length(); j++) {
            if (arg[j] == '=') {
                reading_value = true;
                continue;
            }

            if (reading_value)
                value += arg[j];
            else
                name += arg[j];
        }
        
        (*map)[name] = value;
    }
}

void handle_sigint(int) {
    std::cout << "SIGINT caught, exiting..." << std::endl;
    sqlite3_close(db);
    std::cout << "Database closed" << std::endl;

    std::cout << "Bye!" << std::endl;

    exit(1);
}

int main(int argc, char **argv) {
    signal(SIGINT, handle_sigint);

    if (argc > 1) {
        if (!strcmp(argv[1], "-h")) {
            usage(argv[0]);
            return 0;
        }
    }
    std::cout << "Welcome to redirector, use -h if needed" << std::endl;


    std::unordered_map<std::string, std::string> args;
    
    fill_umap(&args, argc, argv);

    std::string host = args["host"];
    if (host.empty())
        host = "localhost";
    int port = std::atoi(args["port"].c_str());
    if (port == 0)
        port = 9000;

    const bool ssl = args["ssl"] == "true";
    std::string cert = args["cert"];
    if (cert.empty())
        cert = "./cert.pem";
    std::string key  = args["key"];
    if (key.empty())
        key = "./key.pem";

    if (ssl) {
        if (!std::ifstream(cert).good() || !std::ifstream(key).good())
            error("Certificate or key not found!", true);
    }

    if (port <= 1024)
        warn("The port you're trying to use might need root.");

    std::string not_found_url = args["nfu"];
    if (not_found_url.empty()) {
        not_found_url = "https://proximus.be";
    }

    std::string db_s = args["db"];
    if (db_s.empty()) {
        db_s = "main.db";
    }
    
    if (!std::ifstream(db_s).good())
        warn(db_s + " does not exist. The database will be created.");

    std::cout << "Loading database" << std::endl;
    sqlite3 *db;
    if (sqlite3_open(db_s.c_str(), &db))
        error("Couldn't open the SQLite database.", true);

    const char *table_sql = "CREATE TABLE IF NOT EXISTS redirects("
                            "id INTEGER PRIMARY KEY, "
                            "created_at TEXT NOT NULL, "
                            "needs_auth BOOLEAN NOT NULL, "
                            "expires TEXT NOT NULL, "
                            "rid TEXT NOT NULL UNIQUE, "
                            "target TEXT NOT NULL);";

    char *sql_error;
    if (sqlite3_exec(db, table_sql, NULL, 0, &sql_error)) {
        error("Couldn't create the necessary tables in the database.");
        sqlite3_close(db);
        return 1;
    }

    std::string token = args["token"];
    if (token.empty())
        warn("Token is empty, authorisation is now trivial!");

    httplib::Server svr;

    if (ssl)
        httplib::SSLServer svr(cert.c_str(), key.c_str());


    svr.Get("/cleanup", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req, token)) {
            res.status = 401;
            res.set_content("Unauthorized - 401", "text/plain");
            return;
        }

        const char *del_sql = "DELETE FROM redirects WHERE CAST(expires AS INTEGER) < strftime('%s', 'now') AND expires <> '0';";
        if (sqlite3_exec(db, del_sql, NULL, 0, nullptr)) {
            res.status = 500;
            res.set_content("Failed :(", "text/plain");
        } else {
            res.set_content("Success!", "text/plain");
        }
    });

    // svr.Get("/list-rids", [&](const httplib::Request &req, httplib::Response &res) {list_rids(db, req, res, token);});

    svr.Get("/:rid", [&](const httplib::Request& req, httplib::Response& res) {get_rid(db, req, res, token, not_found_url);});

    svr.Post("/", [&](const httplib::Request &req, httplib::Response &res) {set_rid(db, req, res, token);});

    if (ssl) {
        std::cout << "Listening on https://" << host << ":" << port << std::endl;
        std::cout << "- Using OpenSSL :-)" << std::endl;
    } else {
        std::cout << "Listening on http://" << host << ":" << port << std::endl;
    }
    svr.listen(args["host"], port);

    return 0;
}
