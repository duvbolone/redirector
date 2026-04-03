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

#include "json.hpp"
#include "log.h"

using json = nlohmann::json;

#define NOT_FOUND_URL "https://proximus.be"

sqlite3 *db;

void usage(char *exec) {
    std::cout << "Usage: " << exec << " [--port=PORT] [--host=HOST] [--ssl=true|false] [--cert=CERT] [--key=KEY] [--db=SQLITE_DATABASE]" << std::endl;
}

bool is_authenticated(const httplib::Request &req, std::string token) {
    if (!req.has_header("Authorization")) {
        if (req.has_param("token")) {
            return (req.get_param_value("token") == token);
        }
        return false;
    }

    std::string s = "Bearer ";
    s += token;
    
    return s == req.get_header_value("Authorization");
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

    std::string db_s = args["db"];
    
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

    svr.Get("/:rid", [&](const httplib::Request& req, httplib::Response& res) {
        std::string rid = req.path_params.at("rid");
        if (rid.empty()) {
            res.set_redirect(NOT_FOUND_URL);
            return 0;
        }

        // Use std::string here so we leave the size and length calc's to a better programmer.
        std::string get_sql = "SELECT expires,needs_auth,target FROM redirects WHERE rid=?;";
        sqlite3_stmt* stmt;

        if (sqlite3_prepare_v2(db, get_sql.c_str(), get_sql.size() + 1, &stmt, nullptr)) {
            error("Couldn't prepare the statement to get the redirect.");
            return 0;
        }

        if (sqlite3_bind_text(stmt, 1, rid.c_str(), -1, NULL)) {
            error("Couldn't bind the statement to get the redirect.");
            return 0;
        }

        const int step_result = sqlite3_step(stmt);
        if (step_result == SQLITE_DONE) {
            res.set_redirect(NOT_FOUND_URL);
        } else if (step_result == SQLITE_ROW) {
            const unsigned char *expires = sqlite3_column_text(stmt, 0);
            const auto epoch = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count(); 
            const int expires_i = std::atoi(reinterpret_cast<const char*>(expires));
            if (epoch > expires_i) {
                res.set_redirect(NOT_FOUND_URL);

                sqlite3_stmt* d_stmt;
                std::string del_sql = "DELETE FROM redirects WHERE rid=?";
                if (sqlite3_prepare_v2(db, del_sql.c_str(), del_sql.size() + 1, &d_stmt, nullptr)) {
                    error("Couldn't prepare the DELETE statement for an expired rid.");
                }

                if (sqlite3_bind_text(d_stmt, 1, rid.c_str(), -1, NULL)) {
                    error("Couldn't bind for an expired rid.");
                }

                if (sqlite3_step(d_stmt) != SQLITE_DONE) {
                    error("Couldn't step for an expired rid.");
                }

                if (sqlite3_finalize(d_stmt)) {
                    error("Couldn't finalise for an expired rid.");
                }
            } else {
                const int needs_auth = sqlite3_column_int(stmt, 1);
                if (needs_auth == 1 && !is_authenticated(req, token)) {
                    res.set_redirect("https://proximus.be");
                } else {
                    const unsigned char *target = sqlite3_column_text(stmt, 2);
                    res.set_redirect(reinterpret_cast<const char*>(target));
                }
            }
        } else if (step_result) {
            error("Couldn't step while getting the rid.");
            return 0;
        }

        
        if (sqlite3_finalize(stmt)) {
            error("Couldn't finalise after getting the rid.");
            return 0;
        }

        return 0;
    });

    svr.Post("/", [&](const httplib::Request &req, httplib::Response &res) {
        if (!is_authenticated(req, token)) {
            res.status = 401;
            res.set_content("Unauthorized - 401", "text/plain");
            return;
        }
        if (req.body.empty()) {
            res.status = 200;
            res.set_content("No content provided :(", "text/plain");
            return;
        }
        json body;
        try {
            body = json::parse(req.body);
        } catch (...) {
            res.status = 400;
            res.set_content("Not a JSON body :(", "text/plain");
            return;
        }
        if (!body.contains("rid") || !body.contains("target")) {
            res.status = 400;
            res.set_content("Malformed JSON body :(", "text/plain");
            return;
        }

        std::string rid = body["rid"];
        std::string target = body["target"];
        bool needs_auth = false;
        if (body.contains("needs_auth")) {
            needs_auth = body["needs_auth"];
        }

        const auto epoch = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count(); 
        int expires = epoch + 60*60*24;
        if (body.contains("expires")) {
            expires = body["expires"];
        } else if (body.contains("expires_in")) {
            int expires_in = body["expires_in"];
            expires = epoch + expires_in;
        }

        if (expires < epoch) {
            res.status = 400;
            res.set_content("Expires is older than current time.", "text/plain");
            return;
        }
        const int created_at = epoch;

        sqlite3_stmt* stmt;
        std::string ins_sql = "INSERT INTO redirects (created_at, needs_auth, expires, rid, target) VALUES (?, ?, ?, ?, ?)";
        if (sqlite3_prepare_v2(db, ins_sql.c_str(), ins_sql.size() + 1, &stmt, nullptr)) {
            error("Couldn't prepare the INSERT statement for a new rid.");
            res.status = 500;
            res.set_content("SQLite error :(", "text/plain");
            return;
        }
       

        std::string cs= std::to_string(created_at);
        if (sqlite3_bind_text(stmt, 1, cs.c_str(), cs.size(), NULL)) {
            error("Couldn't bind 'created_at' for a new rid.");
            res.status = 500;
            res.set_content("SQLite error :(", "text/plain");
            return;
        }

        if (sqlite3_bind_int(stmt, 2, needs_auth)) {
            error("Couldn't bind 'needs_auth' for a new rid.");
            res.status = 500;
            res.set_content("SQLite error :(", "text/plain");
            return;
        }
 

        std::string es = std::to_string(expires);
        if (sqlite3_bind_text(stmt, 3, es.c_str(), es.size(), NULL)) {
            error("Couldn't bind 'expires' for a new rid.");
            res.status = 500;
            res.set_content("SQLite error :(", "text/plain");
            return;
        }

        if (sqlite3_bind_text(stmt, 4, rid.c_str(), -1, NULL)) {
            error("Couldn't bind 'rid' for a new rid.");
            res.status = 500;
            res.set_content("SQLite error :(", "text/plain");
            return;

        }

        if (sqlite3_bind_text(stmt, 5, target.c_str(), -1, NULL)) {
            error("Couldn't bind 'target' for a new rid.");
            res.status = 500;
            res.set_content("SQLite error :(", "text/plain");
            return;
        }

       
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::stringstream ss;
            ss << "While stepping for a new RID: " << sqlite3_errmsg(db);
            error(ss.str());
            res.status = 500;
            res.set_content("SQLite error :(", "text/plain");
            return;
        }
        
        if (sqlite3_finalize(stmt)) {
            error("Couldn't finalise for a new rid.");
            res.status = 500;
            res.set_content("SQLite error :(", "text/plain");
            return;
        }

        res.set_content("ok", "text/plain");
    });


    if (ssl) {
        std::cout << "Listening on https://" << host << ":" << port << std::endl;
        std::cout << "- Using OpenSSL :-)" << std::endl;
    } else {
        std::cout << "Listening on http://" << host << ":" << port << std::endl;
    }
    svr.listen(args["host"], port);

    return 0;
}
