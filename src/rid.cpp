#include "rid.h"

using json = nlohmann::json;

int get_rid(sqlite3 *db, const httplib::Request& req, httplib::Response& res, std::string token, std::string not_found_url) {
        std::string rid = req.path_params.at("rid");
        if (rid.empty()) {
            res.set_redirect(not_found_url);
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
            res.set_redirect(not_found_url);
        } else if (step_result == SQLITE_ROW) {
            const unsigned char *expires = sqlite3_column_text(stmt, 0);
            const auto epoch = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count(); 
            const int expires_i = std::atoi(reinterpret_cast<const char*>(expires));
            if (epoch > expires_i && expires_i != 0) {
                res.set_redirect(not_found_url);

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
    }

void set_rid(sqlite3 *db, const httplib::Request& req, httplib::Response& res, std::string token) {
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
        if (expires_in != 0) {
            expires = epoch + expires_in;
        } else {
            expires = 0;
        }
    }

    if (expires < epoch && expires != 0) {
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
        res.set_content(sqlite3_errmsg(db), "text/plain");
        return;
    }
    
    if (sqlite3_finalize(stmt)) {
        error("Couldn't finalise for a new rid.");
        res.status = 500;
        res.set_content("SQLite error :(", "text/plain");
        return;
    }

    res.set_content("ok", "text/plain");
}
