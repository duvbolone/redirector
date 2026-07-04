#ifndef __RED_GETR
#define __RED_GETR

#include <string>
#include <chrono>
#include <sqlite3.h>
#include "httplib.h"
#include "json.hpp"

#include "log.h"
#include "utils.h"

int get_rid(sqlite3 *db, const httplib::Request& req, httplib::Response& res, std::string token, std::string not_found_url);
void set_rid(sqlite3 *db, const httplib::Request& req, httplib::Response& res, std::string token);

#endif
