#ifndef __RED_UTILS
#define __RED_UTILS

#include <string>
#include "httplib.h"

bool is_authenticated(const httplib::Request &req, std::string token);

#endif
