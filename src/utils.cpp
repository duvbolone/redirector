#include "utils.h"

bool is_authenticated(const httplib::Request &req, std::string token) {
    if (!req.has_header("Authorization")) {
        if (req.has_param("token")) {
            return (req.get_param_value("token") == token);
        }
        if (req.has_param("t")) {
            return (req.get_param_value("t") == token);
        }
        return false;
    }

    std::string s = "Bearer ";
    s += token;
    
    return s == req.get_header_value("Authorization");
}
