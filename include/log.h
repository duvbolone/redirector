#ifndef LOG_H
#define LOG_H

#include <iostream>
#include <string>

inline void warn(std::string message) {
    std::cerr << "\033[33;1mWARNING\033[0m: " << message << std::endl;
}

inline void error(std::string message, bool quit = false) {
    std::cerr << "\033[31;1mERROR\033[0m: " << message << std::endl;
    if (quit) {
        exit(1);
    }
}

#endif
