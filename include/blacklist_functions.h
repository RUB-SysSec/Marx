#ifndef BLACKLIST_FUNCTIONS_H
#define BLACKLIST_FUNCTIONS_H

#include <stdexcept>
#include <set>
#include <string>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iostream>

typedef std::set<uint64_t> BlacklistFuncsSet;

const BlacklistFuncsSet import_blacklist_funcs(const std::string &target_file);

#endif
