#ifndef GOT_H
#define GOT_H

#include <map>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iostream>

typedef std::map<uint64_t, uint64_t> GotMap;

GotMap import_got(const std::string &target_file);

#endif
