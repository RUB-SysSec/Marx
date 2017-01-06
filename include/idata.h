#ifndef IDATA_H
#define IDATA_H

#include <map>
#include <string>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iostream>

typedef std::map<uint64_t, std::string> IDataMap;

IDataMap import_idata(const std::string &target_file);

#endif
