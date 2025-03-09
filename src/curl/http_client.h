#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include "lib.rs.h"
#include <cstdint>
#include <string>
#include <vector>

#include <android/log.h>
#include <curl/curl.h>

std::unique_ptr<std::vector<uint8_t>>
get_new_certificate_chain(rust::Str old_certificate_chain);

#endif
