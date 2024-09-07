#include "http_client.h"

#define ALOG(priority, tag, ...)                                               \
  ((void)__android_log_print(ANDROID_##priority, tag, __VA_ARGS__))
#define LOG_TAG "DroidfoodAttestationFixer http_client.cpp"
#define ALOGI(...) ALOG(LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) ALOG(LOG_ERROR, LOG_TAG, __VA_ARGS__)

static constexpr char HOSTNAME[] = "greendroidfood-pa.googleapis.com";

static size_t write_callback(char *contents, size_t size, size_t nmemb,
                             void *userp) {
  std::vector<uint8_t> *output = static_cast<std::vector<uint8_t> *>(userp);
  const size_t real_size = size * nmemb;

  std::copy(contents, contents + real_size, std::back_inserter(*output));

  return real_size;
}

std::unique_ptr<std::vector<uint8_t>>
get_new_certificate_chain(rust::Str old_certificate_chain) {
  const std::string url =
      std::string("https://") + HOSTNAME + "/v1:overwriteAttestation";
  struct curl_slist *headers =
      curl_slist_append(nullptr, "Content-Type: application/json");

  auto response = std::make_unique<std::vector<uint8_t>>();
  CURL *handle = curl_easy_init();

  curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
  curl_easy_setopt(handle, CURLOPT_POSTFIELDS, old_certificate_chain.data());
  curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, old_certificate_chain.size());
  curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(handle, CURLOPT_WRITEDATA, response.get());
  curl_easy_setopt(handle, CURLOPT_VERBOSE, 1L);

  const CURLcode rc = curl_easy_perform(handle);

  curl_slist_free_all(headers);
  curl_easy_cleanup(handle);
  if (rc == CURLE_OK) {
    ALOGI("%zu bytes retrieved from server.", response->size());
  } else {
    const std::string error_message =
        std::string("{\"error\": \"") + curl_easy_strerror(rc) + "\"}";
    ALOGE("error message to be returned: %s", error_message.c_str());
    return std::make_unique<std::vector<uint8_t>>(error_message.begin(),
                                                  error_message.end());
  }

  return response;
}
