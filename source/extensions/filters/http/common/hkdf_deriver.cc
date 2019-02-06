#include "extensions/filters/http/common/hkdf_deriver.h"

#include "envoy/common/exception.h"
#include "envoy/config/filter/http/session_manager/v1alpha/config.pb.h"

#include "common/common/assert.h"

#include "openssl/digest.h"
#include "openssl/hkdf.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {

class HkdfDeriverImpl : public HkdfDeriver {
public:
  HkdfDeriverImpl(std::vector<unsigned char> secret, const Config::HkdfHash& hash_alg);

  virtual std::vector<unsigned char> hkdf(size_t out_len, const std::vector<unsigned char>& salt,
                                          const std::vector<unsigned char>& info = {});

private:
  std::vector<unsigned char> secret_;
  const EVP_MD* hash_alg_;
};

HkdfDeriverImpl::HkdfDeriverImpl(std::vector<unsigned char> secret,
                                 const Config::HkdfHash& hash_alg)
    : secret_(std::move(secret)) {
  switch (hash_alg) {
  case Config::SHA256:
    hash_alg_ = EVP_sha256();
    break;
  case Config::SHA384:
    hash_alg_ = EVP_sha384();
    break;
  case Config::SHA512:
    hash_alg_ = EVP_sha512();
    break;
  default:
    throw EnvoyException("Unsupport hash algorithm");
  }
}

std::vector<unsigned char> HkdfDeriverImpl::hkdf(size_t out_len,
                                                 const std::vector<unsigned char>& salt,
                                                 const std::vector<unsigned char>& info) {
  std::vector<unsigned char> output(out_len);

  auto rc = HKDF(output.data(), out_len, hash_alg_, secret_.data(), secret_.size(), salt.data(),
                 salt.size(), info.data(), info.size());
  RELEASE_ASSERT(rc == 1, "");

  return output;
}

HkdfDeriverPtr HkdfDeriver::create(const std::vector<unsigned char>& secret,
                                   const Config::HkdfHash& hash_alg) {
  return std::make_shared<HkdfDeriverImpl>(secret, hash_alg);
}

} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
