#include <cstring>
#include <stdexcept>

#include "common/common/base64.h"

#include "extensions/filters/http/common/session_manager.h"

#include "openssl/crypto.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {
namespace {

class SessionManagerImpl : public SessionManager {
private:
  char key_[32];

public:
  explicit SessionManagerImpl(const std::string& key) {
    auto characters = Base64::decode(key);
    // At present we only support 32-byte/256-bit keys
    if (characters.size() != sizeof(key)) {
      throw std::runtime_error(
          "expected session_protection_key to be 32 bytes after base64 decode");
    }
    std::memcpy(key_, characters.c_str(), sizeof(key_));
  }

  unsigned int Hmac(const SessionManager::Context& ctx, uint8_t* mac) const {
    unsigned int length;
    const EVP_MD* digester = EVP_sha256();
    auto macd = HMAC(digester, key_, sizeof(key_),
                     reinterpret_cast<const unsigned char*>(ctx.c_str()), ctx.size(), mac, &length);
    if (!macd) {
      // Never expected to happen.
      throw std::runtime_error("Unexpected token binding failure");
    }
    return length;
  }

  SessionManager::SessionToken CreateToken(const SessionManager::Context& ctx) {
    uint8_t mac[EVP_MAX_MD_SIZE];
    auto length = Hmac(ctx, mac);
    return Base64Url::encode(reinterpret_cast<char*>(mac), length);
  }

  bool VerifyToken(const SessionManager::Context& ctx,
                   const SessionManager::SessionToken& token) const {
    // First decode the provided token. If decoding fails bail.
    std::string decoded = Base64Url::decode(token);
    if (decoded.empty()) {
      return false;
    }
    // Calculate HMAC of context and compare to the decoded value.
    uint8_t calculated[EVP_MAX_MD_SIZE];
    auto length = Hmac(ctx, calculated);
    if (decoded.length() != length) {
      return false;
    }
    return CRYPTO_memcmp(decoded.c_str(), reinterpret_cast<char*>(calculated), length) == 0;
  }
};
} // namespace

SessionManagerPtr SessionManager::Create(const std::string& key) {
  return std::make_shared<SessionManagerImpl>(key);
}
} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
