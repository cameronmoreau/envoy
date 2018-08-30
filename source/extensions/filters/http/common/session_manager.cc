#include "common/common/base64.h"
#include "extensions/filters/http/common/session_manager.h"
#include <cstring>
#include <stdexcept>
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
  explicit SessionManagerImpl(const std::string &key) {
    auto characters = Base64::decode(key);
    // At present we only support 32-byte/256-bit keys
    if (characters.size() != sizeof(key)) {
      throw std::runtime_error("expected session_protection_key to be 32 bytes after base64 decode");
    }
    std::memcpy(key_, characters.c_str(), sizeof(key_));
  }

  SessionManager::SessionToken Hmac(const SessionManager::Context &ctx) const {
    uint8_t mac[EVP_MAX_MD_SIZE];
    unsigned int length;
    const EVP_MD *digester = EVP_sha256();
    auto macd = HMAC(digester,
                     key_,
                     sizeof(key_),
                     reinterpret_cast<const unsigned char *>(ctx.c_str()),
                     ctx.size(),
                     mac,
                     &length);
    if (!macd) {
      // Never expected to happen.
      throw std::runtime_error("Unexpected token binding failure");
    }
    return Base64::encode(reinterpret_cast<char *>(macd), length);
  }

  SessionManager::SessionToken CreateToken(const SessionManager::Context &ctx) {
    return Hmac(ctx);
  }

  bool VerifyToken(const SessionManager::Context &ctx, const SessionManager::SessionToken &token) const {
    auto calculated = Hmac(ctx);
    if (token.length() != calculated.length()) {
      return false;
    }
    return CRYPTO_memcmp(token.c_str(), calculated.c_str(), token.length()) == 0;
  }
};
} // namespace

SessionManagerPtr SessionManager::Create(const std::string &key) {
  return std::make_shared<SessionManagerImpl>(key);
}
} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
