#include "extensions/filters/http/common/token_encryptor.h"

#include "common/common/base64.h"

#include "extensions/filters/http/common/gcm_encryptor.h"
#include "extensions/filters/http/common/hkdf_deriver.h"
#include "extensions/filters/http/common/state_store.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {

namespace {
const size_t DERIVED_KEY_SIZE = 32;
}

class TokenEncryptorImpl : public TokenEncryptor {
public:
  TokenEncryptorImpl(const std::string& secret, const Config::EncryptionAlg& enc_alg,
                     const Config::HkdfHash& hash_alg);

  virtual std::string encrypt(const std::string& token, const StateStore::Nonce& nonce);
  virtual absl::optional<std::string> decrypt(const std::string& ciphertext);

private:
  Config::EncryptionAlg enc_alg_;
  HkdfDeriverPtr deriver_;

  size_t keySize() const;

  std::vector<unsigned char> encryptInternal(const std::string& token,
                                             const std::vector<unsigned char>& key) const;
};

TokenEncryptorImpl::TokenEncryptorImpl(const std::string& secret,
                                       const Config::EncryptionAlg& enc_alg,
                                       const Config::HkdfHash& hash_alg)
    : enc_alg_(enc_alg) {
  // Get the secret from the config and use it and the claim nonce to derive a new AES-256 key
  std::vector<unsigned char> secret_vec(secret.begin(), secret.end());
  deriver_ = Common::HkdfDeriver::create(secret_vec, hash_alg);
}

size_t TokenEncryptorImpl::keySize() const {
  switch (enc_alg_) {
  case Config::AES128GCM:
    return 16;
  case Config::AES256GCM:
    return 32;
  default:
    throw EnvoyException("Unsupported encryption algorithm");
  }
}

std::vector<unsigned char>
TokenEncryptorImpl::encryptInternal(const std::string& token,
                                    const std::vector<unsigned char>& key) const {
  switch (enc_alg_) {
  case Config::AES128GCM:
  case Config::AES256GCM: {
    // Encrypt the JWT, using the derived key and a random nonce
    // Ouput is: gcm_nonce || ciphertext || tag
    auto encryptor = Common::GcmEncryptor::create(key);
    std::vector<unsigned char> tokenVec(token.begin(), token.end());
    auto encrypted = encryptor->seal(tokenVec);
    return encrypted;
  }
  default:
    throw EnvoyException("Unsupported encryption algorithm");
  }
}

std::string TokenEncryptorImpl::encrypt(const std::string& token, const StateStore::Nonce& nonce) {
  std::vector<unsigned char> nonce_vec(nonce.Value, nonce.Value + sizeof(nonce.Value));
  auto derivedKey = deriver_->hkdf(keySize(), nonce_vec);

  auto encrypted = encryptInternal(token, derivedKey);

  // Concatenate the claim nonce and the ciphertext
  // Result is: derive_nonce || gcm_nonce || ciphertext || tag
  std::vector<unsigned char> output(nonce_vec);
  output.insert(output.end(), encrypted.begin(), encrypted.end());

  // Base64 encode the final encrypted JWT
  return Base64::encode(reinterpret_cast<char*>(output.data()), output.size());
}

absl::optional<std::string> TokenEncryptorImpl::decrypt(const std::string& ciphertext) {
  // Base64 decode the token
  auto decoded = Base64::decode(std::string(ciphertext));

  if (decoded.size() < sizeof(StateStore::Nonce::NonceValue)) {
    return absl::nullopt;
  }
  std::vector<unsigned char> nonce_vec(decoded.begin(),
                                       decoded.begin() + sizeof(StateStore::Nonce::NonceValue));
  auto derivedKey = deriver_->hkdf(DERIVED_KEY_SIZE, nonce_vec);

  // Decrypt the JWT
  auto decryptor = Common::GcmEncryptor::create(derivedKey);
  std::vector<unsigned char> ciphertext_vec(decoded.begin() + sizeof(StateStore::Nonce::NonceValue),
                                            decoded.end());
  auto decrypted = decryptor->open(ciphertext_vec);

  if (!decrypted) {
    return absl::nullopt;
  }

  return std::string(decrypted->begin(), decrypted->end());
}

TokenEncryptorPtr TokenEncryptor::create(const std::string& secret,
                                         const Config::EncryptionAlg& enc_alg,
                                         const Config::HkdfHash& hash_alg) {
  return std::make_shared<TokenEncryptorImpl>(secret, enc_alg, hash_alg);
}

TokenEncryptorPtr TokenEncryptor::create(const Config& config) {
  return TokenEncryptor::create(config.secret(), config.encryption_alg(), config.hkdf_hash());
}

} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy