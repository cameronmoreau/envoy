#pragma once

#include "envoy/config/filter/http/session_manager/v1alpha/config.pb.h"

#include "common/common/logger.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {

class HkdfDeriver;
typedef std::shared_ptr<HkdfDeriver> HkdfDeriverPtr;

class HkdfDeriver : public Logger::Loggable<Logger::Id::filter> {
public:
  using Config = ::envoy::config::filter::http::session_manager::v1alpha::TokenBinding;
  virtual ~HkdfDeriver(){};

  virtual std::vector<unsigned char> hkdf(size_t out_len, const std::vector<unsigned char>& salt,
                                          const std::vector<unsigned char>& info = {}) PURE;

  /**
   * Create an instance of a HkdfDeriver.
   * @return an instance of a HkdfDeriver.
   */
  static HkdfDeriverPtr create(const std::vector<unsigned char>& secret,
                               const Config::HkdfHash& hash_alg = Config::SHA256);
};

} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy