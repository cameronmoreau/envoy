#include "extensions/filters/http/common/fetcher.h"

#include "gmock/gmock.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {

class MockFetcher : public Fetcher {
 public:
  MOCK_METHOD0(cancel, void());
  MOCK_METHOD2(fetch, void(const ::envoy::api::v2::core::HttpUri&, const std::string&, const std::string&, const std::string&,JwksReceiver&));
};

} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
