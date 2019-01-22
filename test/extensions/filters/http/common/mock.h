#pragma once

#include "extensions/filters/http/common/fetcher.h"

#include "test/mocks/server/mocks.h"

#include "gmock/gmock.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {

class MockFetcher : public Fetcher {
public:
  MOCK_METHOD0(cancel, void());
  MOCK_METHOD6(fetch, void(const ::envoy::api::v2::core::HttpUri& uri, const std::string& method,
                           const std::string& accept, const std::string& content_type,
                           const std::string& body, Fetcher::Receiver& receiver));
};

// A mock HTTP upstream.
class MockUpstream {
public:
  /**
   * Mock upstream which returns a given response body.
   */
  MockUpstream(Upstream::MockClusterManager& mock_cm, const std::string& status,
               const std::string& response_body);
  /**
   * Mock upstream which returns a given failure.
   */
  MockUpstream(Upstream::MockClusterManager& mock_cm, Http::AsyncClient::FailureReason reason);
  /**
   * Mock upstream which returns the given request.
   */
  MockUpstream(Upstream::MockClusterManager& mock_cm, Http::MockAsyncClientRequest* request);

private:
  Http::MockAsyncClientRequest request_;
  std::string status_;
  std::string response_body_;
};

} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
