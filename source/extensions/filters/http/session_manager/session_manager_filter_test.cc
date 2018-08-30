#include "common/buffer/buffer_impl.h"
#include "common/grpc/common.h"
#include "common/http/headers.h"
#include "common/http/utility.h"

#include "test/integration/utility.h"
#include "test/mocks/http/mocks.h"
#include "test/test_common/utility.h"

#include "session_manager_filter.h"
#include "src/envoy/utils/mocks.h"

// TODO: Remove below
//#include "test/mocks/runtime/mocks.h"
#include "test/mocks/upstream/mocks.h"

#include "gmock/gmock.h"

namespace Envoy {
class HttpFilterXsrfTest : public testing::Test {

public:
  HttpFilterXsrfTest() {
    session_manager_.reset(new NiceMock<Utils::MockSessionManager>());
    filter_.reset(new Http::XsrfFilter(cluster_manager_, session_manager_));
    filter_->setDecoderFilterCallbacks(callbacks_);
  }

  NiceMock<Upstream::MockClusterManager> cluster_manager_;
  Utils::SessionManager::SessionManagerPtr session_manager_;
  NiceMock<Http::MockStreamDecoderFilterCallbacks> callbacks_;
  std::unique_ptr<Http::XsrfFilter> filter_;
};

TEST_F(HttpFilterXsrfTest, TestRequestWithAuthHeaderPassedThrough) {
  // Test requests that contain an Authorization header are passed through without mutation.
  Http::TestHeaderMapImpl scenario = {
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"host", "host"},
      {"authorization", "some-token"},
  };
  EXPECT_CALL(callbacks_, encodeHeaders_(testing::_, testing::_)).Times(0);
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(scenario, false));
}

TEST_F(HttpFilterXsrfTest, TestRequestWithoutMethodFails) {
  // Test that any request without a method fails.
  Http::TestHeaderMapImpl scenario = {
      {":path", "/"},
      {":authority", "host"},
      {"host", "host"},
  };
  EXPECT_CALL(callbacks_, encodeHeaders_(testing::_, testing::_))
      .WillOnce(testing::Invoke([](Http::HeaderMap& headers, bool) {
        auto status = Http::Utility::getResponseStatus(headers);
        EXPECT_EQ(400, status);
      }));
  EXPECT_EQ(Http::FilterHeadersStatus::StopIteration, filter_->decodeHeaders(scenario, false));
}

TEST_F(HttpFilterXsrfTest,
       TestRequestWithSafeMethodAndTokenCookieArePassedThroughWithAuthorizationHeader) {
  // Test that when a request is received that uses an HTTP safe method and includes an
  // istio_session cookie, the cookie is inserted into the authorization header.
  Http::TestHeaderMapImpl scenarios[] = {
      {{":method", "GET"},
       {":path", "/"},
       {":authority", "host"},
       {"host", "host"},
       {"cookie", "istio_session=expected"}},
      {{":method", "HEAD"},
       {":path", "/"},
       {":authority", "host"},
       {"host", "host"},
       {"cookie", "istio_session=expected"}},
      {{":method", "OPTIONS"},
       {":path", "/"},
       {":authority", "host"},
       {"host", "host"},
       {"cookie", "istio_session=expected"}},
  };
  for (size_t i = 0; i < sizeof(scenarios) / sizeof(Http::TestHeaderMapImpl); i++) {
    EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(scenarios[i], false));
    auto authorization = scenarios[i].get(Http::Headers::get().Authorization);
    ASSERT_NE(authorization, nullptr);
    EXPECT_EQ(authorization->value(), "Bearer expected");
  }
}

TEST_F(HttpFilterXsrfTest,
       TestRequestWithNonSafeMethodAndTokenCookieArePassedThroughWithAuthorizationHeader) {
  // Test that when a request is received that uses an HTTP non-safe method and includes an
  // istio_session cookie and x-xsrf-token header, that the cookie and header are verified and that
  // the cookie is inserted into the authorization header
  Http::TestHeaderMapImpl scenarios[] = {
      {{":method", "POST"},
       {":path", "/"},
       {":authority", "host"},
       {"host", "host"},
       {"cookie", "istio_session=expected"},
       {"x-xsrf-token", "expected"}},
      {{":method", "PUT"},
       {":path", "/"},
       {":authority", "host"},
       {"host", "host"},
       {"cookie", "istio_session=expected"},
       {"x-xsrf-token", "expected"}},
      {{":method", "PATCH"},
       {":path", "/"},
       {":authority", "host"},
       {"host", "host"},
       {"cookie", "istio_session=expected"},
       {"x-xsrf-token", "expected"}},
      {{":method", "DELETE"},
       {":path", "/"},
       {":authority", "host"},
       {"host", "host"},
       {"cookie", "istio_session=expected"},
       {"x-xsrf-token", "expected"}},
  };
  ON_CALL(*reinterpret_cast<NiceMock<Utils::MockSessionManager>*>(session_manager_.get()),
          verifyToken("expected", "expected"))
      .WillByDefault(testing::Return(true));
  for (size_t i = 0; i < sizeof(scenarios) / sizeof(Http::TestHeaderMapImpl); i++) {
    EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(scenarios[i], false));
    auto authorization = scenarios[i].get(Http::Headers::get().Authorization);
    ASSERT_NE(authorization, nullptr);
    EXPECT_EQ(authorization->value(), "Bearer expected");
  }
}

TEST_F(HttpFilterXsrfTest,
       TestRequestWithNonSafeMethodAndNonMatchingXsrfTokensDontForwardAnAuthorizationHeader) {
  // Test that when a request is received that uses an HTTP non-safe method and includes an
  // istio_session cookie and x-xsrf-token header, that the cookie and header when verification
  // fails does *not* insert and authorization header.
  Http::TestHeaderMapImpl scenarios[] = {
      {{":method", "POST"},
       {":path", "/"},
       {":authority", "host"},
       {"host", "host"},
       {"cookie", "istio_session=expected"},
       {"x-xsrf-token", "expected"}},
      {{":method", "PUT"},
       {":path", "/"},
       {":authority", "host"},
       {"host", "host"},
       {"cookie", "istio_session=expected"},
       {"x-xsrf-token", "expected"}},
      {{":method", "PATCH"},
       {":path", "/"},
       {":authority", "host"},
       {"host", "host"},
       {"cookie", "istio_session=expected"},
       {"x-xsrf-token", "expected"}},
      {{":method", "DELETE"},
       {":path", "/"},
       {":authority", "host"},
       {"host", "host"},
       {"cookie", "istio_session=expected"},
       {"x-xsrf-token", "expected"}},
  };
  ON_CALL(*reinterpret_cast<NiceMock<Utils::MockSessionManager>*>(session_manager_.get()),
          verifyToken(testing::_, testing::_))
      .WillByDefault(testing::Return(false));
  for (size_t i = 0; i < sizeof(scenarios) / sizeof(Http::TestHeaderMapImpl); i++) {
    EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(scenarios[i], false));
    auto authorization = scenarios[i].get(Http::Headers::get().Authorization);
    EXPECT_EQ(authorization, nullptr);
  }
}

TEST_F(HttpFilterXsrfTest,
       TestRequestWithNonSafeMethodAndMissingXsrfTokenHeaderDontForwardAnAuthorizationHeader) {
  // Test that when a request is received that uses an HTTP non-safe method and includes an
  // istio_session cookie and without a matching x-xsrf-token header does *not* insert and
  // authorization header.
  Http::TestHeaderMapImpl scenarios[] = {
      {{":method", "POST"},
       {":path", "/"},
       {":authority", "host"},
       {"host", "host"},
       {"cookie", "istio_session=expected"}},
      {{":method", "PUT"},
       {":path", "/"},
       {":authority", "host"},
       {"host", "host"},
       {"cookie", "istio_session=expected"}},
      {{":method", "PATCH"},
       {":path", "/"},
       {":authority", "host"},
       {"host", "host"},
       {"cookie", "istio_session=expected"}},
      {{":method", "DELETE"},
       {":path", "/"},
       {":authority", "host"},
       {"host", "host"},
       {"cookie", "istio_session=expected"}},
  };
  ON_CALL(*reinterpret_cast<NiceMock<Utils::MockSessionManager>*>(session_manager_.get()),
          verifyToken(testing::_, testing::_))
      .WillByDefault(testing::Return(false));
  for (size_t i = 0; i < sizeof(scenarios) / sizeof(Http::TestHeaderMapImpl); i++) {
    EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(scenarios[i], false));
    auto authorization = scenarios[i].get(Http::Headers::get().Authorization);
    EXPECT_EQ(authorization, nullptr);
  }
}

TEST_F(HttpFilterXsrfTest, TestRequestWithoutTokenCookiePassedThroughWithoutModification) {
  // Test that requests that do not contain a token cookie are passed through without an
  // Authorization header.
  Http::TestHeaderMapImpl scenario = {
      {":method", "GET"},
      {":path", "/"},
      {":authority", "host"},
      {"host", "host"},
  };
  EXPECT_CALL(callbacks_, encodeHeaders_(testing::_, testing::_)).Times(0);
  EXPECT_EQ(Http::FilterHeadersStatus::Continue, filter_->decodeHeaders(scenario, false));
}
} // namespace Envoy
