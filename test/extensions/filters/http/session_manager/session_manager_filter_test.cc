#include "extensions/filters/http/session_manager/session_manager_filter.h"

#include "test/extensions/filters/http/common/session_manager_mock.h"
#include "test/mocks/server/mocks.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using testing::_;
using testing::Invoke;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace SessionManager {
namespace {
const char exampleConfig[] = R"(
token_binding:
  secret: Mb07unY1jd4h2s5wUSO9KJzhqjVTazXMWCp4OAiiGko=
  token: __Secure-acme-session-cookie
  binding: x-xsrf-token
forward_rule:
  name: authorization
  preamble: Bearer
)";

const char exampleConfigNoPreamble[] = R"(
token_binding:
  secret: Mb07unY1jd4h2s5wUSO9KJzhqjVTazXMWCp4OAiiGko=
  token: __Secure-acme-session-cookie
  binding: x-xsrf-token
forward_rule:
  name: authorization
)";
} // namespace

class SessionManagerFilterTest : public ::testing::Test {
 public:
  void SetUp() {
    session_manager_ = std::make_shared<Common::MockSessionManager>();
    session_manager_ptr_ = const_cast<Common::MockSessionManager*>(reinterpret_cast<const Common::MockSessionManager*>(session_manager_.get()));
    filter_ = std::make_unique<SessionManagerFilter>(proto_config_, session_manager_);
    filter_->setDecoderFilterCallbacks(filter_callbacks_);
  }

  ::envoy::config::filter::http::session_manager::v1alpha::SessionManager proto_config_;
  NiceMock<Http::MockStreamDecoderFilterCallbacks> filter_callbacks_;
  std::unique_ptr<SessionManagerFilter> filter_;
  Common::SessionManagerPtr session_manager_;
  Common::MockSessionManager* session_manager_ptr_;
};

TEST_F(SessionManagerFilterTest, onDestroy) {
  EXPECT_NO_THROW(filter_->onDestroy());
  EXPECT_NO_THROW(filter_->onDestroy());
};

// When no cookies are included in a request return Continue with no
// header modification.
TEST_F(SessionManagerFilterTest, onDecodeHeadersNoCookies) {
  MessageUtil::loadFromYaml(exampleConfig, proto_config_);
  auto headers = Http::TestHeaderMapImpl{};
  EXPECT_CALL(*session_manager_ptr_, VerifyToken(testing::_, testing::_)).Times(0);
  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::Continue);
  auto authz = headers.get(Http::LowerCaseString(proto_config_.forward_rule().name()));
  EXPECT_EQ(authz, nullptr);
};

// When we call a safe method (GET, HEAD, OPTIONS) insert token into expected
// header whether our binding is passed or not.
TEST_F(SessionManagerFilterTest, onDecodeHeadersSafeMethod) {
  MessageUtil::loadFromYaml(exampleConfig, proto_config_);
  Http::TestHeaderMapImpl headers[] = {
    {
      {":method", "GET"},
      {"cookie", "__Secure-acme-session-cookie=1234567890"}
    },
    {
        {":method", "HEAD"},
        {"cookie", "__Secure-acme-session-cookie=1234567890"}
    },
    {
      {":method", "OPTIONS"},
      {"cookie", "__Secure-acme-session-cookie=1234567890"}
    }
  };
  for(size_t i = 0; i < sizeof(headers)/sizeof(*headers); i++) {
    EXPECT_CALL(*session_manager_ptr_, VerifyToken(testing::_, testing::_)).Times(0);

    EXPECT_EQ(filter_->decodeHeaders(headers[i], false), Http::FilterHeadersStatus::Continue);
    auto authz = headers[i].get(Http::LowerCaseString(proto_config_.forward_rule().name()));
    EXPECT_NE(authz, nullptr);
    EXPECT_STREQ(authz->value().c_str(), "Bearer 1234567890");
  }
};

// When our configuration includes a preamble make sure it is encoded into
// the output header
TEST_F(SessionManagerFilterTest, onDecodeHeadersPreamble) {
  MessageUtil::loadFromYaml(exampleConfig, proto_config_);
  Http::TestHeaderMapImpl headers = {
      {":method", "GET"},
      {"cookie", "__Secure-acme-session-cookie=1234567890"}
  };
  EXPECT_CALL(*session_manager_ptr_, VerifyToken(testing::_, testing::_)).Times(0);
  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::Continue);
  auto authz = headers.get(Http::LowerCaseString(proto_config_.forward_rule().name()));
  EXPECT_NE(authz, nullptr);
  EXPECT_STREQ(authz->value().c_str(), "Bearer 1234567890");
};

// When our configuration *does not* include a preamble make sure our
// output header is as expected.
TEST_F(SessionManagerFilterTest, onDecodeHeadersNoPreamble) {
  MessageUtil::loadFromYaml(exampleConfigNoPreamble, proto_config_);
  Http::TestHeaderMapImpl headers = {
    {":method", "GET"},
    {"cookie", "__Secure-acme-session-cookie=1234567890"}
  };
  EXPECT_CALL(*session_manager_ptr_, VerifyToken(testing::_, testing::_)).Times(0);
  EXPECT_EQ(filter_->decodeHeaders(headers, false), Http::FilterHeadersStatus::Continue);
  auto authz = headers.get(Http::LowerCaseString(proto_config_.forward_rule().name()));
  EXPECT_NE(authz, nullptr);
  EXPECT_STREQ(authz->value().c_str(), "1234567890");
};

// When we receive a non-safe request without binding check that
// we do not map our token to the configured output header.
TEST_F(SessionManagerFilterTest, onDecodeHeadersMissingBinding) {
  MessageUtil::loadFromYaml(exampleConfigNoPreamble, proto_config_);
  Http::TestHeaderMapImpl headers[] = {
      {
          {":method", "POST"},
          {"cookie", "__Secure-acme-session-cookie=1234567890"}
      },
      {
          {":method", "PUT"},
          {"cookie", "__Secure-acme-session-cookie=1234567890"}
      },
      {
          {":method", "DELETE"},
          {"cookie", "__Secure-acme-session-cookie=1234567890"}
      },
      {
          {":method", "PATCH"},
          {"cookie", "__Secure-acme-session-cookie=1234567890"}
      },
  };
  for (size_t i = 0; i < sizeof(headers)/sizeof(*headers); i++) {
    EXPECT_CALL(*session_manager_ptr_, VerifyToken(testing::_, testing::_)).Times(0);
    EXPECT_EQ(filter_->decodeHeaders(headers[i], false), Http::FilterHeadersStatus::Continue);
    auto authz = headers[i].get(Http::LowerCaseString(proto_config_.forward_rule().name()));
    EXPECT_EQ(authz, nullptr);
  }
};

// When we receive a non-safe request with an invalid binding check that
// we do not map our token to the configured output header.
TEST_F(SessionManagerFilterTest, onDecodeHeadersInvalidBinding) {
  MessageUtil::loadFromYaml(exampleConfigNoPreamble, proto_config_);
  Http::TestHeaderMapImpl headers[] = {
      {
          {":method", "POST"},
          { "cookie", "__Secure-acme-session-cookie=1234567890" },
          { "x-xsrf-token", "invalid" }
      },
      {
          {":method", "PUT"},
          { "cookie", "__Secure-acme-session-cookie=1234567890" },
          { "x-xsrf-token", "invalid" }
      },
      {
          {":method", "PATCH"},
          { "cookie", "__Secure-acme-session-cookie=1234567890" },
          { "x-xsrf-token", "invalid" }
      },
      {
          {":method", "DELETE"},
          { "cookie", "__Secure-acme-session-cookie=1234567890" },
          { "x-xsrf-token", "invalid" }
      },
  };
  for (size_t i = 0; i < sizeof(headers)/sizeof(*headers); i++) {
    EXPECT_CALL(*session_manager_ptr_, VerifyToken("1234567890", "invalid")).WillOnce(testing::Return(false));
    EXPECT_EQ(filter_->decodeHeaders(headers[i], false), Http::FilterHeadersStatus::Continue);
    auto authz = headers[i].get(Http::LowerCaseString(proto_config_.forward_rule().name()));
    EXPECT_EQ(authz, nullptr);
  }
};

// When we receive a non-safe request with *a valid* binding ensure that
// we map our token to the configured output header.
TEST_F(SessionManagerFilterTest, onDecodeHeadersValidBinding) {
  MessageUtil::loadFromYaml(exampleConfigNoPreamble, proto_config_);
  Http::TestHeaderMapImpl headers[] = {
      {
          {":method", "POST"},
          { "cookie", "__Secure-acme-session-cookie=1234567890" },
          { "x-xsrf-token", "valid" }
      },
      {
          {":method", "PUT"},
          { "cookie", "__Secure-acme-session-cookie=1234567890" },
          { "x-xsrf-token", "valid" }
      },
      {
          {":method", "PATCH"},
          { "cookie", "__Secure-acme-session-cookie=1234567890" },
          { "x-xsrf-token", "valid" }
      },
      {
          {":method", "DELETE"},
          { "cookie", "__Secure-acme-session-cookie=1234567890" },
          { "x-xsrf-token", "valid" }
      },
  };
  for (size_t i = 0; i < sizeof(headers)/sizeof(*headers); i++) {
    EXPECT_CALL(*session_manager_ptr_, VerifyToken("1234567890", "valid")).WillOnce(testing::Return(true));
    EXPECT_EQ(filter_->decodeHeaders(headers[i], false), Http::FilterHeadersStatus::Continue);
    auto authz = headers[i].get(Http::LowerCaseString(proto_config_.forward_rule().name()));
    EXPECT_NE(authz, nullptr);
    EXPECT_STREQ(authz->value().c_str(), "1234567890");
  }
};

} // namespace SessionManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
