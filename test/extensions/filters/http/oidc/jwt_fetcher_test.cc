#include <chrono>
#include <thread>

#include "common/http/message_impl.h"
#include "common/protobuf/utility.h"

#include "extensions/filters/http/oidc/jwt_fetcher.h"

#include "test/extensions/filters/http/common/mock.h"
#include "test/extensions/filters/http/oidc/jwt_fetcher_mock.h"
#include "test/mocks/http/mocks.h"
#include "test/mocks/server/mocks.h"
#include "test/test_common/utility.h"

using ::envoy::api::v2::core::HttpUri;
using ::google::jwt_verify::Status;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Oidc {
namespace {

const std::string jwtUri = R"(
uri: https://pubkey_server/jwt
cluster: jwt_cluster
timeout:
  seconds: 5
)";

const std::string code = "12345678";
const std::string client = "87654321";
const std::string secret = "sssshhhhh";
const std::string callback = "https://acme.com/callback";

const std::string goodJwt =
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9."
    "eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
    "ob5g8zsyqroiHW-VKMCIUm_VtWrEUKwVoz9jD1uQ2EUKIgjHZyrG0dSFwtWFGYW1tYD0v828OmZ-"
    "EKKbf98cVFRlaznSeTu2TM0SA5NKbL_0ItA9hJUOBvtjkExFpImQt_19TflwtL7YpuM7o0ghTK2Xk5V9gQw_Iq0k-6Eo6_"
    "M";
const std::string badJwt = "abcdefg.abcdefg.abcdefg";

std::string expectedMessageBody() {
  return fmt::format(
      "code={}&client_id={}&client_secret={}&redirect_uri={}&grant_type=authorization_code", code,
      client, secret, Http::Utility::urlSafeEncode(callback));
}

class JwtFetcherTest : public ::testing::Test {
public:
  void SetUp() { MessageUtil::loadFromYaml(jwtUri, uri_); }
  HttpUri uri_;
  testing::NiceMock<Server::Configuration::MockFactoryContext> mock_factory_ctx_;
};

TEST_F(JwtFetcherTest, TestCreate) {
  // Setup/Act
  std::unique_ptr<JwtFetcher> fetcher(JwtFetcher::create(mock_factory_ctx_.cluster_manager_));

  // Assert
  EXPECT_TRUE(fetcher != nullptr);
}

TEST_F(JwtFetcherTest, TestCancel) {
  // Setup/Act
  std::unique_ptr<JwtFetcher> fetcher(JwtFetcher::create(mock_factory_ctx_.cluster_manager_));

  // Assert
  EXPECT_TRUE(fetcher != nullptr);
}

TEST_F(JwtFetcherTest, TestFetchSuccess) {
  // Setup/Act
  Http::MockAsyncClientRequest request(&(mock_factory_ctx_.cluster_manager_.async_client_));
  ON_CALL(mock_factory_ctx_.cluster_manager_.async_client_,
          send_(testing::_, testing::_, testing::_))
      .WillByDefault(testing::Invoke(
          [&request](
              Http::MessagePtr& msg, Http::AsyncClient::Callbacks& cb,
              const absl::optional<std::chrono::milliseconds>&) -> Http::AsyncClient::Request* {
            auto expected = expectedMessageBody();
            EXPECT_STREQ(Http::Headers::get().MethodValues.Post.c_str(),
                         msg->headers().Method()->value().c_str());
            EXPECT_STREQ(expected.c_str(), msg->bodyAsString().c_str());
            Http::MessagePtr response_message(
                new Http::ResponseMessageImpl(Http::HeaderMapPtr{new Http::TestHeaderMapImpl{
                    {":status", "200"},
                    {"content-type", Http::Headers::get().ContentTypeValues.Json}}}));
            response_message->body().reset(new Buffer::OwnedImpl(goodJwt));
            cb.onSuccess(std::move(response_message));
            return &request;
          }));
  MockJwtReceiver receiver;
  std::unique_ptr<JwtFetcher> fetcher(JwtFetcher::create(mock_factory_ctx_.cluster_manager_));

  // Assert
  EXPECT_TRUE(fetcher != nullptr);
  EXPECT_CALL(receiver, onJwtSuccessImpl(testing::_)).Times(1);
  EXPECT_CALL(receiver, onJwtFailure(testing::_)).Times(0);

  // Act
  fetcher->fetch(uri_, client, secret, code, callback, receiver);
}

TEST_F(JwtFetcherTest, TestInvalidJwt) {
  // Setup/Act

  Http::MockAsyncClientRequest request(&(mock_factory_ctx_.cluster_manager_.async_client_));
  ON_CALL(mock_factory_ctx_.cluster_manager_.async_client_,
          send_(testing::_, testing::_, testing::_))
      .WillByDefault(testing::Invoke(
          [&request](
              Http::MessagePtr& msg, Http::AsyncClient::Callbacks& cb,
              const absl::optional<std::chrono::milliseconds>&) -> Http::AsyncClient::Request* {
            auto expected = expectedMessageBody();
            EXPECT_STREQ(Http::Headers::get().MethodValues.Post.c_str(),
                         msg->headers().Method()->value().c_str());
            EXPECT_STREQ(expected.c_str(), msg->bodyAsString().c_str());
            Http::MessagePtr response_message(
                new Http::ResponseMessageImpl(Http::HeaderMapPtr{new Http::TestHeaderMapImpl{
                    {":status", "200"},
                    {"content-type", Http::Headers::get().ContentTypeValues.Json}}}));
            response_message->body().reset(new Buffer::OwnedImpl(badJwt));
            cb.onSuccess(std::move(response_message));
            return &request;
          }));
  MockJwtReceiver receiver;
  std::unique_ptr<JwtFetcher> fetcher(JwtFetcher::create(mock_factory_ctx_.cluster_manager_));

  // Assert
  EXPECT_TRUE(fetcher != nullptr);
  EXPECT_CALL(receiver, onJwtSuccessImpl(testing::_)).Times(0);
  EXPECT_CALL(receiver, onJwtFailure(Common::Failure::InvalidData)).Times(1);

  // Act
  fetcher->fetch(uri_, client, secret, code, callback, receiver);
}

TEST_F(JwtFetcherTest, TestFetchFailure) {
  // Setup/Act
  MockJwtReceiver receiver;
  Common::MockUpstream mock_pubkey(mock_factory_ctx_.cluster_manager_, "400", "Not found");
  std::unique_ptr<JwtFetcher> fetcher(JwtFetcher::create(mock_factory_ctx_.cluster_manager_));

  // Assert
  EXPECT_TRUE(fetcher != nullptr);
  EXPECT_CALL(receiver, onJwtSuccessImpl(testing::_)).Times(0);
  EXPECT_CALL(receiver, onJwtFailure(Common::Failure::Network)).Times(1);

  // Act
  fetcher->fetch(uri_, client, secret, code, callback, receiver);
}

} // namespace
} // namespace Oidc
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
