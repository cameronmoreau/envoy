#include <chrono>
#include <thread>

#include "common/http/message_impl.h"
#include "common/protobuf/utility.h"

#include "extensions/filters/http/common/fetcher.h"

#include "test/mocks/http/mocks.h"
#include "test/mocks/server/mocks.h"
#include "test/test_common/utility.h"

using ::envoy::api::v2::core::HttpUri;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Common {
namespace {

const std::string Uri = R"(
uri: https://host/path
cluster: cluster
timeout:
  seconds: 5
)";

class FetcherTest : public ::testing::Test {
 public:
  void SetUp() { MessageUtil::loadFromYaml(Uri, uri_); }
  HttpUri uri_;
  testing::NiceMock<Server::Configuration::MockFactoryContext> mock_factory_ctx_;
};

// A mock HTTP upstream with response body.
class MockUpstream {
 public:
  MockUpstream(Upstream::MockClusterManager& mock_cm, const std::string& status,
               const std::string& content_type,
               const std::string& response_body)
      : request_(&mock_cm.async_client_), status_(status), content_type_(content_type), response_body_(response_body) {
    ON_CALL(mock_cm.async_client_, send_(testing::_, testing::_, testing::_))
        .WillByDefault(testing::Invoke([this](Http::MessagePtr&, Http::AsyncClient::Callbacks& cb,
                                              const absl::optional<std::chrono::milliseconds>&)
                                           -> Http::AsyncClient::Request* {
          Http::MessagePtr response_message(new Http::ResponseMessageImpl(
              Http::HeaderMapPtr{new Http::TestHeaderMapImpl{{":status", status_}, {"content-type", content_type_}}}));
          if (response_body_.length()) {
            response_message->body().reset(new Buffer::OwnedImpl(response_body_));
          } else {
            response_message->body().reset(nullptr);
          }
          cb.onSuccess(std::move(response_message));
          return &request_;
        }));
  }

  MockUpstream(Upstream::MockClusterManager& mock_cm, Http::MockAsyncClientRequest* request)
      : request_(&mock_cm.async_client_) {
    ON_CALL(mock_cm.async_client_, send_(testing::_, testing::_, testing::_))
        .WillByDefault(testing::Return(request));
  }

 private:
  Http::MockAsyncClientRequest request_;
  std::string status_;
  std::string content_type_;
  std::string response_body_;
};

class MockReceiver : public Fetcher::Receiver {
 public:
  // GoogleMock does not support r-value references. To get around this we use
  // an intermediate.
  void onFetchSuccess(Buffer::InstancePtr&& body) override {
    onFetchSuccessImpl(body.get());
  }
  MOCK_METHOD1(onFetchSuccessImpl, void(Buffer::Instance* body));
  MOCK_METHOD1(onFetchFailure, void(Failure reason));
};

TEST_F(FetcherTest, TestGetSuccess) {
  // Setup
  MockUpstream mock_response(mock_factory_ctx_.cluster_manager_, "200", "application/json", "{}");
  MockReceiver receiver;
  std::unique_ptr<Fetcher> fetcher(Fetcher::create(mock_factory_ctx_.cluster_manager_));
  EXPECT_TRUE(fetcher != nullptr);
  EXPECT_CALL(receiver, onFetchSuccessImpl(testing::_)).Times(1);
  EXPECT_CALL(receiver, onFetchFailure(testing::_)).Times(0);

  // Act
  fetcher->fetch(uri_, Http::Headers::get().MethodValues.Get, Http::Headers::get().ContentTypeValues.Json, "", receiver);
}

TEST_F(FetcherTest, TestPostSuccess) {
  // Setup
  MockUpstream mock_response(mock_factory_ctx_.cluster_manager_, "200", "application/json", "{}");
  MockReceiver receiver;
  std::unique_ptr<Fetcher> fetcher(Fetcher::create(mock_factory_ctx_.cluster_manager_));
  EXPECT_TRUE(fetcher != nullptr);
  EXPECT_CALL(receiver, onFetchSuccessImpl(testing::_)).Times(1);
  EXPECT_CALL(receiver, onFetchFailure(testing::_)).Times(0);

  // Act
  fetcher->fetch(uri_, Http::Headers::get().MethodValues.Post, Http::Headers::get().ContentTypeValues.Json, "", receiver);
}

TEST_F(FetcherTest, TestMissingBody) {
  // Setup
  MockUpstream mock_response(mock_factory_ctx_.cluster_manager_, "200", Http::Headers::get().ContentTypeValues.Json, "");
  MockReceiver receiver;
  std::unique_ptr<Fetcher> fetcher(Fetcher::create(mock_factory_ctx_.cluster_manager_));
  EXPECT_TRUE(fetcher != nullptr);
  EXPECT_CALL(receiver, onFetchSuccessImpl(testing::_)).Times(0);
  EXPECT_CALL(receiver, onFetchFailure(Failure::InvalidData)).Times(1);

  // Act
  fetcher->fetch(uri_, Http::Headers::get().MethodValues.Get, Http::Headers::get().ContentTypeValues.Json, "", receiver);
}

TEST_F(FetcherTest, TestGet400) {
  // Setup
  MockUpstream mock_response(mock_factory_ctx_.cluster_manager_, "400", "application/json", "invalid");
  MockReceiver receiver;
  std::unique_ptr<Fetcher> fetcher(Fetcher::create(mock_factory_ctx_.cluster_manager_));
  EXPECT_TRUE(fetcher != nullptr);
  EXPECT_CALL(receiver, onFetchSuccessImpl(testing::_)).Times(0);
  EXPECT_CALL(receiver, onFetchFailure(Failure::Network)).Times(1);

  // Act
  fetcher->fetch(uri_, Http::Headers::get().MethodValues.Get, Http::Headers::get().ContentTypeValues.Json, "", receiver);
}

TEST_F(FetcherTest, TestUnexpectedContentType) {
  // Setup
  MockUpstream mock_response(mock_factory_ctx_.cluster_manager_, "200", "xml", "");
  MockReceiver receiver;
  std::unique_ptr<Fetcher> fetcher(Fetcher::create(mock_factory_ctx_.cluster_manager_));
  EXPECT_TRUE(fetcher != nullptr);
  EXPECT_CALL(receiver, onFetchSuccessImpl(testing::_)).Times(0);
  EXPECT_CALL(receiver, onFetchFailure(Failure::InvalidData)).Times(1);

  // Act
  fetcher->fetch(uri_, Http::Headers::get().MethodValues.Get, Http::Headers::get().ContentTypeValues.Json, "", receiver);
}

TEST_F(FetcherTest, TestPost200) {
  Http::MockAsyncClientRequest request(&(mock_factory_ctx_.cluster_manager_.async_client_));
  ON_CALL(mock_factory_ctx_.cluster_manager_.async_client_, send_(testing::_, testing::_, testing::_))
    .WillByDefault(testing::Invoke([this, &request](Http::MessagePtr& msg, Http::AsyncClient::Callbacks& cb,
                                          const absl::optional<std::chrono::milliseconds>&) -> Http::AsyncClient::Request* {
      EXPECT_STREQ(Http::Headers::get().MethodValues.Post.c_str(), msg->headers().Method()->value().c_str());
      EXPECT_STREQ("expected", msg->bodyAsString().c_str());
      Http::MessagePtr response_message(new Http::ResponseMessageImpl(
          Http::HeaderMapPtr{new Http::TestHeaderMapImpl{{":status", "200"}, {"content-type", Http::Headers::get().ContentTypeValues.Json}}}));
      response_message->body().reset(new Buffer::OwnedImpl("expected"));
      cb.onSuccess(std::move(response_message));
      return &request;
    }));

  MockReceiver receiver;
  std::unique_ptr<Fetcher> fetcher(Fetcher::create(mock_factory_ctx_.cluster_manager_));
  EXPECT_TRUE(fetcher != nullptr);
  EXPECT_CALL(request, cancel()).Times(0);
  EXPECT_CALL(receiver, onFetchSuccessImpl(testing::_)).Times(1);
  EXPECT_CALL(receiver, onFetchFailure(testing::_)).Times(0);

  // Act
  fetcher->fetch(uri_, Http::Headers::get().MethodValues.Post, Http::Headers::get().ContentTypeValues.Json, "expected", receiver);
}

TEST_F(FetcherTest, TestCancel) {
  // Setup
  Http::MockAsyncClientRequest request(&(mock_factory_ctx_.cluster_manager_.async_client_));
  MockUpstream mock_response(mock_factory_ctx_.cluster_manager_, &request);
  MockReceiver receiver;
  std::unique_ptr<Fetcher> fetcher(Fetcher::create(mock_factory_ctx_.cluster_manager_));
  EXPECT_TRUE(fetcher != nullptr);
  EXPECT_CALL(request, cancel()).Times(1);
  EXPECT_CALL(receiver, onFetchSuccessImpl(testing::_)).Times(0);
  EXPECT_CALL(receiver, onFetchFailure(testing::_)).Times(0);
  
  // Act
  fetcher->fetch(uri_, Http::Headers::get().MethodValues.Get, Http::Headers::get().ContentTypeValues.Json, "", receiver);
  // Proper cancel
  fetcher->cancel();
  // Re-entrant cancel
  fetcher->cancel();
}

} // namespace
} // namespace Common
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
