#include "extensions/filters/http/session_manager/session_manager_factory.h"
#include "envoy/config/filter/http/session_manager/v1alpha/config.pb.validate.h"

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
const char exampleConfigWithPreamble[] = R"(
secret: Mb07unY1jd4h2s5wUSO9KJzhqjVTazXMWCp4OAiiGko=
token: __Secure-acme-session-cookie
binding: x-xsrf-token
forward_header:
  name: authorization
  preamble: Bearer
)";

const char exampleConfigNoPreamble[] = R"(
secret: Mb07unY1jd4h2s5wUSO9KJzhqjVTazXMWCp4OAiiGko=
token: __Secure-acme-session-cookie
binding: x-xsrf-token
forward_header:
  name: authorization
)";
} // namespace

class SessionManagerFactoryTest : public ::testing::Test {
 public:
  void SetUp() {
    factory_ = std::make_unique<FilterFactory>();
  }

  ::envoy::config::filter::http::session_manager::v1alpha::SessionManager proto_config_;
  NiceMock<Server::Configuration::MockFactoryContext> context_;
  std::unique_ptr<FilterFactory> factory_;
  //NiceMock<Http::MockStreamDecoderFilterCallbacks> filter_callbacks_;
  //Common::SessionManagerPtr session_manager_;
  //Common::MockSessionManager* session_manager_ptr_;
};

TEST_F(SessionManagerFactoryTest, createFilter) {
  MessageUtil::loadFromYamlAndValidate(exampleConfigWithPreamble, proto_config_);
  EXPECT_NO_THROW(factory_->createFilterFactoryFromProto(proto_config_, "prefix", context_));
};

} // namespace SessionManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
