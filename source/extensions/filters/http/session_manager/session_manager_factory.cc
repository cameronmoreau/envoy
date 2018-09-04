#include "extensions/filters/http/session_manager/session_manager_factory.h"

#include "envoy/config/filter/http/session_manager/v1alpha/config.pb.validate.h"
#include "envoy/registry/registry.h"

#include "extensions/filters/http/session_manager/filter.h"
#include "extensions/filters/http/common/session_manager.h"

using ::envoy::config::filter::http::session_manager::v1alpha::SessionManager;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace SessionManager {

Http::FilterFactoryCb
FilterFactory::createFilterFactoryFromProtoTyped(const SessionManager& proto_config,
                                                 const std::string& prefix,
                                                 Server::Configuration::FactoryContext& context) {
  auto sessionManagerPtr = Common::SessionManager::SessionManager::Create(proto_config.getSecret());
  return [context, sessionManagerPtr](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamDecoderFilter(std::make_shared<SessionManagerFilter>(
        context->cm(), sessionManagerPtr));
  };
}

/**
 * Static registration for this jwt_authn filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<FilterFactory, Server::Configuration::NamedHttpFilterConfigFactory>
    register_;

} // namespace JwtAuthn
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
