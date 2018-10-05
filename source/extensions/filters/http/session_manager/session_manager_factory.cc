#include "envoy/config/filter/http/session_manager/v1alpha/config.pb.validate.h"
#include "envoy/registry/registry.h"

#include "extensions/filters/http/session_manager/session_manager_factory.h"
#include "extensions/filters/http/session_manager/session_manager_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace SessionManager {

Http::FilterFactoryCb FilterFactory::createFilterFactoryFromProtoTyped(
    const ::envoy::config::filter::http::session_manager::v1alpha::SessionManager& proto_config,
    const std::string&, Server::Configuration::FactoryContext& context) {
  auto sessionManagerPtr =
      Common::SessionManager::SessionManager::Create(proto_config.token_binding().secret());
  return [&context, &proto_config,
          sessionManagerPtr](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamDecoderFilter(std::make_shared<SessionManagerFilter>(
        context.clusterManager(), proto_config, sessionManagerPtr));
  };
}

/**
 * Static registration for this SessionManager filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<FilterFactory, Server::Configuration::NamedHttpFilterConfigFactory>
    register_;

} // namespace SessionManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
