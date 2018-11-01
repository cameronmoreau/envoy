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
    const std::string&, Server::Configuration::FactoryContext&) {
  auto sessionManagerPtr =
      Common::SessionManager::SessionManager::Create(proto_config.token_binding().secret());
  auto configPtr = std::make_shared<const ::envoy::config::filter::http::session_manager::v1alpha::SessionManager>(proto_config);
  return [configPtr, sessionManagerPtr](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamDecoderFilter(std::make_shared<SessionManagerFilter>(configPtr, sessionManagerPtr));
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
