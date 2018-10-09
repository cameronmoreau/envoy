#include "envoy/config/filter/http/oidc/v1alpha/config.pb.validate.h"
#include "envoy/registry/registry.h"

#include "extensions/filters/http/oidc/oidc_factory.h"
#include "extensions/filters/http/oidc/oidc_filter.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Oidc {
namespace {

} // namespace

Http::FilterFactoryCb FilterFactory::createFilterFactoryFromProtoTyped(
    const ::envoy::config::filter::http::oidc::v1alpha::OidcConfig& proto_config,
    const std::string&, Server::Configuration::FactoryContext& context) {
  auto sharedConfig = std::make_shared<const ::envoy::config::filter::http::oidc::v1alpha::OidcConfig>(proto_config);
  auto sessionManagerPtr =
      Common::SessionManager::SessionManager::Create(proto_config.binding().secret());
  return [this, &context, sharedConfig, sessionManagerPtr](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    callbacks.addStreamDecoderFilter(std::make_shared<OidcFilter>(
        context.clusterManager(), sessionManagerPtr, state_store_, sharedConfig, Common::JwksFetcher::create));
  };
}

/**
 * Static registration for this OpenID Connect filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<FilterFactory, Server::Configuration::NamedHttpFilterConfigFactory>
    register_;

} // namespace SessionManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
