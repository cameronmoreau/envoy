#include "extensions/filters/http/oidc/oidc_factory.h"

#include "envoy/config/filter/http/oidc/v1alpha/config.pb.validate.h"
#include "envoy/registry/registry.h"

#include "common/config/datasource.h"

#include "extensions/filters/http/oidc/oidc_filter.h"

#include "jwt_verify_lib/jwks.h"

using ::envoy::config::filter::http::oidc::v1alpha::OidcConfig;

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Oidc {
namespace {
/**
 * Validate inline jwks is valid
 */
void validateJwksConfig(const OidcConfig& proto_config) {
  for (const auto& it : proto_config.matches()) {
    const auto& idp = it.second.idp();
    const auto inline_jwks = Config::DataSource::read(idp.local_jwks(), true);
    if (!inline_jwks.empty()) {
      auto jwks_obj =
          ::google::jwt_verify::Jwks::createFrom(inline_jwks, ::google::jwt_verify::Jwks::JWKS);
      if (jwks_obj->getStatus() != ::google::jwt_verify::Status::Ok) {
        throw EnvoyException(
            fmt::format("IdP '{}' in oidc config has invalid local jwks: {}", it.first,
                        ::google::jwt_verify::getStatusString(jwks_obj->getStatus())));
      }
    }
  }
}
} // namespace

Http::FilterFactoryCb
FilterFactory::createFilterFactoryFromProtoTyped(const OidcConfig& proto_config, const std::string&,
                                                 Server::Configuration::FactoryContext& context) {
  ENVOY_LOG(trace, "{}", __func__);
  validateJwksConfig(proto_config);
  auto sharedConfig = std::make_shared<const OidcConfig>(proto_config);
  auto sessionManagerPtr =
      Common::SessionManager::SessionManager::Create(proto_config.binding().secret());
  return [this, &context, sharedConfig,
          sessionManagerPtr](Http::FilterChainFactoryCallbacks& callbacks) -> void {
    if (sharedConfig->state_store().store_type() ==
        ::envoy::config::filter::http::oidc::v1alpha::StateStore::IN_MEMORY) {
      callbacks.addStreamDecoderFilter(std::make_shared<OidcFilter>(
          context.clusterManager(), sessionManagerPtr, sharedConfig, Common::JwksFetcher::create,
          context.dispatcher().timeSystem(), state_store_));
    } else {
      callbacks.addStreamDecoderFilter(std::make_shared<OidcFilter>(
          context.clusterManager(), sessionManagerPtr, sharedConfig, Common::JwksFetcher::create,
          context.dispatcher().timeSystem()));
    }
  };
}

/**
 * Static registration for this OpenID Connect filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<FilterFactory, Server::Configuration::NamedHttpFilterConfigFactory>
    register_;

} // namespace Oidc
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
