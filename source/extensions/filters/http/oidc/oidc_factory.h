#pragma once

#include "envoy/config/filter/http/oidc/v1alpha/config.pb.h"
#include "envoy/server/filter_config.h"

#include "extensions/filters/http/common/factory_base.h"
#include "extensions/filters/http/oidc/state_store.h"
#include "extensions/filters/http/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace Oidc {

/**
 * Config registration for OpenID Connect filter.
 */
class FilterFactory
    : public Common::FactoryBase<::envoy::config::filter::http::oidc::v1alpha::OidcConfig>,
      public Logger::Loggable<Logger::Id::filter> {
public:
  FilterFactory() : FactoryBase(HttpFilterNames::get().OpenIDConnect) {
    state_store_ = StateStore::create();
  }

private:
  Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const ::envoy::config::filter::http::oidc::v1alpha::OidcConfig& proto_config,
      const std::string& stats_prefix, Server::Configuration::FactoryContext& context) override;

  StateStorePtr state_store_;
};

} // namespace Oidc
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
