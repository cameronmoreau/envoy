#pragma once

#include "envoy/config/filter/http/session_manager/v1alpha/config.pb.h"
#include "envoy/server/filter_config.h"

#include "extensions/filters/http/common/factory_base.h"
#include "extensions/filters/http/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace SessionManager {

/**
 * Config registration for session_manager filter.
 */
class FilterFactory : public Common::FactoryBase<
    ::envoy::config::filter::http::session_manager::v1alpha::SessionManager> {
 public:
  FilterFactory() : FactoryBase(HttpFilterNames::get().SessionManager) {}

 private:
  Http::FilterFactoryCb createFilterFactoryFromProtoTyped(
      const ::envoy::config::filter::http::session_manager::v2alpha::SessionManager& proto_config,
      const std::string& stats_prefix, Server::Configuration::FactoryContext& context) override;
};

} // namespace JwtAuthn
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
