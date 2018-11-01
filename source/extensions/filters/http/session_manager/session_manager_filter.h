#pragma once

#include <string>

#include "envoy/config/filter/http/session_manager/v1alpha/config.pb.h"
#include "envoy/http/filter.h"
#include "envoy/upstream/cluster_manager.h"

#include "common/common/logger.h"

#include "extensions/filters/http/common/session_manager.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace SessionManager {

class SessionManagerFilter : public Http::StreamDecoderFilter,
                             public Logger::Loggable<Logger::Id::filter> {
public:
  SessionManagerFilter(
      std::shared_ptr<const ::envoy::config::filter::http::session_manager::v1alpha::SessionManager> config,
      Common::SessionManagerPtr session_manager);

  ~SessionManagerFilter();

  // Http::StreamFilterBase
  void onDestroy() override;
  // Http::StreamDecoderFilter
  /* Entry point for decoding request headers. */
  Http::FilterHeadersStatus decodeHeaders(Http::HeaderMap& headers, bool) override;
  /* Entry point for decoding request data. */
  Http::FilterDataStatus decodeData(Buffer::Instance&, bool) override;
  /* Entry point for decoding request headers. */
  Http::FilterTrailersStatus decodeTrailers(Http::HeaderMap&) override;
  /* Decoder configuration. */
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override;

private:
  Common::SessionManagerPtr session_manager_;
  std::shared_ptr<const ::envoy::config::filter::http::session_manager::v1alpha::SessionManager> config_;
  Http::StreamDecoderFilterCallbacks* decoder_callbacks_ = nullptr;

  /**
   * Encode the given token according to the configuration.
   * @param headers HTTP headers to encode the token into.
   * @param token the token.
   */
  void encodeToken(Http::HeaderMap& headers, const std::string& token);
};
} // namespace SessionManager
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
