#pragma once

#include <mutex>
#include <string>

#include "envoy/http/filter.h"
#include "envoy/upstream/cluster_manager.h"

#include "common/common/logger.h"

#include "src/envoy/utils/session_manager.h"

namespace Envoy {
namespace Http {
class XsrfFilter : public StreamDecoderFilter, public Logger::Loggable<Logger::Id::filter> {
public:
  XsrfFilter(Upstream::ClusterManager& cluster_manager,
             Utils::SessionManager::SessionManagerPtr session_manager);

  ~XsrfFilter();

  // Http::StreamFilterBase
  void onDestroy() override;
  // Http::StreamDecoderFilter
  /* Entry point for decoding request headers. */
  FilterHeadersStatus decodeHeaders(HeaderMap& headers, bool) override;
  /* Entry point for decoding request data. */
  FilterDataStatus decodeData(Buffer::Instance&, bool) override;
  /* Entry point for decoding request headers. */
  FilterTrailersStatus decodeTrailers(HeaderMap&) override;
  /* Decoder configuration. */
  void setDecoderFilterCallbacks(StreamDecoderFilterCallbacks& callbacks) override;

private:
  Upstream::ClusterManager& cluster_manager_;
  Utils::SessionManager::SessionManagerPtr session_manager_;
  StreamDecoderFilterCallbacks* decoder_callbacks_;
};
} // namespace Http
} // namespace Envoy
