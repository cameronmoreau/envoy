licenses(["notice"])  # Apache 2

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "pass_through_filter_lib",
    hdrs = ["pass_through_filter.h"],
    deps = [
        "//include/envoy/server:filter_config_interface",
    ],
)

envoy_cc_library(
    name = "empty_http_filter_config_lib",
    hdrs = ["empty_http_filter_config.h"],
    deps = [
        "//include/envoy/server:filter_config_interface",
    ],
)

envoy_cc_library(
    name = "factory_base_lib",
    hdrs = ["factory_base.h"],
    deps = [
        "//include/envoy/server:filter_config_interface",
    ],
)

envoy_cc_library(
    name = "jwks_fetcher_lib",
    srcs = ["jwks_fetcher.cc"],
    hdrs = ["jwks_fetcher.h"],
    external_deps = [
        "jwt_verify_lib",
    ],
    deps = [
        "//include/envoy/upstream:cluster_manager_interface",
        "//source/common/http:utility_lib",
        "//source/extensions/filters/http/common:fetcher_lib",
        "@envoy_api//envoy/api/v2/core:http_uri_cc",
    ],
)

envoy_cc_library(
    name = "fetcher_lib",
    srcs = ["fetcher.cc"],
    hdrs = ["fetcher.h"],
    deps = [
        "//include/envoy/upstream:cluster_manager_interface",
        "//source/common/http:utility_lib",
        "@envoy_api//envoy/api/v2/core:http_uri_cc",
    ],
)

envoy_cc_library(
    name = "session_manager_lib",
    srcs = ["session_manager.cc"],
    hdrs = ["session_manager.h"],
    external_deps = [
        "ssl",
    ],
    deps = [
        "//source/common/common:base64_lib",
    ],
)

envoy_cc_library(
    name = "state_store_lib",
    srcs = [
        "redis_conn.cc",
        "state_store.cc",
    ],
    hdrs = [
        "redis_conn.h",
        "state_store.h",
    ],
    external_deps = [
        "cpp_redis",
    ],
    deps = [
        "//include/envoy/common:time_interface",
        "//include/envoy/upstream:cluster_manager_interface",
        "//source/common/common:assert_lib",
        "//source/common/common:base64_lib",
        "//source/common/common:thread_lib",
        "//source/common/network:filter_lib",
        "@envoy_api//envoy/config/filter/http/oidc/v1alpha:oidc_cc",
    ],
)

envoy_cc_library(
    name = "token_encryptor_lib",
    srcs = [
        "gcm_encryptor.cc",
        "hkdf_deriver.cc",
        "token_encryptor.cc",
    ],
    hdrs = [
        "gcm_encryptor.h",
        "hkdf_deriver.h",
        "token_encryptor.h",
    ],
    external_deps = ["ssl"],
    deps = [
        "//source/common/common:assert_lib",
        "//source/common/common:minimal_logger_lib",
        "//source/extensions/filters/http/common:state_store_lib",
        "@envoy_api//envoy/config/filter/http/session_manager/v1alpha:session_manager_cc",
    ],
)
