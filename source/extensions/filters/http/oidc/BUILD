licenses(["notice"])  # Apache 2

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "state_store_lib",
    srcs = ["state_store.cc"],
    hdrs = ["state_store.h"],
    external_deps = [
        "ssl",
    ],
    deps = [
        "//source/common/common:assert_lib",
        "//source/common/common:base64_lib",
        "//source/common/common:thread_lib",
    ],
)

envoy_cc_library(
    name = "oidc_filter_lib",
    srcs = ["oidc_filter.cc"],
    hdrs = ["oidc_filter.h"],
    external_deps = [
        "jwt_verify_lib",
    ],
    deps = [
        "//include/envoy/http:filter_interface",
        "//include/envoy/upstream:cluster_manager_interface",
        "//source/common/common:enum_to_int",
        "//source/common/common:minimal_logger_lib",
        "//source/common/http:codes_lib",
        "//source/extensions/filters/http/common:jwks_fetcher_lib",
        "//source/extensions/filters/http/common:session_manager_lib",
        "//source/extensions/filters/http/oidc:state_store_lib",
        "@envoy_api//envoy/api/v2/core:http_uri_cc",
        "@envoy_api//envoy/config/filter/http/oidc/v1alpha:oidc_cc",
    ],
)

envoy_cc_library(
    name = "config",
    srcs = ["oidc_factory.cc"],
    hdrs = ["oidc_factory.h"],
    deps = [
        "//include/envoy/registry",
        "//source/extensions/filters/http:well_known_names",
        "//source/extensions/filters/http/common:factory_base_lib",
        "//source/extensions/filters/http/oidc:oidc_filter_lib",
        "@envoy_api//envoy/config/filter/http/oidc/v1alpha:oidc_cc",
    ],
)
