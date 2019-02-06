licenses(["notice"])  # Apache 2

load(
    "//bazel:envoy_build_system.bzl",
    "envoy_cc_library",
    "envoy_package",
)

envoy_package()

envoy_cc_library(
    name = "config",
    srcs = ["session_manager_factory.cc"],
    hdrs = ["session_manager_factory.h"],
    deps = [
        "//include/envoy/registry",
        "//source/extensions/filters/http:well_known_names",
        "//source/extensions/filters/http/common:factory_base_lib",
        "//source/extensions/filters/http/session_manager:session_manager_filter_lib",
        "@envoy_api//envoy/config/filter/http/session_manager/v1alpha:session_manager_cc",
    ],
)

envoy_cc_library(
    name = "session_manager_filter_lib",
    srcs = ["session_manager_filter.cc"],
    hdrs = ["session_manager_filter.h"],
    deps = [
        "//include/envoy/http:filter_interface",
        "//include/envoy/upstream:cluster_manager_interface",
        "//source/common/http:utility_lib",
        "//source/extensions/filters/http/common:session_manager_lib",
        "//source/extensions/filters/http/common:state_store_lib",
        "//source/extensions/filters/http/common:token_encryptor_lib",
        "@envoy_api//envoy/config/filter/http/session_manager/v1alpha:session_manager_cc",
    ],
)
