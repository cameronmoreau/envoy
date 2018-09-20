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
    deps = [
        "//source/common/common:assert_lib",
        "//source/common/common:base64_lib",
        "//source/common/common:thread_lib",
    ],
)
