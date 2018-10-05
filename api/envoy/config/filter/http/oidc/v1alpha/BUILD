licenses(["notice"])  # Apache 2

load("//bazel:api_build_system.bzl", "api_proto_library_internal")

api_proto_library_internal(
    name = "oidc",
    srcs = ["config.proto"],
    deps = [
        "//envoy/api/v2/core:http_uri",
        "//envoy/config/filter/http/session_manager/v1alpha:session_manager",
    ],
)
