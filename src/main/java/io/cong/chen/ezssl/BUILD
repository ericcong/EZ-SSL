package(default_visibility = ["//visibility:public"])

java_library(
    name = "abstract_ssl_builder",
    srcs = ["AbstractSSLBuilder.java"],
)

java_library(
    name = "ssl_server_socket_builder",
    srcs = ["SSLServerSocketBuilder.java"],
    deps = [
        ":abstract_ssl_builder",
    ],
)

java_library(
    name = "ssl_socket_builder",
    srcs = ["SSLSocketBuilder.java"],
    deps = [
        ":abstract_ssl_builder",
    ],
)

java_library(
    name = "ezssl",
    srcs = glob(["*.java"]),
)
