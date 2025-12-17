using Workerd = import "/workerd/workerd.capnp";

const config :Workerd.Config = (
  services = [
    (name = "main", worker = .proxyWorker),
  ],

  sockets = [
    # 占位符，将在构建阶段被替换
    ( name = "http", address = "*:8080", http = (), service = "main" )
  ]
);

const proxyWorker :Workerd.Worker = (
  compatibilityDate = "2025-09-06",
  globalOutbound = "internet",
  
  modules = [
    (name = "worker", esModule = embed "dist/index.js")
  ],

  bindings = [
    (name = "ENVIRONMENT", text = "production"),
    (name = "PASSWORD", fromEnvironment = "PASSWORD"),
    (name = "PROXY_HOSTNAME", fromEnvironment = "PROXY_HOSTNAME"),
    (name = "PROXY_PROTOCOL", fromEnvironment = "PROXY_PROTOCOL"),
    (name = "PROXY_RESOURCE_DOMAINS", fromEnvironment = "PROXY_RESOURCE_DOMAINS"),
    (name = "PROXY_DOMAINS", fromEnvironment = "PROXY_DOMAINS"),
    (name = "WECHAT_CHECK_FILE_NAME", fromEnvironment = "WECHAT_CHECK_FILE_NAME"),
    (name = "WECHAT_CHECK_FILE_CONTENT", fromEnvironment = "WECHAT_CHECK_FILE_CONTENT"),
    (name = "WECHAT_CHECK_FILE_MODIFY_TIME", fromEnvironment = "WECHAT_CHECK_FILE_MODIFY_TIME")

  ]
);
