local kong_default_conf = require "kong.templates.kong_defaults"
local openssl_pkey = require "resty.openssl.pkey"
local pl_stringio = require "pl.stringio"
local pl_stringx = require "pl.stringx"
local constants = require "kong.constants"
local listeners = require "kong.conf_loader.listeners"
local pl_pretty = require "pl.pretty"
local pl_config = require "pl.config"
local pl_file = require "pl.file"
local pl_path = require "pl.path"
local tablex = require "pl.tablex"
local utils = require "kong.tools.utils"
local log = require "kong.cmd.utils.log"
local env = require "kong.cmd.utils.env"
local ffi = require "ffi"


local fmt = string.format
local concat = table.concat
local C = ffi.C

ffi.cdef([[
  struct group *getgrnam(const char *name);
  struct passwd *getpwnam(const char *name);
]])

local cipher_suites = {
                   modern = {
                protocols = "TLSv1.3",
                  ciphers = nil,   -- all TLSv1.3 ciphers are considered safe
    prefer_server_ciphers = "off", -- as all are safe, let client choose
  },
             intermediate = {
                protocols = "TLSv1.2 TLSv1.3",
                  ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:"
                         .. "ECDHE-RSA-AES128-GCM-SHA256:"
                         .. "ECDHE-ECDSA-AES256-GCM-SHA384:"
                         .. "ECDHE-RSA-AES256-GCM-SHA384:"
                         .. "ECDHE-ECDSA-CHACHA20-POLY1305:"
                         .. "ECDHE-RSA-CHACHA20-POLY1305:"
                         .. "DHE-RSA-AES128-GCM-SHA256:"
                         .. "DHE-RSA-AES256-GCM-SHA384",
                 dhparams = "ffdhe2048",
    prefer_server_ciphers = "off",
  },
                      old = {
                protocols = "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3",
                  ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:"
                         .. "ECDHE-RSA-AES128-GCM-SHA256:"
                         .. "ECDHE-ECDSA-AES256-GCM-SHA384:"
                         .. "ECDHE-RSA-AES256-GCM-SHA384:"
                         .. "ECDHE-ECDSA-CHACHA20-POLY1305:"
                         .. "ECDHE-RSA-CHACHA20-POLY1305:"
                         .. "DHE-RSA-AES128-GCM-SHA256:"
                         .. "DHE-RSA-AES256-GCM-SHA384:"
                         .. "DHE-RSA-CHACHA20-POLY1305:"
                         .. "ECDHE-ECDSA-AES128-SHA256:"
                         .. "ECDHE-RSA-AES128-SHA256:"
                         .. "ECDHE-ECDSA-AES128-SHA:"
                         .. "ECDHE-RSA-AES128-SHA:"
                         .. "ECDHE-ECDSA-AES256-SHA384:"
                         .. "ECDHE-RSA-AES256-SHA384:"
                         .. "ECDHE-ECDSA-AES256-SHA:"
                         .. "ECDHE-RSA-AES256-SHA:"
                         .. "DHE-RSA-AES128-SHA256:"
                         .. "DHE-RSA-AES256-SHA256:"
                         .. "AES128-GCM-SHA256:"
                         .. "AES256-GCM-SHA384:"
                         .. "AES128-SHA256:"
                         .. "AES256-SHA256:"
                         .. "AES128-SHA:"
                         .. "AES256-SHA:"
                         .. "DES-CBC3-SHA",
    prefer_server_ciphers = "on",
  }
}

local DEFAULT_PATHS = {
  "/etc/kong/kong.conf",
  "/etc/kong.conf",
}

local HEADERS = constants.HEADERS
local HEADER_KEY_TO_NAME = {
  ["server_tokens"] = "server_tokens",
  ["latency_tokens"] = "latency_tokens",
  [string.lower(HEADERS.VIA)] = HEADERS.VIA,
  [string.lower(HEADERS.SERVER)] = HEADERS.SERVER,
  [string.lower(HEADERS.PROXY_LATENCY)] = HEADERS.PROXY_LATENCY,
  [string.lower(HEADERS.RESPONSE_LATENCY)] = HEADERS.RESPONSE_LATENCY,
  [string.lower(HEADERS.ADMIN_LATENCY)] = HEADERS.ADMIN_LATENCY,
  [string.lower(HEADERS.UPSTREAM_LATENCY)] = HEADERS.UPSTREAM_LATENCY,
  [string.lower(HEADERS.UPSTREAM_STATUS)] = HEADERS.UPSTREAM_STATUS,
}

local EMPTY = {}

local DYNAMIC_KEY_NAMESPACES = {
  {
    injected_conf_name = "nginx_main_directives",
    prefix = "nginx_main_",
    ignore = EMPTY,
  },
  {
    injected_conf_name = "nginx_events_directives",
    prefix = "nginx_events_",
    ignore = EMPTY,
  },
  {
    injected_conf_name = "nginx_http_directives",
    prefix = "nginx_http_",
    ignore = {
      upstream_keepalive          = true,
      upstream_keepalive_timeout  = true,
      upstream_keepalive_requests = true,
    },
  },
  {
    injected_conf_name = "nginx_upstream_directives",
    prefix = "nginx_upstream_",
    ignore = EMPTY,
  },
  {
    injected_conf_name = "nginx_proxy_directives",
    prefix = "nginx_proxy_",
    ignore = EMPTY,
  },
  {
    injected_conf_name = "nginx_status_directives",
    prefix = "nginx_status_",
    ignore = EMPTY,
  },
  {
    injected_conf_name = "nginx_admin_directives",
    prefix = "nginx_admin_",
    ignore = EMPTY,
  },
  {
    injected_conf_name = "nginx_stream_directives",
    prefix = "nginx_stream_",
    ignore = EMPTY,
  },
  {
    injected_conf_name = "nginx_supstream_directives",
    prefix = "nginx_supstream_",
    ignore = EMPTY,
  },
  {
    injected_conf_name = "nginx_sproxy_directives",
    prefix = "nginx_sproxy_",
    ignore = EMPTY,
  },
  {
    prefix = "pluginserver_",
    ignore = EMPTY,
  },
}

local DEPRECATED_DYNAMIC_KEY_NAMESPACES = {
  {
    injected_conf_name = "nginx_upstream_directives",
    previous_conf_name = "nginx_http_upstream_directives",
  },
  {
    injected_conf_name = "nginx_status_directives",
    previous_conf_name = "nginx_http_status_directives",
  },
}

local PREFIX_PATHS = {
  nginx_pid = {"pids", "nginx.pid"},
  nginx_err_logs = {"logs", "error.log"},
  nginx_acc_logs = {"logs", "access.log"},
  admin_acc_logs = {"logs", "admin_access.log"},
  nginx_conf = {"nginx.conf"},
  nginx_kong_conf = {"nginx-kong.conf"},
  nginx_kong_stream_conf = {"nginx-kong-stream.conf"},

  kong_env = {".kong_env"},

  ssl_cert_csr_default = {"ssl", "kong-default.csr"},
  ssl_cert_default = {"ssl", "kong-default.crt"},
  ssl_cert_key_default = {"ssl", "kong-default.key"},
  ssl_cert_default_ecdsa = {"ssl", "kong-default-ecdsa.crt"},
  ssl_cert_key_default_ecdsa = {"ssl", "kong-default-ecdsa.key"},

  client_ssl_cert_default = {"ssl", "kong-default.crt"},
  client_ssl_cert_key_default = {"ssl", "kong-default.key"},

  admin_ssl_cert_default = {"ssl", "admin-kong-default.crt"},
  admin_ssl_cert_key_default = {"ssl", "admin-kong-default.key"},
  admin_ssl_cert_default_ecdsa = {"ssl", "admin-kong-default-ecdsa.crt"},
  admin_ssl_cert_key_default_ecdsa = {"ssl", "admin-kong-default-ecdsa.key"},

  status_ssl_cert_default = {"ssl", "status-kong-default.crt"},
  status_ssl_cert_key_default = {"ssl", "status-kong-default.key"},
  status_ssl_cert_default_ecdsa = {"ssl", "status-kong-default-ecdsa.crt"},
  status_ssl_cert_key_default_ecdsa = {"ssl", "status-kong-default-ecdsa.key"},
}

local function is_predefined_dhgroup(group)
  if type(group) ~= "string" then
    return false
  end

  return not not openssl_pkey.paramgen({
    type = "DH",
    group = group,
  })
end

local function upstream_keepalive_deprecated_properties(conf)
  if conf.nginx_upstream_keepalive == nil then
    if conf.nginx_http_upstream_keepalive ~= nil then
      conf.nginx_upstream_keepalive = conf.nginx_http_upstream_keepalive
    end
  end

  if conf.nginx_upstream_keepalive == nil then
    if conf.upstream_keepalive ~= nil then
      if conf.upstream_keepalive == 0 then
        conf.nginx_upstream_keepalive = "NONE"
        conf.nginx_http_upstream_keepalive = "NONE"
      else
        conf.nginx_upstream_keepalive = tostring(conf.upstream_keepalive)
        conf.nginx_http_upstream_keepalive = tostring(conf.upstream_keepalive)
      end
    end
  end

  -- nginx_upstream_keepalive -> upstream_keepalive_pool_size
  if conf.upstream_keepalive_pool_size == nil then
    if conf.nginx_upstream_keepalive ~= nil then
      if conf.nginx_upstream_keepalive == "NONE" then
        conf.upstream_keepalive_pool_size = 0

      else
        conf.upstream_keepalive_pool_size = tonumber(conf.nginx_upstream_keepalive)
      end
    end
  end

  -- nginx_http_upstream_keepalive_requests -> nginx_upstream_keepalive_requests
  if conf.nginx_upstream_keepalive_requests == nil then
    conf.nginx_upstream_keepalive_requests = conf.nginx_http_upstream_keepalive_requests
  end

  -- nginx_upstream_keepalive_requests -> upstream_keepalive_max_requests
  if conf.upstream_keepalive_max_requests == nil
     and conf.nginx_upstream_keepalive_requests ~= nil
  then
    conf.upstream_keepalive_max_requests = tonumber(conf.nginx_upstream_keepalive_requests)
  end

  -- nginx_http_upstream_keepalive_timeout -> nginx_upstream_keepalive_timeout
  if conf.nginx_upstream_keepalive_timeout == nil then
    conf.nginx_upstream_keepalive_timeout = conf.nginx_http_upstream_keepalive_timeout
  end

  -- nginx_upstream_keepalive_timeout -> upstream_keepalive_idle_timeout
  if conf.upstream_keepalive_idle_timeout == nil
     and conf.nginx_upstream_keepalive_timeout ~= nil
  then
    conf.upstream_keepalive_idle_timeout =
      utils.nginx_conf_time_to_seconds(conf.nginx_upstream_keepalive_timeout)
  end
end

local CONF_INFERENCES = {
  -- forced string inferences (or else are retrieved as numbers)
  port_maps = { typ = "array" },
  proxy_listen = { typ = "array" },
  admin_listen = { typ = "array" },
  status_listen = { typ = "array" },
  stream_listen = { typ = "array" },
  cluster_listen = { typ = "array" },
  ssl_cert = { typ = "array" },
  ssl_cert_key = { typ = "array" },
  admin_ssl_cert = { typ = "array" },
  admin_ssl_cert_key = { typ = "array" },
  status_ssl_cert = { typ = "array" },
  status_ssl_cert_key = { typ = "array" },
  db_update_frequency = {  typ = "number"  },
  db_update_propagation = {  typ = "number"  },
  db_cache_ttl = {  typ = "number"  },
  db_cache_neg_ttl = {  typ = "number"  },
  db_resurrect_ttl = {  typ = "number"  },
  db_cache_warmup_entities = { typ = "array" },
  nginx_user = {
    typ = "string",
    alias = {
      replacement = "nginx_main_user",
    }
  },
  nginx_daemon = {
    typ = "ngx_boolean",
    alias = {
      replacement = "nginx_main_daemon",
    }
  },
  nginx_worker_processes = {
    typ = "string",
    alias = {
      replacement = "nginx_main_worker_processes",
    },
  },

  -- TODO: remove since deprecated in 1.3
  upstream_keepalive = {
    typ = "number",
    deprecated = {
      replacement = "upstream_keepalive_pool_size",
      alias = upstream_keepalive_deprecated_properties,
    }
  },

  -- TODO: remove since deprecated in 2.0
  nginx_http_upstream_keepalive = {
    typ = "string",
    deprecated = {
      replacement = "upstream_keepalive_pool_size",
      alias = upstream_keepalive_deprecated_properties,
    }
  },
  nginx_http_upstream_keepalive_requests = {
    typ = "string",
    deprecated = {
      replacement = "upstream_keepalive_max_requests",
      alias = upstream_keepalive_deprecated_properties,
    }
  },
  nginx_http_upstream_keepalive_timeout = {
    typ = "string",
    deprecated = {
      replacement = "upstream_keepalive_idle_timeout",
      alias = upstream_keepalive_deprecated_properties,
    }
  },

  -- TODO: remove since deprecated in 2.1
  nginx_upstream_keepalive = {
    typ = "string",
    deprecated = {
      replacement = "upstream_keepalive_pool_size",
      alias = upstream_keepalive_deprecated_properties,
    }
  },
  nginx_upstream_keepalive_requests = {
    typ = "string",
    deprecated = {
      replacement = "upstream_keepalive_max_requests",
      alias = upstream_keepalive_deprecated_properties,
    }
  },
  nginx_upstream_keepalive_timeout = {
    typ = "string",
    deprecated = {
      replacement = "upstream_keepalive_idle_timeout",
      alias = upstream_keepalive_deprecated_properties,
    }
  },

  upstream_keepalive_pool_size = { typ = "number" },
  upstream_keepalive_max_requests = { typ = "number" },
  upstream_keepalive_idle_timeout = { typ = "number" },

  headers = { typ = "array" },
  trusted_ips = { typ = "array" },
  real_ip_header = {
    typ = "string",
    alias = {
      replacement = "nginx_proxy_real_ip_header",
    }
  },
  real_ip_recursive = {
    typ = "ngx_boolean",
    alias = {
      replacement = "nginx_proxy_real_ip_recursive",
    }
  },
  client_max_body_size = {
    typ = "string",
    deprecated = {
      replacement = "nginx_http_client_max_body_size",
      alias = function(conf)
        if conf.nginx_http_client_max_body_size == nil then
          conf.nginx_http_client_max_body_size = conf.client_max_body_size
        end
      end,
    }
  },
  client_body_buffer_size = {
    typ = "string",
    deprecated = {
      replacement = "nginx_http_client_body_buffer_size",
      alias = function(conf)
        if conf.nginx_http_client_body_buffer_size == nil then
          conf.nginx_http_client_body_buffer_size = conf.client_body_buffer_size
        end
      end,
    }
  },
  error_default_type = { enum = {
                           "application/json",
                           "application/xml",
                           "text/html",
                           "text/plain",
                         }
                       },

  database = { enum = { "postgres", "cassandra", "off" }  },
  pg_port = { typ = "number" },
  pg_timeout = { typ = "number" },
  pg_password = { typ = "string" },
  pg_ssl = { typ = "boolean" },
  pg_ssl_verify = { typ = "boolean" },
  pg_max_concurrent_queries = { typ = "number" },
  pg_semaphore_timeout = { typ = "number" },

  pg_ro_port = { typ = "number" },
  pg_ro_timeout = { typ = "number" },
  pg_ro_password = { typ = "string" },
  pg_ro_ssl = { typ = "boolean" },
  pg_ro_ssl_verify = { typ = "boolean" },
  pg_ro_max_concurrent_queries = { typ = "number" },
  pg_ro_semaphore_timeout = { typ = "number" },

  cassandra_contact_points = { typ = "array" },
  cassandra_port = { typ = "number" },
  cassandra_password = { typ = "string" },
  cassandra_timeout = { typ = "number" },
  cassandra_ssl = { typ = "boolean" },
  cassandra_ssl_verify = { typ = "boolean" },
  cassandra_write_consistency = { enum = {
                                  "ALL",
                                  "EACH_QUORUM",
                                  "QUORUM",
                                  "LOCAL_QUORUM",
                                  "ONE",
                                  "TWO",
                                  "THREE",
                                  "LOCAL_ONE",
                                }
                              },
  cassandra_read_consistency = { enum = {
                                  "ALL",
                                  "EACH_QUORUM",
                                  "QUORUM",
                                  "LOCAL_QUORUM",
                                  "ONE",
                                  "TWO",
                                  "THREE",
                                  "LOCAL_ONE",
                                }
                              },
  cassandra_consistency = {
    typ = "string",
    deprecated = {
      replacement = "cassandra_write_consistency / cassandra_read_consistency",
      alias = function(conf)
        if conf.cassandra_write_consistency == nil then
          conf.cassandra_write_consistency = conf.cassandra_consistency
        end

        if conf.cassandra_read_consistency == nil then
          conf.cassandra_read_consistency = conf.cassandra_consistency
        end
      end,
    }
  },
  cassandra_lb_policy = { enum = {
                            "RoundRobin",
                            "RequestRoundRobin",
                            "DCAwareRoundRobin",
                            "RequestDCAwareRoundRobin",
                          }
                        },
  cassandra_local_datacenter = { typ = "string" },
  cassandra_refresh_frequency = { typ = "number" },
  cassandra_repl_strategy = { enum = {
                                "SimpleStrategy",
                                "NetworkTopologyStrategy",
                              }
                            },
  cassandra_repl_factor = { typ = "number" },
  cassandra_data_centers = { typ = "array" },
  cassandra_schema_consensus_timeout = { typ = "number" },

  dns_resolver = { typ = "array" },
  dns_hostsfile = { typ = "string" },
  dns_order = { typ = "array" },
  dns_valid_ttl = { typ = "number" },
  dns_stale_ttl = { typ = "number" },
  dns_not_found_ttl = { typ = "number" },
  dns_error_ttl = { typ = "number" },
  dns_no_sync = { typ = "boolean" },
  worker_consistency = { enum = { "strict", "eventual" } },
  router_consistency = {
    enum = { "strict", "eventual" },
    deprecated = {
      replacement = "worker_consistency",
      alias = function(conf)
        if conf.worker_consistency == nil and
           conf.router_consistency ~= nil then
          conf.worker_consistency = conf.router_consistency
        end
      end,
    }
  },
  worker_state_update_frequency = { typ = "number" },
  router_update_frequency = {
    typ = "number",
    deprecated = {
      replacement = "worker_state_update_frequency",
      alias = function(conf)
        if conf.worker_state_update_frequency == nil and
           conf.router_update_frequency ~= nil then
          conf.worker_state_update_frequency = conf.router_update_frequency
        end
      end,
    }
  },

  ssl_protocols = {
    typ = "string",
    directives = {
      "nginx_http_ssl_protocols",
      "nginx_stream_ssl_protocols",
    },
  },
  ssl_prefer_server_ciphers = {
    typ = "ngx_boolean",
    directives = {
      "nginx_http_ssl_prefer_server_ciphers",
      "nginx_stream_ssl_prefer_server_ciphers",
    },
  },
  ssl_dhparam = {
    typ = "string",
    directives = {
      "nginx_http_ssl_dhparam",
      "nginx_stream_ssl_dhparam",
    },
  },
  ssl_session_tickets = {
    typ = "ngx_boolean",
    directives = {
      "nginx_http_ssl_session_tickets",
      "nginx_stream_ssl_session_tickets",
    },
  },
  ssl_session_timeout = {
    typ = "string",
    directives = {
      "nginx_http_ssl_session_timeout",
      "nginx_stream_ssl_session_timeout",
    },
  },

  client_ssl = { typ = "boolean" },

  proxy_access_log = { typ = "string" },
  proxy_error_log = { typ = "string" },
  proxy_stream_access_log = { typ = "string" },
  proxy_stream_error_log = { typ = "string" },
  admin_access_log = { typ = "string" },
  admin_error_log = { typ = "string" },
  status_access_log = { typ = "string" },
  status_error_log = { typ = "string" },
  log_level = { enum = {
                  "debug",
                  "info",
                  "notice",
                  "warn",
                  "error",
                  "crit",
                  "alert",
                  "emerg",
                }
              },
  plugins = { typ = "array" },
  anonymous_reports = { typ = "boolean" },
  nginx_optimizations = {
    typ = "boolean",
    deprecated = { replacement = false }
  },

  lua_ssl_trusted_certificate = { typ = "array" },
  lua_ssl_verify_depth = { typ = "number" },
  lua_ssl_protocols = {
    typ = "string",
    directives = {
      "nginx_http_lua_ssl_protocols",
      "nginx_stream_lua_ssl_protocols",
    },
  },
  lua_socket_pool_size = { typ = "number" },

  role = { enum = { "data_plane", "control_plane", "traditional", }, },
  cluster_control_plane = { typ = "string", },
  cluster_cert = { typ = "string" },
  cluster_cert_key = { typ = "string" },
  cluster_mtls = { enum = { "shared", "pki" } },
  cluster_ca_cert = { typ = "string" },
  cluster_server_name = { typ = "string" },
  cluster_data_plane_purge_delay = { typ = "number" },
  cluster_ocsp = { enum = { "on", "off", "optional" } },

  kic = { typ = "boolean" },
  pluginserver_names = { typ = "array" },

  untrusted_lua = { enum = { "on", "off", "sandbox" } },
  untrusted_lua_sandbox_requires = { typ = "array" },
  untrusted_lua_sandbox_environment = { typ = "array" },
}

local CONF_SENSITIVE_PLACEHOLDER = "******"
local CONF_SENSITIVE = {
  pg_password = true,
  pg_ro_password = true,
  cassandra_password = true,
}

local typ_checks = {
  array = function(v) return type(v) == "table" end,
  string = function(v) return type(v) == "string" end,
  number = function(v) return type(v) == "number" end,
  boolean = function(v) return type(v) == "boolean" end,
  ngx_boolean = function(v) return v == "on" or v == "off" end,
}

local _nop_tostring_mt = {
  __tostring = function() return "" end,
}

local function check_and_infer(conf, opts)
  local errors = {}

  for k, value in pairs(conf) do
    local v_schema = CONF_INFERENCES[k] or {}
    local typ = v_schema.typ

    if type(value) == "string" then
      if not opts.from_kong_env then
        value = string.gsub(value, "[^\\]#.-$", "")
        value = string.gsub(value, "\\#", "#")
      end

      value = pl_stringx.strip(value)
    end

    if typ == "boolean" then
      value = value == true or value == "on" or value == "true"

    elseif typ == "ngx_boolean" then
      value = (value == "on" or value == true) and "on" or "off"

    elseif typ == "string" then
      value = tostring(value)

    elseif typ == "number" then
      value = tonumber(value)

    elseif typ == "array" and type(value) == "string" then
      value = setmetatable(pl_stringx.split(value, ","), nil)

      for i = 1, #value do
        value[i] = pl_stringx.strip(value[i])
      end
    end

    if value == "" then
      value = nil
    end

    typ = typ or "string"

    if value and not typ_checks[typ](value) then
      errors[#errors + 1] = fmt("%s is not a %s: '%s'", k, typ,
                                tostring(value))

    elseif v_schema.enum and not tablex.find(v_schema.enum, value) then
      errors[#errors + 1] = fmt("%s has an invalid value: '%s' (%s)", k,
                              tostring(value), concat(v_schema.enum, ", "))

    end

    conf[k] = value
  end

  -- custom validations

  conf.host_ports = {}
  if conf.port_maps then
    local MIN_PORT = 1
    local MAX_PORT = 65535

    for _, port_map in ipairs(conf.port_maps) do
      local colpos = string.find(port_map, ":", nil, true)
      if not colpos then
        errors[#errors + 1] = "invalid port mapping (`port_maps`): " .. port_map
      else
        local host_port_str = string.sub(port_map, 1, colpos - 1)
        local host_port_num = tonumber(host_port_str, 10)
        local kong_port_str = string.sub(port_map, colpos + 1)
        local kong_port_num = tonumber(kong_port_str, 10)

        if  (host_port_num and host_port_num >= MIN_PORT and host_port_num <= MAX_PORT)
        and (kong_port_num and kong_port_num >= MIN_PORT and kong_port_num <= MAX_PORT)
        then
            conf.host_ports[kong_port_num] = host_port_num
            conf.host_ports[kong_port_str] = host_port_num
        else
          errors[#errors + 1] = "invalid port mapping (`port_maps`): " .. port_map
        end
      end
    end
  end

  if conf.database == "cassandra" then
    error("cassandra")
  end

  for _, prefix in ipairs({ "proxy_", "admin_", "status_" }) do
    local listen = conf[prefix .. "listen"]

    local ssl_enabled = (concat(listen, ",") .. " "):find("%sssl[%s,]") ~= nil
    if not ssl_enabled and prefix == "proxy_" then
      ssl_enabled = (concat(conf.stream_listen, ",") .. " "):find("%sssl[%s,]") ~= nil
    end

    if prefix == "proxy_" then
      prefix = ""
    end

    if ssl_enabled then
      conf.ssl_enabled = true

      local ssl_cert = conf[prefix .. "ssl_cert"]
      local ssl_cert_key = conf[prefix .. "ssl_cert_key"]

      if #ssl_cert > 0 and #ssl_cert_key == 0 then
        errors[#errors + 1] = prefix .. "ssl_cert_key must be specified"

      elseif #ssl_cert_key > 0 and #ssl_cert == 0 then
        errors[#errors + 1] = prefix .. "ssl_cert must be specified"

      elseif #ssl_cert ~= #ssl_cert_key then
        errors[#errors + 1] = prefix .. "ssl_cert was specified " .. #ssl_cert .. " times while " ..
          prefix .. "ssl_cert_key was specified " .. #ssl_cert_key .. " times"
      end

      if ssl_cert then
        for _, cert in ipairs(ssl_cert) do
          if not pl_path.exists(cert) then
            errors[#errors + 1] = prefix .. "ssl_cert: no such file at " .. cert
          end
        end
      end

      if ssl_cert_key then
        for _, cert_key in ipairs(ssl_cert_key) do
          if not pl_path.exists(cert_key) then
            errors[#errors + 1] = prefix .. "ssl_cert_key: no such file at " .. cert_key
          end
        end
      end
    end
  end

  if conf.client_ssl then
    if conf.client_ssl_cert and not conf.client_ssl_cert_key then
      errors[#errors + 1] = "client_ssl_cert_key must be specified"

    elseif conf.client_ssl_cert_key and not conf.client_ssl_cert then
      errors[#errors + 1] = "client_ssl_cert must be specified"
    end

    if conf.client_ssl_cert and not pl_path.exists(conf.client_ssl_cert) then
      errors[#errors + 1] = "client_ssl_cert: no such file at " ..
                          conf.client_ssl_cert
    end

    if conf.client_ssl_cert_key and not pl_path.exists(conf.client_ssl_cert_key) then
      errors[#errors + 1] = "client_ssl_cert_key: no such file at " ..
                          conf.client_ssl_cert_key
    end
  end

  if conf.lua_ssl_trusted_certificate then
    local new_paths = {}

    for i, path in ipairs(conf.lua_ssl_trusted_certificate) do
      error("lua_ssl_trusted_certificate")
    end

    conf.lua_ssl_trusted_certificate = new_paths
  end

  if conf.ssl_cipher_suite ~= "custom" then
    local suite = cipher_suites[conf.ssl_cipher_suite]
    if suite then
      conf.ssl_ciphers = suite.ciphers
      conf.nginx_http_ssl_protocols = suite.protocols
      conf.nginx_http_ssl_prefer_server_ciphers = suite.prefer_server_ciphers
      conf.nginx_stream_ssl_protocols = suite.protocols
      conf.nginx_stream_ssl_prefer_server_ciphers = suite.prefer_server_ciphers

      if conf.ssl_cipher_suite ~= "old" then
        conf.ssl_dhparam = suite.dhparams
        conf.nginx_http_ssl_dhparam = suite.dhparams
        conf.nginx_stream_ssl_dhparam = suite.dhparams
      end

    else
      errors[#errors + 1] = "Undefined cipher suite " .. tostring(conf.ssl_cipher_suite)
    end
  end

  if conf.ssl_dhparam then
    if not is_predefined_dhgroup(conf.ssl_dhparam) and not pl_path.exists(conf.ssl_dhparam) then
      errors[#errors + 1] = "ssl_dhparam: no such file at " .. conf.ssl_dhparam
    end
  else
    for _, key in ipairs({ "nginx_http_ssl_dhparam", "nginx_stream_ssl_dhparam" }) do
      local file = conf[key]
      if file and not is_predefined_dhgroup(file) and not pl_path.exists(file) then
        errors[#errors + 1] = key .. ": no such file at " .. file
      end
    end
  end

  if conf.headers then
    for _, token in ipairs(conf.headers) do
      if token ~= "off" and not HEADER_KEY_TO_NAME[string.lower(token)] then
        errors[#errors + 1] = fmt("headers: invalid entry '%s'",
                                  tostring(token))
      end
    end
  end

  if conf.dns_resolver then
    for _, server in ipairs(conf.dns_resolver) do
      local dns = utils.normalize_ip(server)

      if not dns or dns.type == "name" then
        errors[#errors + 1] = "dns_resolver must be a comma separated list " ..
                              "in the form of IPv4/6 or IPv4/6:port, got '"  ..
                              server .. "'"
      end
    end
  end

  if conf.dns_hostsfile then
    if not pl_path.isfile(conf.dns_hostsfile) then
      errors[#errors + 1] = "dns_hostsfile: file does not exist"
    end
  end

  if conf.dns_order then
    local allowed = { LAST = true, A = true, CNAME = true, SRV = true }

    for _, name in ipairs(conf.dns_order) do
      if not allowed[name:upper()] then
        errors[#errors + 1] = fmt("dns_order: invalid entry '%s'",
                                  tostring(name))
      end
    end
  end

  if not conf.lua_package_cpath then
    conf.lua_package_cpath = ""
  end

  for _, address in ipairs(conf.trusted_ips) do
    if not utils.is_valid_ip_or_cidr(address) and address ~= "unix:" then
      errors[#errors + 1] = "trusted_ips must be a comma separated list in " ..
                            "the form of IPv4 or IPv6 address or CIDR "      ..
                            "block or 'unix:', got '" .. address .. "'"
    end
  end

  if conf.pg_max_concurrent_queries < 0 then
    errors[#errors + 1] = "pg_max_concurrent_queries must be greater than 0"
  end

  if conf.pg_max_concurrent_queries ~= math.floor(conf.pg_max_concurrent_queries) then
    errors[#errors + 1] = "pg_max_concurrent_queries must be an integer greater than 0"
  end

  if conf.pg_semaphore_timeout < 0 then
    errors[#errors + 1] = "pg_semaphore_timeout must be greater than 0"
  end

  if conf.pg_semaphore_timeout ~= math.floor(conf.pg_semaphore_timeout) then
    errors[#errors + 1] = "pg_semaphore_timeout must be an integer greater than 0"
  end

  if conf.pg_ro_max_concurrent_queries then
    if conf.pg_ro_max_concurrent_queries < 0 then
      errors[#errors + 1] = "pg_ro_max_concurrent_queries must be greater than 0"
    end

    if conf.pg_ro_max_concurrent_queries ~= math.floor(conf.pg_ro_max_concurrent_queries) then
      errors[#errors + 1] = "pg_ro_max_concurrent_queries must be an integer greater than 0"
    end
  end

  if conf.pg_ro_semaphore_timeout then
    if conf.pg_ro_semaphore_timeout < 0 then
      errors[#errors + 1] = "pg_ro_semaphore_timeout must be greater than 0"
    end

    if conf.pg_ro_semaphore_timeout ~= math.floor(conf.pg_ro_semaphore_timeout) then
      errors[#errors + 1] = "pg_ro_semaphore_timeout must be an integer greater than 0"
    end
  end

  if conf.worker_state_update_frequency <= 0 then
    errors[#errors + 1] = "worker_state_update_frequency must be greater than 0"
  end

  if conf.role == "control_plane" then
    error("control_plane")
  elseif conf.role == "data_plane" then
    error("data_plane")
  end

  if conf.cluster_data_plane_purge_delay < 60 then
    errors[#errors + 1] = "cluster_data_plane_purge_delay must be 60 or greater"
  end

  if conf.role == "control_plane" or conf.role == "data_plane" then
    error("control_plane or data_plane")
  end

  if conf.upstream_keepalive_pool_size < 0 then
    errors[#errors + 1] = "upstream_keepalive_pool_size must be 0 or greater"
  end

  if conf.upstream_keepalive_max_requests < 0 then
    errors[#errors + 1] = "upstream_keepalive_max_requests must be 0 or greater"
  end

  if conf.upstream_keepalive_idle_timeout < 0 then
    errors[#errors + 1] = "upstream_keepalive_idle_timeout must be 0 or greater"
  end

  return #errors == 0, errors[1], errors
end

local function overrides(k, default_v, opts, file_conf, arg_conf)
  opts = opts or {}

  local value
  local escape

  if file_conf and file_conf[k] == nil and not opts.no_defaults then
    value = default_v == "NONE" and "" or default_v
  else
    value = file_conf[k]
  end

  -- 如果defaults_only为true就不再找其他可能的值了
  if opts.defaults_only then
    return value, k
  end

  if not opts.from_kong_env then
    local env_name = "KONG_" .. string.upper(k)
    local env = os.getenv(env_name)
    if env ~= nil then
      local to_print = env

      if CONF_SENSITIVE[k] then
        to_print = CONF_SENSITIVE_PLACEHOLDER
      end

      log.debug('%s ENV found with "%s"', env_name, to_print)

      value = env
      escape = true
    end
  end

  if arg_conf and arg_conf[k] ~= nil then
    value = arg_conf[k]
    escape = true
  end

  -- escape是为了过滤#
  if escape and type(value) == "string" then
    repeat
      local s, n = string.gsub(value, [[([^\])#]], [[%1\#]])
      value = s
    until n == 0
  end

  return value, k
end

local function parse_nginx_directives(dyn_namespace, conf, injected_in_namespace)
  conf = conf or {}
  local directives = {}

  for k, v in pairs(conf) do
    if type(k) == "string" and not injected_in_namespace[k] then
      local directive = string.match(k, dyn_namespace.prefix .. "(.+)")
      if directive then
        if v ~= "NONE" and not dyn_namespace.ignore[directive] then
          table.insert(directives, { name = directive, value = v })
        end
        injected_in_namespace[k] = true
      end
    end
  end

  return directives
end

local function aliased_properties(conf)
  for property_name, v_schema in pairs(CONF_INFERENCES) do
    local alias = v_schema.alias

    if alias and conf[property_name] ~= nil and conf[alias.replacement] == nil then
      if alias.alias then
        conf[alias.replacement] = alias.alias(conf)
      else
        local value = conf[property_name]
        if type(value) == "boolean" then
          value = value and "on" or "off"
        end
        conf[alias.replacement] = tostring(value)
      end
    end
  end
end

local function deprecated_properties(conf, opts)
  for property_name, v_schema in pairs(CONF_INFERENCES) do
    local deprecated = v_schema.deprecated
    if deprecated and conf[property_name] ~= nil then
      if not opts.from_kong_env then
        if deprecated.replacement then
          log.warn("the '%s' configuration property is deprecated, use " ..
                     "'%s' instead", property_name, deprecated.replacement)
        else
          log.warn("the '%s' configuration property is deprecated",
                   property_name)
        end
      end

      if deprecated.alias then
        deprecated.alias(conf)
      end
    end
  end
end

local function dynamic_properties(conf)
  for property_name, v_schema in pairs(CONF_INFERENCES) do
    local value = conf[property_name]
    if value ~= nil then
      local directives = v_schema.directives
      if directives then
        for _, directive in ipairs(directives) do
          if not conf[directive] then
            if type(value) == "boolean" then
              value = value and "on" or "off"
            end
            conf[directive] = value
          end
        end
      end
    end
  end
end

local function load_config_file(path)
  assert(type(path) == "string")

  local f, err = pl_file.read(path)
  if not f then
    return nil, err
  end

  local s = pl_stringio.open(f)
  local conf, err = pl_config.read(s, {
    smart = false,
    list_delim = "_blank_"
  })
  s:close()
  if not conf then
    return nil, err
  end

  return conf
end

-- args.conf --conf
-- {prefix = args.prefix}
-- {starting = true}
local function load(path, custom_conf, opts)
  opts = opts or {}

  local s = pl_stringio.open(kong_default_conf)
  local defaults, err = pl_config.read(s, {
    smart = false,
    list_delim = "_blank_"
  })
  s:close()
  if not defaults then
    return nil, "could not load default conf: " .. err
  end

  -- Configuration file

  local from_file_conf = {}
  if path and not pl_path.exists(path) then
    return nil, "no file at: " .. path
  end

  if not path then
    for _, default_path in ipairs(DEFAULT_PATHS) do
      if pl_path.exists(default_path) then
        path = default_path
        break
      end

      log.verbose("no config file found at %s", default_path)
    end
  end

  if not path then
    log.verbose("no config file, skip loading")
  else
    log.verbose("reading config file at %s", path)
    from_file_conf = load_config_file(path)
  end

  -- merge and validation

  do
    local dynamic_keys = {}

    local function add_dynamic_keys(t)
      t = t or {}

--ssl_protocols = {
--  typ = "string",
--  directives = {
--    "nginx_http_ssl_protocols",
--    "nginx_stream_ssl_protocols",
--  },
--},
      for property_name, v_schema in pairs(CONF_INFERENCES) do
        local directives = v_schema.directives
        if directives then
          local v = t[property_name]
          if v then
            if type(v) == "boolean" then
              v = v and "on" or "off"
            end

            tostring(v)

            for _, directive in ipairs(directives) do
              dynamic_keys[directive] = true
              -- 以指令作为键，值为对应配置的值，放到conf里
              t[directive] = v
            end
          end
        end
      end
    end

    -- 将指令配置放到dynamic_keys中，值变成字符串
    local function find_dynamic_keys(dyn_prefix, t)
      t = t or {}

      for k, v in pairs(t) do
        local directive = string.match(k, "^(" .. dyn_prefix .. ".+)")
        if directive then
          dynamic_keys[directive] = true

          if type(v) == "boolean" then
            v = v and "on" or "off"
          end

          t[k] = tostring(v)
        end
      end
    end

    local kong_env_vars = {}

    do
      local env_vars, err = env.read_all()
      if err then
        return nil, err
      end

      for k, v in pairs(env_vars) do
        local kong_var = string.match(string.lower(k), "^kong_(.+)")
        if kong_var then
          kong_env_vars[kong_var] = true
        end
      end
    end

    add_dynamic_keys(defaults)
    add_dynamic_keys(custom_conf)
    add_dynamic_keys(kong_env_vars)
    add_dynamic_keys(from_file_conf)

--{
--  injected_conf_name = "nginx_admin_directives",
--  prefix = "nginx_admin_",
--  ignore = EMPTY,
--},
    for _, dyn_namespace in ipairs(DYNAMIC_KEY_NAMESPACES) do
      find_dynamic_keys(dyn_namespace.prefix, defaults)
      find_dynamic_keys(dyn_namespace.prefix, custom_conf)
      find_dynamic_keys(dyn_namespace.prefix, kong_env_vars)
      find_dynamic_keys(dyn_namespace.prefix, from_file_conf)
    end
    
    --local a = {a = true, b = true}
    --local b = {a = "on"}
    --local c = tablex.merge(a, b, true)
    -- {a = true, b = true} MERGE {a = "on"} => {a:"on",b:true}
    defaults = tablex.merge(dynamic_keys, defaults, true)
  end

    local a = {a = true, b = true}
    local b = {a = "on"}
    local c = tablex.merge(a, b, true)
  
  local user_conf = tablex.pairmap(overrides, defaults,
                      tablex.union(opts, { no_defaults = true, }),
                      from_file_conf, custom_conf)
  if not opts.starting then
    log.disable()
  end

  aliased_properties(user_conf)
  dynamic_properties(user_conf)
  deprecated_properties(user_conf, opts)

  -- merge user_conf with defaults
  local conf = tablex.pairmap(overrides, defaults,
                              tablex.union(opts, { defaults_only = true, }),
                              user_conf)

  -- validation
  -- 检查配置有效性
  local ok, err, errors = check_and_infer(conf, opts)

  if not opts.starting then
    log.enable()
  end

  if not ok then
    return nil, err, errors
  end

  conf = tablex.merge(conf, defaults)

  local default_nginx_main_user = false
  local default_nginx_user = false

  do
    local user = utils.strip(conf.nginx_main_user):gsub("%s+", " ")
    if user == "nobody" or user == "nobody nobody" then
      conf.nginx_main_user = nil

    elseif user == "kong" or user == "kong kong" then
      default_nginx_main_user = true
    end

    local user = utils.strip(conf.nginx_user):gsub("%s+", " ")
    if user == "nobody" or user == "nobody nobody" then
      conf.nginx_user = nil

    elseif user == "kong" or user == "kong kong" then
      default_nginx_user = true
    end
  end

  if C.getpwnam("kong") == nil or C.getgrnam("kong") == nil then
    if default_nginx_main_user == true and default_nginx_user == true then
      conf.nginx_user = nil
      conf.nginx_main_user = nil
    end
  end

  do
    local injected_in_namespace = {}

    for _, dyn_namespace in ipairs(DYNAMIC_KEY_NAMESPACES) do
      if dyn_namespace.injected_conf_name then
        injected_in_namespace[dyn_namespace.injected_conf_name] = true
        local directives = parse_nginx_directives(dyn_namespace, conf, injected_in_namespace)
        conf[dyn_namespace.injected_conf_name] = setmetatable(directives, _nop_tostring_mt)
      end
    end

    for _, dyn_namespace in ipairs(DEPRECATED_DYNAMIC_KEY_NAMESPACES) do
      if conf[dyn_namespace.injected_conf_name] then
        conf[dyn_namespace.previous_conf_name] = conf[dyn_namespace.injected_conf_name]
      end
    end
  end

  do
    local conf_arr = {}

    for k, v in pairs(conf) do
      local to_print = v
      if CONF_SENSITIVE[k] then
        to_print = "******"
      end

      conf_arr[#conf_arr+1] = k .. " = " .. pl_pretty.write(to_print, "")
    end

    table.sort(conf_arr)

    for i = 1, #conf_arr do
      log.debug(conf_arr[i])
    end
  end

  do
    local plugins = {}
    if #conf.plugins > 0 and conf.plugins[1] ~= "off" then
      for i = 1, #conf.plugins do
        local plugin_name = pl_stringx.strip(conf.plugins[i])

        if plugin_name ~= "off" then
          if plugin_name == "bundled" then
            plugins = tablex.merge(constants.BUNDLED_PLUGINS, plugins, true)
          else
            plugins[plugin_name] = true
          end
        end
      end
    end
    conf.loaded_plugins = setmetatable(plugins, _nop_tostring_mt)
  end

  if conf.loaded_plugins["prometheus"] then
    error("prometheus")
  end

  for _, dyn_namespace in ipairs(DYNAMIC_KEY_NAMESPACES) do
    if dyn_namespace.injected_conf_name then
      table.sort(conf[dyn_namespace.injected_conf_name], function(a, b)
        return a.name < b.name
      end)
    end
  end

  ok, err = listeners.parse(conf, {
    { name = "proxy_listen",   subsystem = "http",   ssl_flag = "proxy_ssl_enabled" },
    { name = "stream_listen",  subsystem = "stream", ssl_flag = "stream_proxy_ssl_enabled" },
    { name = "admin_listen",   subsystem = "http",   ssl_flag = "admin_ssl_enabled" },
    { name = "status_listen",  flags = { "ssl" },    ssl_flag = "status_ssl_enabled" },
    { name = "cluster_listen", subsystem = "http" },
  })
  if not ok then
    return nil, err
  end

  do
    local enabled_headers = {}

    for _, v in pairs(HEADER_KEY_TO_NAME) do
      enabled_headers[v] = false
    end

    if #conf.headers > 0 and conf.headers[1] ~= "off" then
      for _, token in ipairs(conf.headers) do
        if token ~= "off" then
          enabled_headers[HEADER_KEY_TO_NAME[string.lower(token)]] = true
        end
      end
    end

    if enabled_headers.server_tokens then
      enabled_headers[HEADERS.VIA] = true
      enabled_headers[HEADERS.SERVER] = true
    end

    if enabled_headers.latency_tokens then
      enabled_headers[HEADERS.PROXY_LATENCY] = true
      enabled_headers[HEADERS.RESPONSE_LATENCY] = true
      enabled_headers[HEADERS.ADMIN_LATENCY] = true
      enabled_headers[HEADERS.UPSTREAM_LATENCY] = true
    end

    conf.enabled_headers = setmetatable(enabled_headers, _nop_tostring_mt)
  end

  conf.prefix = pl_path.abspath(conf.prefix)

  for _, prefix in ipairs({ "ssl", "admin_ssl", "status_ssl", "client_ssl", "cluster" }) do
    local ssl_cert = conf[prefix .. "_cert"]
    local ssl_cert_key = conf[prefix .. "_cert_key"]

    if ssl_cert and ssl_cert_key then
      if type(ssl_cert) == "table" then
        for i, cert in ipairs(ssl_cert) do
          ssl_cert[i] = pl_path.abspath(cert)
        end

      else
        conf[prefix .. "_cert"] = pl_path.abspath(ssl_cert)
      end

      if type(ssl_cert) == "table" then
        for i, key in ipairs(ssl_cert_key) do
          ssl_cert_key[i] = pl_path.abspath(key)
        end

      else
        conf[prefix .. "_cert_key"] = pl_path.abspath(ssl_cert_key)
      end
    end
  end

  if conf.cluster_ca_cert then
    conf.cluster_ca_cert = pl_path.abspath(conf.cluster_ca_cert)
  end

  local ssl_enabled = conf.proxy_ssl_enabled or
                      conf.stream_proxy_ssl_enabled or
                      conf.admin_ssl_enabled or
                      conf.status_ssl_enabled

  for _, name in ipairs({ "nginx_http_directives", "nginx_stream_directives" }) do
    for i, directive in ipairs(conf[name]) do
      if directive.name == "ssl_dhparam" then
        if is_predefined_dhgroup(directive.value) then
          if ssl_enabled then
            directive.value = pl_path.abspath(pl_path.join(conf.prefix, "ssl", directive.value .. ".pem"))

          else
            table.remove(conf[name], i)
          end

        else
          directive.value = pl_path.abspath(directive.value)
        end

        break
      end
    end
  end

  if conf.lua_ssl_trusted_certificate
     and #conf.lua_ssl_trusted_certificate > 0 then
    conf.lua_ssl_trusted_certificate =
      tablex.map(pl_path.abspath, conf.lua_ssl_trusted_certificate)

    conf.lua_ssl_trusted_certificate_combined =
      pl_path.abspath(pl_path.join(conf.prefix, ".ca_combined"))
  end

  for property, t_path in pairs(PREFIX_PATHS) do
    conf[property] = pl_path.join(conf.prefix, unpack(t_path))
  end

  log.verbose("prefix in use: %s", conf.prefix)

  assert(require("kong.tools.dns")(conf))

  return setmetatable(conf, nil)
end

return setmetatable({
  load = load,

  load_config_file = load_config_file,

  add_default_path = function(path)
    DEFAULT_PATHS[#DEFAULT_PATHS+1] = path
  end,

  remove_sensitive = function(conf)
    local purged_conf = tablex.deepcopy(conf)

    for k in pairs(CONF_SENSITIVE) do
      if purged_conf[k] then
        purged_conf[k] = CONF_SENSITIVE_PLACEHOLDER
      end
    end

    return purged_conf
  end,
}, {
  __call = function(_, ...)
    return load(...)
  end,
})
