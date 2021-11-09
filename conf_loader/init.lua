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
                  ciphers = nil,   -- all TLSv1.3 ciphers are consider
ed safe
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
}

local DEPRECATED_DYNAMIC_KEY_NAMESPACES = {
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
end

local function upstream_keepalive_deprecated_properties(conf)
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
end

local function overrides(k, default_v, opts, file_conf, arg_conf)
end

local function parse_nginx_directives(dyn_namespace, conf, injected_in_namespace)
end

local function aliased_properties(conf)
end

local function deprecated_properties(conf, opts)
end

local function dynamic_properties(conf)
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

      for property_name, v_schema in pairs(CONF_INFERENCES) do
      end
    end

    local function find_dynamic_keys(dyn_prefix, t)
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
  end
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
