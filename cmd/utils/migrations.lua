local log = require "kong.cmd.utils.log"


local MIGRATIONS_MUTEX_KEY = "migrations"
local NOT_LEADER_MSG = "aborted: another node is performing database changes"
local NEEDS_BOOTSTRAP_MSG = "Database needs bootstrapping or is older than Kong 1.0.\n\n" ..
  "To start a new installation from scratch, run 'kong migrations bootstrap'.\n\n" ..
  "To migrate from a version older than 1.0, migrated to Kong 1.5.0 first. \n" ..
  "If you still have 'apis' entities, you can convert them to Routes and Services\n" ..
  "using the 'kong migrations migrate-apis' command in Kong 1.5.0.\n\n"

local function check_state(schema_state)
  if not schema_state:is_up_to_date() then
    if schema_state.needs_bootstrap then
      error(NEEDS_BOOTSTRAP_MSG)
    end

    if schema_state.new_migrations then
      error("New migrations available; run 'kong migrations up' to proceed")
    end
  end 
end

local function bootstrap(schema_state, db, ttl)
  error("in bootstrap")
end

local function up(schema_state, db, opts)
  error("in up")
end

local function finish(schema_state, db, opts)
  error("in finish")
end

local function reset(schema_state, db, ttl)
  error("in reset")
end

return {
  up = up,
  reset = reset,
  finish = finish,
  bootstrap = bootstrap,
  check_state = check_state,
  NEEDS_BOOTSTRAP_MSG = NEEDS_BOOTSTRAP_MSG,
}
