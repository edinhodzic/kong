local responses = require "kong.tools.responses"
local http = require "resty.http"
local utils = require "kong.tools.utils"
local json = require "cjson"

local ERROR = "error"

local _M = {}

function _M.log_debug(message)
  ngx.log(ngx.DEBUG, message)
  print(message) -- TODO remove this line once we figure out how to change the logging level
end

function _M.print_table(message, table)
  _M.log_debug("\n\n")
  _M.log_debug(string.format("------------ [%s] start ------------", message))
  for k, v in pairs(table) do
    _M.log_debug(string.format("key[%s] value [%s]\t\t", k, v))
  end
  _M.log_debug(string.format("------------ [%s] end ------------", message))
  _M.log_debug("\n\n")
end

--local function audit_event(auditSource, auditType, eventId, generatedAt, tags, detail, request, response)
local function audit_event(auditType, eventId)
  return {
    auditSource = "kong",
    auditType = auditType,
    eventId = eventId,
    generatedAt = "generatedAt",
    tags = "tags",
    detail = "audit detail",
    request = "request detail",
    response = "response detail"
  }
end

local function audit(auditEvent)
  -- TODO implement properly
  _M.print_table("sending audit event", auditEvent)
end

function _M.validate_scope(token)
  local isValidScope = utils.table_contains(ngx.ctx.plugins_for_request.oauth2.scopes, token.scope)
  if not isValidScope then
    _M.log_debug(string.format("scope validation failed for request path [%s], token [%s %s] and scope [%s]", ngx.ctx.api.request_path, token.token_type, token.access_token, token.scope))
  end
  if not isValidScope then
    return responses.send_HTTP_UNAUTHORIZED({[ERROR] = "invalid_request", error_description = "Scope validation failed"}, {["WWW-Authenticate"] = 'Bearer realm="service" error="invalid_request" error_description="Scope validation failed"'})
  end
  return isValidScope
end

function _M.exchange_token(token)
  audit(audit_event("audit-type", "event-id"))
  --  local delegatedAuthorityUrl = string.format("http://192.168.224.16:9606/authority?access_token=%s", token.access_token)
  local delegatedAuthorityUrl = "http://192.168.224.16:9606/authority?access_token=3d35ec66daf3bf62c09b7b40242b211f"
  local res, err = http.new():request_uri(delegatedAuthorityUrl, {
    method = "GET",
    headers = {
      ["Content-Type"] = "application/json",
    }
  })

  if err then
    return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
  elseif res.status == 404 then
    return responses.send_HTTP_NOT_FOUND(res.body)
  elseif not res.status == 200 then
    return responses.send_HTTP_INTERNAL_SERVER_ERROR("some useful message here?")
  end

  local authBearerToken = json.decode(res.body).delegatedAuthority.user.authBearerToken

  _M.log_debug(string.format("exchanged oauth token22 [%s] for auth token [%s]", token.access_token, authBearerToken))
  ngx.req.set_header("Authorization", "Bearer "..authBearerToken)
end

return _M
