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

function _M.log_debug_table_as_json(message, table)
  _M.log_debug(message .. " : " .. json.encode(table))
end


function _M.print_table(message, table)
  _M.log_debug("\n\n")
  _M.log_debug("------------ [" .. message .. "] start ------------")
  for key, value in pairs(table) do
    if (type(value) == "table") then
      _M.print_table(key, value)
    else
      _M.log_debug(string.format("key [%s] value [%s]\t\t", key, value))
    end
  end
  _M.log_debug("------------ [" .. message .. "] end ------------")
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

local function http_get(uri)
  local res, err = http.new():request_uri(uri, {
    method = "GET",
    headers = {
      ["Content-Type"] = "application/json",
    }
  })
  return res, err
end

local function http_post(uri, payload)
  -- NOTE payload should be of the form "a=1&b=2"
  local res, err = http.new():request_uri(uri, {
    method = "POST",
    headers = {
      ["Content-Type"] = "application/json",
      body = payload,
    }
  })
  return res, err
end

function _M.exchange_token(token)
  audit(audit_event("audit-type", "event-id"))
  --  local res, err = http_get("http://192.168.224.16:9606/authority?access_token="..token.access_token)
  local res, err = http_get("http://192.168.224.10:9606/authority?access_token=3d35ec66daf3bf62c09b7b40242b211f")

  if err then
    return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
  elseif res.status == 404 then
    return responses.send_HTTP_NOT_FOUND(res.body)
  elseif not res.status == 200 then
    return responses.send_HTTP_INTERNAL_SERVER_ERROR("some useful message here?")
  end

  local authBearerToken = json.decode(res.body).delegatedAuthority.user.authBearerToken

  _M.log_debug("exchanged oauth token [" .. token.access_token .. "] for auth token [" .. authBearerToken .. "]")
  ngx.req.set_header("Authorization", "Bearer " .. authBearerToken)
end

function _M.validate_scope(token)
  local isValidScope = utils.table_contains(ngx.ctx.plugins_for_request.oauth2.scopes, token.scope)
  if not isValidScope then
    _M.log_debug("scope validation failed for request path [" .. ngx.ctx.api.request_path .. "], token [" .. token.token_type .. token.access_token .. "] and scope [" .. token.scope .. "]")
  end
  if not isValidScope then
    return responses.send_HTTP_UNAUTHORIZED({ [ERROR] = "invalid_request", error_description = "Scope validation failed" }, { ["WWW-Authenticate"] = 'Bearer realm="service" error="invalid_request" error_description="Scope validation failed"' })
  end
  return isValidScope
end


function _M.validate_subscription(appId, requestPath)

  function string.take(s, n)
    return string.sub(s, 1, n)
  end

  function string.starts_with(s1, s2)
    return string.sub(s1, 1, string.len(s2)) == s2
  end

  function string.has_context(requestPath, context)
    local trimmedRequestPath = requestPath:take(string.len(context) + 2)
    return trimmedRequestPath:starts_with("/" .. context .. "/")
  end

  local function context_matches_subscription(requestPath, subscriptions)
    for _, value in pairs(subscriptions) do
      if requestPath:has_context(value.context) then
        return true
      end
    end
    return false
  end

  _M.log_debug("validating subscription for api id [" .. appId .. "]")
  --  local res, err = http_get("http://192.168.224.16:9607/application/"..appId.."/subscriptions")
  local res, err = http_get("http://192.168.224.10:9607/application/9e61c6e1-88eb-4969-8d13-bc58c5f4e735/subscriptions")

  if err then
    return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
  elseif res.status == 404 then
    return responses.send_HTTP_NOT_FOUND(res.body)
  elseif not res.status == 200 then
    return responses.send_HTTP_INTERNAL_SERVER_ERROR("some useful message here?")
  end

  local subscriptions = json.decode(res.body)
  _M.log_debug_table_as_json("subscriptions", subscriptions)

  -- TODO include api version in subscription check
  if not context_matches_subscription(requestPath, subscriptions) then
    return responses.send_HTTP_UNAUTHORIZED({ [ERROR] = "invalid_request", error_description = "Subscription validation failed" }, { ["WWW-Authenticate"] = 'Bearer realm="service" error="invalid_request" error_description="Subscription validation failed"' })
  end


  return true
end

return _M
