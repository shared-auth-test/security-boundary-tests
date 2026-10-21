-- Never log request data or trust forwarded identity headers.
local function shared_auth_check(txn)
    local headers = txn.http:req_get_headers()
    local authorization = headers["authorization"]
    local count = 0
    local value = nil
    if authorization then
        for _, item in pairs(authorization) do
            count = count + 1
            value = item
        end
    end
    if count ~= 1 or #value > 16391 or
       not value:match("^[Bb][Ee][Aa][Rr][Ee][Rr] [A-Za-z0-9._~+/%-=]+$") then
        txn:set_var("txn.auth_status", 401)
        return
    end
    local response = core.httpclient():get({
        url = "http://127.0.0.1:9081/auth/verify",
        headers = { ["authorization"] = { value } },
        timeout = 1000
    })
    if not response then
        return
    end
    if response.status == 401 or response.status == 403 then
        txn:set_var("txn.auth_status", response.status)
        return
    end
    if response.status ~= 200 then
        return
    end
    local allowed = {
        ["authorization"] = true, ["host"] = true, ["accept"] = true,
        ["content-type"] = true, ["content-encoding"] = true,
        ["content-length"] = true, ["transfer-encoding"] = true
    }
    for name, _ in pairs(headers) do
        if not allowed[name:lower()] then
            txn.http:req_del_header(name)
        end
    end
    txn:set_var("txn.auth_status", 200)
end

core.register_action("shared_auth_check", { "http-req" }, shared_auth_check)
