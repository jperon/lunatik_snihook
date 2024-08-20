local concat
concat = table.concat
local inbox
inbox = require("mailbox").inbox
local register, pf, hooknum, priority, CONTINUE, DROP
do
  local _obj_0 = require("netfilter")
  register, pf, hooknum, priority, CONTINUE, DROP = _obj_0.register, _obj_0.family.BRIDGE, _obj_0.bridge_hooks.FORWARD, _obj_0.bridge_priority.FILTER_BRIDGED, _obj_0.action.CONTINUE, _obj_0.action.DROP
end
DROP = require("snihook.config").activate and DROP or CONTINUE
local set_log, notice, info, dbg
do
  local _obj_0 = require("snihook.log")
  set_log, notice, info, dbg = _obj_0.set_log, _obj_0.notice, _obj_0.info, _obj_0.dbg
end
local auto_ip, tcp_proto, Fragmented_IP4, TCP, TLS, TLSHandshake, TLSExtension
do
  local _obj_0 = require("snihook.ipparse")
  auto_ip, tcp_proto, Fragmented_IP4, TCP, TLS, TLSHandshake, TLSExtension = _obj_0.auto_ip, _obj_0.IP.protocols.TCP, _obj_0.Fragmented_IP4, _obj_0.TCP, _obj_0.TLS, _obj_0.TLSHandshake, _obj_0.TLSExtension
end
local handshake
handshake = TLS.types.handshake
local hello
hello = TLSHandshake.types.hello
local server_name
server_name = TLSExtension.types.server_name
local whitelist = { }
local get_first
get_first = function(self, fn)
  for v in self do
    if fn(v) then
      return v
    end
  end
end
local fragmented_ips = setmetatable({ }, {
  __mode = "kv",
  __index = function(self, id)
    self[id] = Fragmented_IP4()
    dbg(id, self[id])
    return self[id]
  end
})
return function(dev_queue, log_queue)
  local dev = inbox(dev_queue)
  set_log(log_queue, 6, "snihook")
  return register({
    pf = pf,
    hooknum = hooknum,
    priority = priority,
    hook = function(self)
      do
        local changes = dev:receive()
        if changes then
          for action, domain in changes:gmatch("(%S+)%s(%S+)") do
            if action == "add" then
              whitelist[domain] = true
            elseif action == "del" then
              whitelist[domain] = nil
            end
          end
        end
      end
      local ip = auto_ip(self)
      if not ip or ip:is_empty() then
        return CONTINUE
      end
      if ip:is_fragment() then
        dbg("Fragment detected")
        local f_ip = fragmented_ips[ip.id]:insert(ip)
        if not (f_ip:is_complete()) then
          return CONTINUE
        end
        dbg("Last fragment received")
        ip = f_ip
        fragmented_ips[ip.id] = nil
      end
      if ip.protocol ~= tcp_proto then
        return CONTINUE
      end
      local tcp = TCP(ip.data)
      if tcp:is_empty() or tcp.dport ~= 443 then
        return CONTINUE
      end
      local tls = TLS(tcp.data)
      if tls:is_empty() or tls.type ~= handshake then
        return CONTINUE
      end
      local hshake = TLSHandshake(tls.data)
      if hshake:is_empty() or hshake.type ~= hello then
        return CONTINUE
      end
      do
        local sni = get_first(hshake:iter_extensions(), function(self)
          return self.type == server_name
        end)
        if sni then
          sni = sni.server_name
          if whitelist[sni] then
            return CONTINUE, info(tostring(ip.src) .. " -> " .. tostring(sni) .. " allowed.")
          end
          local sni_parts
          do
            local _accum_0 = { }
            local _len_0 = 1
            for part in sni:gmatch("[^%.]+") do
              _accum_0[_len_0] = part
              _len_0 = _len_0 + 1
            end
            sni_parts = _accum_0
          end
          for i = 2, #sni_parts do
            local domain = concat((function()
              local _accum_0 = { }
              local _len_0 = 1
              for _index_0 = i, #sni_parts do
                local part = sni_parts[_index_0]
                _accum_0[_len_0] = part
                _len_0 = _len_0 + 1
              end
              return _accum_0
            end)(), ".")
            if whitelist[domain] then
              return CONTINUE, info(tostring(ip.src) .. " -> " .. tostring(sni) .. " allowed as a subdomain of " .. tostring(domain) .. ".")
            end
          end
          return DROP, notice(tostring(ip.src) .. " -> " .. tostring(sni) .. " BLOCKED.")
        end
      end
      return CONTINUE
    end
  })
end
