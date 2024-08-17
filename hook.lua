local concat
concat = table.concat
local nf = require("netfilter")
local BRIDGE
BRIDGE = nf.family.BRIDGE
local FORWARD
FORWARD = nf.bridge_hooks.FORWARD
local FILTER_BRIDGED
FILTER_BRIDGED = nf.bridge_priority.FILTER_BRIDGED
local CONTINUE, DROP
do
  local _obj_0 = nf.action
  CONTINUE, DROP = _obj_0.CONTINUE, _obj_0.DROP
end
local device = require("device")
local linux = require("linux")
local IRUSR, IWUSR
do
  local _obj_0 = linux.stat
  IRUSR, IWUSR = _obj_0.IRUSR, _obj_0.IWUSR
end
local IRWUSR = IRUSR | IWUSR
local ipparse = require("snihook.ipparse")
ipparse.log.level = 7
local auto_ip, IP, TCP, TLS, TLSHandshake, TLSExtension
auto_ip, IP, TCP, TLS, TLSHandshake, TLSExtension = ipparse.auto_ip, ipparse.IP, ipparse.TCP, ipparse.TLS, ipparse.TLSHandshake, ipparse.TLSExtension
local tcp_proto = IP.protocols.TCP
local handshake
handshake = TLS.types.handshake
local hello
hello = TLSHandshake.types.hello
local server_name
server_name = TLSExtension.types.server_name
local info
info = require("snihook.log")(6, "snihook").info
local whitelist = { }
local nop
nop = function() end
local get_first
get_first = function(self, fn)
  for v in self do
    if fn(v) then
      return v
    end
  end
end
device.new({
  name = "sni_whitelist",
  mode = IRWUSR,
  open = nop,
  release = nop,
  read = function(self, len)
    return ('{\"' .. concat((function()
      local _accum_0 = { }
      local _len_0 = 1
      for k in pairs(whitelist) do
        _accum_0[_len_0] = k
        _len_0 = _len_0 + 1
      end
      return _accum_0
    end)(), '","') .. '"}\n'):gsub('""', '')
  end,
  write = function(self, s)
    for action, domain in s:gmatch("(%S+)%s(%S+)") do
      if action == "add" then
        whitelist[domain] = true
      elseif action == "del" then
        whitelist[domain] = nil
      end
    end
  end
})
local hook
hook = function(self)
  local ip = auto_ip(self)
  if not ip or ip:is_empty() or ip.protocol ~= tcp_proto then
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
        info(tostring(ip.src) .. " -> " .. tostring(sni) .. " allowed.")
        return CONTINUE
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
          info(tostring(ip.src) .. " -> " .. tostring(sni) .. " allowed as a subdomain of " .. tostring(domain) .. ".")
          return CONTINUE
        end
      end
      info(tostring(ip.src) .. " -> " .. tostring(sni) .. " BLOCKED.")
      return DROP
    end
  end
  return CONTINUE
end
return nf.register({
  hook = hook,
  pf = BRIDGE,
  hooknum = FORWARD,
  priority = FILTER_BRIDGED
})
