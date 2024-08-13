local concat
concat = table.concat
local xt = require("xtable")
local UNSPEC
UNSPEC = xt.family.UNSPEC
local device = require("device")
local linux = require("linux")
local IRUSR, IWUSR
do
  local _obj_0 = linux.stat
  IRUSR, IWUSR = _obj_0.IRUSR, _obj_0.IWUSR
end
local IRWUSR = IRUSR | IWUSR
local auto_ip, TCP, TLS, TLSHandshake, TLSExtension
do
  local _obj_0 = require("sniblock.ipparse")
  auto_ip, TCP, TLS, TLSHandshake, TLSExtension = _obj_0.auto_ip, _obj_0.TCP, _obj_0.TLS, _obj_0.TLSHandshake, _obj_0.TLSExtension
end
local handshake
handshake = TLS.types.handshake
local hello
hello = TLSHandshake.types.hello
local server_name
server_name = TLSExtension.types.server_name
local whitelist = { }
local nop
nop = function() end
local get_first
get_first = function(self, fn)
  for _index_0 = 1, #self do
    local v = self[_index_0]
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
return xt.match({
  name = "sniblock",
  revision = 1,
  family = UNSPEC,
  proto = 0,
  checkentry = nop,
  destroy = nop,
  hooks = 0,
  match = function(self, par)
    local tcp = TCP({
      skb = self,
      off = par.thoff
    })
    local tls = TLS(tcp.data)
    if tls:is_empty() then
      return 
    end
    if tls.type == handshake then
      local hshake = TLSHandshake(tls.data)
      if hshake.type == hello then
        do
          local sni = (get_first(hshake.extensions, function(self)
            return self.type == server_name
          end)).server_name
          if sni then
            if whitelist[sni] then
              print(tostring(sni) .. " allowed.")
              return false
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
                print(tostring(sni) .. " allowed as a subdomain of " .. tostring(domain) .. ".")
                return false
              end
            end
            print(tostring(sni) .. " BLOCKED.")
            return true
          end
        end
      end
    end
    return false
  end
})
