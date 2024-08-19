local outbox
outbox = require("mailbox").outbox
local new
new = require("device").new
local IRUSR, IWUSR
do
  local _obj_0 = require("linux")
  IRUSR, IWUSR = _obj_0.stat.IRUSR, _obj_0.stat.IWUSR
end
local nop
nop = function() end
return function(self)
  local hook = outbox(self)
  return new({
    name = "sni_whitelist",
    mode = (IRUSR | IWUSR),
    open = nop,
    release = nop,
    read = nop,
    write = function(self, s)
      return hook:send(s)
    end
  })
end
