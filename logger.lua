local remove
remove = table.remove
local inbox
inbox = require("mailbox").inbox
local schedule, time
do
  local _obj_0 = require("linux")
  schedule, time = _obj_0.schedule, _obj_0.time
end
local shouldstop
shouldstop = require("thread").shouldstop
return function(queue)
  local _in = inbox(queue)
  local previous = {
    __mode = "kv"
  }
  while not shouldstop() do
    do
      local self = _in:receive()
      if self then
        local t = time() / 1000000000
        do
          local _t = previous[self]
          if _t then
            if t - _t >= 10 then
              previous[self] = nil
            end
          else
            print(self)
            previous[self] = t
          end
        end
        schedule(1)
      else
        schedule(1000)
      end
    end
  end
end
