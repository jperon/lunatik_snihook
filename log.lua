local concat
concat = table.concat
local outbox
outbox = require("mailbox").outbox
return function(queue, level, msg)
  if msg == nil then
    msg = ""
  end
  local self = {
    level = level,
    msg = msg
  }
  local _out = outbox(queue)
  local logger
  logger = function(lvl, txt)
    return function(...)
      if not (self.level < lvl) then
        return _out:send(tostring(self.msg) .. " " .. tostring(txt) .. ": " .. concat((function(...)
          local _accum_0 = { }
          local _len_0 = 1
          local _list_0 = {
            ...
          }
          for _index_0 = 1, #_list_0 do
            local part = _list_0[_index_0]
            _accum_0[_len_0] = tostring(part)
            _len_0 = _len_0 + 1
          end
          return _accum_0
        end)(...), "\t"))
      end
    end
  end
  self.emergency = logger(0, "EMERGENCY")
  self.alert = logger(1, "ALERT")
  self.critical = logger(2, "CRITICAL")
  self.error = logger(3, "ERROR")
  self.warning = logger(4, "WARNING")
  self.notice = logger(5, "NOTICE")
  self.info = logger(6, "INFO")
  self.dbg = logger(7, "DEBUG")
  return self
end
