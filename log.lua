local concat, remove
do
  local _obj_0 = table
  concat, remove = _obj_0.concat, _obj_0.remove
end
local time
time = require("linux").time
local nop
nop = function() end
return function(level, msg)
  local self = {
    level = level,
    msg = msg
  }
  local previous = { }
  local logger
  logger = function(level, txt)
    if self.level < level then
      return nop
    end
    return function(...)
      if not (self.level < level) then
        msg = tostring(self.msg) .. " " .. tostring(txt) .. ": " .. concat((function(...)
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
        end)(...), "\t")
        local t = time() / 1000000000
        for i = 1, #previous do
          local _continue_0 = false
          repeat
            local prev = previous[i]
            if not prev then
              _continue_0 = true
              break
            end
            local _t, _n, _msg
            _t, _n, _msg = prev[1], prev[2], prev[3]
            if t - _t >= 10 then
              if _n == 0 then
                previous[_msg] = nil
                remove(previous, i)
              else
                print(_n > 1 and tostring(_msg) .. " (" .. tostring(_n) .. "x)" or _msg)
                prev[1], prev[2] = t, 0
              end
            end
            _continue_0 = true
          until true
          if not _continue_0 then
            break
          end
        end
        do
          local prev = previous[msg]
          if prev then
            prev[2] = prev[2] + 1
          else
            print(msg)
            prev = {
              t,
              0,
              msg
            }
            previous[msg] = prev
            previous[#previous + 1] = prev
          end
        end
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
