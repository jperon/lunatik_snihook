local _runtimes = {
  {
    "snihook/dev",
    true
  },
  {
    "snihook/hook",
    false
  }
}
local runtime, runtimes
do
  local _obj_0 = require("rcu") and require("lunatik")
  runtime, runtimes = _obj_0.runtime, _obj_0.runtimes
end
local run, shouldstop
do
  local _obj_0 = require("thread")
  run, shouldstop = _obj_0.run, _obj_0.shouldstop
end
local inbox
inbox = require("mailbox").inbox
local schedule, time
do
  local _obj_0 = require("linux")
  schedule, time = _obj_0.schedule, _obj_0.time
end
return function()
  local dev_hook = inbox(100 * 1024)
  local log = inbox(100 * 1024)
  runtimes = runtimes()
  for _index_0 = 1, #_runtimes do
    local r = _runtimes[_index_0]
    local path, sleep
    path, sleep = r[1], r[2]
    assert(not runtimes[path], "Please stop " .. tostring(path) .. " before launching this script.")
    local rt = runtime(path, sleep)
    run(rt, path, dev_hook.queue, log.queue)
    r[3] = rt
    runtimes[path] = rt
  end
  local previous = {
    __mode = "kv"
  }
  while not shouldstop() do
    do
      local event = log:receive()
      if event then
        local t = time() / 1000000000
        do
          local _t = previous[event]
          if _t then
            if t - _t >= 10 then
              previous[event] = nil
            end
          else
            print(event)
            previous[event] = t
          end
        end
      else
        schedule(1000)
      end
    end
  end
  for _index_0 = 1, #_runtimes do
    local _des_0 = _runtimes[_index_0]
    local path, _, rt
    path, _, rt = _des_0[1], _des_0[2], _des_0[3]
    rt:stop()
    runtimes[path] = nil
  end
end
