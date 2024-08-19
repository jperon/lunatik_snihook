local runtimes = {
  {
    "snihook/dev",
    true
  },
  {
    "snihook/hook",
    false
  }
}
local remove
remove = table.remove
local runtime
runtime = (require("rcu") and require("lunatik")).runtime
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
  for i, _des_0 in ipairs(runtimes) do
    local path, sleep
    path, sleep = _des_0[1], _des_0[2]
    local rt = runtime(path, sleep)
    run(rt, path, dev_hook.queue, log.queue)
    runtimes[i] = rt
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
  for _index_0 = 1, #runtimes do
    local rt = runtimes[_index_0]
    rt:stop()
  end
end
