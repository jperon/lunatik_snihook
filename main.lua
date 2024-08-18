local hook = "snihook/hook"
local logger = "snihook/logger"
local name = "sni_whitelist"
local runtime, runtimes, lstop
do
  local _obj_0 = require("lunatik")
  runtime, runtimes, lstop = _obj_0.runtime, _obj_0.runtimes, _obj_0.stop
end
require("rcu")
local run, tstop
do
  local _obj_0 = require("thread")
  run, tstop = _obj_0.run, _obj_0.stop
end
local outbox
outbox = require("mailbox").outbox
local device = require("device")
local linux = require("linux")
local IRUSR, IWUSR
do
  local _obj_0 = linux.stat
  IRUSR, IWUSR = _obj_0.IRUSR, _obj_0.IWUSR
end
local IRWUSR = IRUSR | IWUSR
local msg = outbox(100 * 1024)
local log = outbox(100 * 1024)
local rt = runtimes()
local _list_0 = {
  hook,
  logger
}
for _index_0 = 1, #_list_0 do
  local script = _list_0[_index_0]
  assert(not rt[script], "Please stop " .. tostring(script) .. " before starting this script.")
end
local logger_rt = runtime(logger)
local hook_rt = runtime(hook, false)
local logger_th = run(logger_rt, logger, log.queue)
local hook_th = run(hook_rt, hook, msg.queue, log.queue)
rt[logger] = logger_rt
rt[hook] = hook_rt
local nop
nop = function() end
return device.new({
  name = name,
  mode = IRWUSR,
  open = nop,
  release = nop,
  read = nop,
  write = function(self, s)
    if s == "STOP\n" then
      msg:send(s)
      log:send(s)
      tstop(logger_th)
      tstop(hook_th)
      lstop(hook_rt)
      return lstop(logger_rt)
    else
      return msg:send(s)
    end
  end
})
