local hook = "snihook/hook"
local logger = "snihook/logger"
local name = "sni_whitelist"
local runtime, runtimes
do
  local _obj_0 = require("lunatik")
  runtime, runtimes = _obj_0.runtime, _obj_0.runtimes
end
require("rcu")
local run
run = require("thread").run
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
local l = runtime(logger)
local r = runtime(hook, false)
run(l, logger, log.queue)
run(r, hook, msg.queue, log.queue)
rt[logger] = l
rt[hook] = r
local nop
nop = function() end
return device.new({
  name = name,
  mode = IRWUSR,
  open = nop,
  release = nop,
  read = nop,
  write = function(self, s)
    return msg:send(s)
  end
})
