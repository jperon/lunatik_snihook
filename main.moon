-- SPDX-FileCopyrightText: (c) 2024 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only

-- Filter TLS packets based on SNI

-- Assuming that MoonScript files are transpiled into in /lib/modules/lua/snihook/*.lua,
--
-- > sudo lunatik run snihook/main

-- To disable it:
--
-- > sudo lunatik stop snihook/main; sudo lunatik stop snihook/logger; sudo lunatik stop snihook/hook

-- Once enabled, to add entries to whitelist:
-- > echo add DOMAIN > /dev/sni_whitelist
-- To remove entries:
-- > echo del DOMAIN > /dev/sni_whitelist


hook   = "snihook/hook"    -- script that will register nftable hook(s)
logger = "snihook/logger"  -- script that will handle logging
name   = "sni_whitelist"   -- name of the device file (in /dev)

:runtime, :runtimes, stop: lstop = require"lunatik"
require"rcu"  -- required for runtime
:run, stop: tstop = require"thread"
import outbox from require"mailbox"

device = require"device"
linux = require"linux"
import IRUSR, IWUSR from linux.stat
IRWUSR = IRUSR | IWUSR


msg = outbox 100 * 1024
log = outbox 100 * 1024


rt = runtimes!
for script in *{hook, logger}
  assert not rt[script], "Please stop #{script} before starting this script."
logger_rt = runtime logger
hook_rt = runtime hook, false
logger_th = run logger_rt, logger, log.queue
hook_th = run hook_rt, hook, msg.queue, log.queue
rt[logger] = logger_rt
rt[hook] = hook_rt

nop = ->  -- Do nothing


device.new{
  :name, mode: IRWUSR
  open: nop, release: nop, read: nop
  write: (s) =>
    if s == "STOP\n"
      msg\send s
      log\send s
      tstop logger_th
      tstop hook_th
      lstop hook_rt
      lstop logger_rt
    else
      msg\send s
}
