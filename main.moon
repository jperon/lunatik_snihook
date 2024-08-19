-- SPDX-FileCopyrightText: (c) 2024 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only

-- Filter TLS packets based on SNI

-- Assuming that MoonScript files are transpiled into in /lib/modules/lua/snihook/*.lua,
--
-- > sudo lunatik spawn snihook/main

-- To disable it:
--
-- > sudo lunatik stop snihook/main

-- Once enabled, to add entries to whitelist:
-- > echo add DOMAIN > /dev/sni_whitelist
-- To remove entries:
-- > echo del DOMAIN > /dev/sni_whitelist


runtimes = {
  {"snihook/dev", true}      -- script that will handle /dev/sni_whitelist
  {"snihook/hook", false}    -- script that will register nftable hook(s)
}


:remove = table

:runtime = require"rcu" and require"lunatik"
:run, :shouldstop = require"thread"
:inbox = require"mailbox"
:schedule, :time = require"linux"


->
  dev_hook = inbox 100 * 1024
  log = inbox 100 * 1024

  for i, {path, sleep} in ipairs runtimes
    rt = runtime path, sleep
    run rt, path, dev_hook.queue, log.queue
    runtimes[i] = rt

  previous = __mode: "kv"
  while not shouldstop!
    if event = log\receive!
      t = time! / 1000000000
      if _t = previous[event]
        previous[event] = nil if t - _t >= 10
      else
        print event
        previous[event] = t
    else
      schedule 1000

  rt\stop! for rt in *runtimes
