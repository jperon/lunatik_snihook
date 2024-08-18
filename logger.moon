import remove from table

import inbox from require"mailbox"
import shouldstop from require"thread"
:schedule, :time, task: :INTERRUPTIBLE = require"linux"

(queue) ->
  _in = inbox queue
  previous = __mode: "kv"
  while not shouldstop!
    if @ = _in\receive!
      break if @ == "STOP\n"
      t = time! / 1000000000
      if _t = previous[@]
        previous[@] = nil if t - _t >= 10
      else
        print @
        previous[@] = t
      schedule 1, INTERRUPTIBLE
    else
      schedule 1000, INTERRUPTIBLE
