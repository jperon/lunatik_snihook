import remove from table

import inbox from require"mailbox"
import schedule, time from require"linux"
import shouldstop from require"thread"

(queue) ->
  _in = inbox queue
  previous = __mode: "kv"
  while not shouldstop!
    if @ = _in\receive!
      t = time! / 1000000000
      if _t = previous[@]
        previous[@] = nil if t - _t >= 10
      else
        print @
        previous[@] = t
      schedule 1
    else
      schedule 1000

