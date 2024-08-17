import concat, remove from table
import time from require"linux"

nop = ->

(level, msg) ->
  @ = :level, :msg
  previous = {}

  logger = (level, txt) ->
    return nop if @level < level
    (...) ->
      unless @level < level
        msg = "#{@msg} #{txt}: " .. concat [ "#{part}" for part in *{...} ], "\t"
        t = time! / 1000000000
        for i = 1, #previous
          prev = previous[i]
          continue if not prev
          {_t, _n, _msg} = prev
          if t - _t >= 10
            if _n == 0
              previous[_msg] = nil
              remove previous, i
            else
              print _n > 1 and "#{_msg} (#{_n}x)" or _msg
              prev[1], prev[2] = t, 0
        if prev = previous[msg]
          prev[2] += 1
        else
          print msg
          prev = {t, 0, msg}
          previous[msg] = prev
          previous[#previous+1] = prev

  @emergency = logger 0, "EMERGENCY"
  @alert = logger 1, "ALERT"
  @critical = logger 2, "CRITICAL"
  @error = logger 3, "ERROR"
  @warning = logger 4, "WARNING"
  @notice = logger 5, "NOTICE"
  @info = logger 6, "INFO"
  @dbg = logger 7, "DEBUG"
  @
