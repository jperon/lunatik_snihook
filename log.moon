import concat from table
import outbox from require"mailbox"

@ = {}

@set_log = (queue, @level, @msg="") ->
  @log = outbox queue

logger = (lvl, txt) ->
  (...) ->
    unless @level < lvl
      @log\send "#{@msg} #{txt}: " .. concat [ "#{part}" for part in *{...} ], "\t"

@emergency = logger 0, "EMERGENCY"
@alert = logger 1, "ALERT"
@critical = logger 2, "CRITICAL"
@error = logger 3, "ERROR"
@warn = logger 4, "WARNING"
@notice = logger 5, "NOTICE"
@info = logger 6, "INFO"
@dbg = logger 7, "DEBUG"
@
