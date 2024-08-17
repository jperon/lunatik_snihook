import concat from table
import outbox from require"mailbox"

(queue, level, msg="") ->
  @ = :level, :msg
  _out = outbox queue
  
  logger = (lvl, txt) ->
    (...) ->
      unless @level < lvl
        _out\send "#{@msg} #{txt}: " .. concat [ "#{part}" for part in *{...} ], "\t"

  @emergency = logger 0, "EMERGENCY"
  @alert = logger 1, "ALERT"
  @critical = logger 2, "CRITICAL"
  @error = logger 3, "ERROR"
  @warning = logger 4, "WARNING"
  @notice = logger 5, "NOTICE"
  @info = logger 6, "INFO"
  @dbg = logger 7, "DEBUG"
  @

