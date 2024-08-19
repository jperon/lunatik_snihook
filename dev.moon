-- SPDX-FileCopyrightText: (c) 2024 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only

:outbox = require"mailbox"
:new = require"device"
stat: {:IRUSR, :IWUSR} = require"linux"

nop = ->  -- Do nothing

=>
  hook = outbox @
  new name: "sni_whitelist", mode: (IRUSR | IWUSR), open: nop, release: nop, read: nop, write: (s) => hook\send s
