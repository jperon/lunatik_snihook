-- SPDX-FileCopyrightText: (c) 2024 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only

-- Filter TLS packets based on SNI

-- Assuming that this script is transpiled into in /lib/modules/lua/snihook/hook.lua,
-- and libxt_snihook.so is installed:
--
-- > sudo lunatik run snihook/hook false

-- To disable it:
--
-- > sudo lunatik stop snihook/hook

-- Once enabled, to add entries to whitelist:
-- > echo add DOMAIN > /dev/sni_whitelist
-- To remove entries:
-- > echo del DOMAIN > /dev/sni_whitelist
-- To get a list of entries (formatted as a Lua table):
-- > head -1 /dev/sni_whitelist

import concat from table
nf = require"netfilter"
import BRIDGE from nf.family
import FORWARD from nf.bridge_hooks
import FILTER_BRIDGED from nf.bridge_priority
import CONTINUE, DROP from nf.action
-- DROP = CONTINUE  -- Enable to debug without blocking traffic
device = require"device"
linux = require"linux"
import IRUSR, IWUSR from linux.stat
IRWUSR = IRUSR | IWUSR
ipparse = require"snihook.ipparse"
ipparse.log.level = 7
import auto_ip, IP, TCP, TLS, TLSHandshake, TLSExtension from ipparse
tcp_proto = IP.protocols.TCP
import handshake from TLS.types
import hello from TLSHandshake.types
import server_name from TLSExtension.types
import info from require"snihook.log" 6, "snihook"

whitelist = {}


nop = ->  -- Do nothing


get_first = (fn) =>  -- Returns first value of an iterator that matches the condition defined in function fn.
  for v in @
    return v if fn v

device.new{
  name: "sni_whitelist", mode: IRWUSR
  open: nop, release: nop
  read: (len) => ('{\"' .. concat([ k for k in pairs whitelist ], '","') .. '"}\n')\gsub '""', ''
  write: (s) =>
    for action, domain in s\gmatch"(%S+)%s(%S+)"
      if action == "add"
        whitelist[domain] = true
      elseif action == "del"
        whitelist[domain] = nil
}


hook = =>
  ip = auto_ip @
  return CONTINUE if not ip or ip\is_empty! or ip.protocol ~= tcp_proto
  tcp = TCP ip.data
  return CONTINUE if tcp\is_empty! or tcp.dport ~= 443
  tls = TLS tcp.data
  return CONTINUE if tls\is_empty! or tls.type ~= handshake
  hshake = TLSHandshake tls.data
  return CONTINUE if hshake\is_empty! or hshake.type ~= hello
  if sni = get_first hshake\iter_extensions!, => @type == server_name
    sni = sni.server_name
    if whitelist[sni]
        info"#{ip.src} -> #{sni} allowed."
        return CONTINUE
    sni_parts = [ part for part in sni\gmatch"[^%.]+"]
    for i = 2, #sni_parts
      domain = concat [ part for part in *sni_parts[i,] ], "."
      if whitelist[domain]
        info"#{ip.src} -> #{sni} allowed as a subdomain of #{domain}."
        return CONTINUE
    info"#{ip.src} -> #{sni} BLOCKED."
    return DROP

  CONTINUE

nf.register :hook, pf: BRIDGE, hooknum: FORWARD, priority: FILTER_BRIDGED

