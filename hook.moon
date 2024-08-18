import concat from table

import inbox from require"mailbox"

nf = require"netfilter"
import BRIDGE from nf.family
import FORWARD from nf.bridge_hooks
import FILTER_BRIDGED from nf.bridge_priority
import CONTINUE, DROP from nf.action
DROP = CONTINUE  -- Enable to debug without blocking traffic
log = require"snihook.log"
ipparse = require"snihook.ipparse"


whitelist = {}


get_first = (fn) =>  -- Returns first value of an iterator that matches the condition defined in function fn.
  for v in @
    return v if fn v


(queue) =>
  msg = inbox @
  log = log queue, 6, "snihook"
  import notice, info from log
  ipparse = ipparse log
  import auto_ip, IP, TCP, TLS, TLSHandshake, TLSExtension from ipparse
  tcp_proto = IP.protocols.TCP
  import handshake from TLS.types
  import hello from TLSHandshake.types
  import server_name from TLSExtension.types

  hook = =>
    if changes = msg\receive!
      for action, domain in changes\gmatch"(%S+)%s(%S+)"
        if action == "add"
          whitelist[domain] = true
        elseif action == "del"
          whitelist[domain] = nil

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
        return CONTINUE, info"#{ip.src} -> #{sni} allowed."
      sni_parts = [ part for part in sni\gmatch"[^%.]+" ]
      for i = 2, #sni_parts
        domain = concat [ part for part in *sni_parts[i,] ], "."
        if whitelist[domain]
          return CONTINUE, info"#{ip.src} -> #{sni} allowed as a subdomain of #{domain}."
      return DROP, notice"#{ip.src} -> #{sni} BLOCKED."

    CONTINUE

  nf.register :hook, pf: BRIDGE, hooknum: FORWARD, priority: FILTER_BRIDGED
