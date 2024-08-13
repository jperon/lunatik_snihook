# Sniblock

Sniblock is a kernel script that uses the lunatik xtable library to filter DNS packets.
This script drops any outbound TLS handshake packet with sni not matching the whitelist provided by the user.
This whitelist is populated by the mean of `/dev/sni_whitelist`.

## Installation

Assuming [lunatik](https://github.com/luainkernel/lunatik) is installed:

```
make               # builds the userspace extension for netfilter, and transpiles MoonScript files
sudo make install  # installs the extension to Xtables directory, and lua files to module directory
```

## Usage

```
sudo lunatik run sniblock/match                                    # runs the Lua kernel script
sudo iptables -A OUTPUT -m sniblock -p tcp --dport 443 -j REJECT   # initiates the netfilter framework to load our extension
sudo ip6tables -A OUTPUT -m sniblock -p tcp --dport 443 -j REJECT  # initiates the netfilter framework to load our extension for IPv6
echo "add github.com" | sudo tee /dev/sni_whitelist                # opens access to https://github.com (and subdomains of github.com)
echo "del github.com" | sudo tee /dev/sni_whitelist                # removes access to https://github.com (and subdomains not open otherwise)
```

