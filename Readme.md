# Snihook

Snihook is a kernel script that uses the lunatik netfilter library to filter TLS packets.
This script drops any TLS handshake packet forwarded on a bridge with sni not matching the whitelist provided by the user.
This whitelist is populated by the mean of `/dev/sni_whitelist`.

## Installation

Install [lunatik](https://github.com/luainkernel/lunatik):

```sh
git clone https://github.com/luainkernel/lunatik
git remote add gsoc2024 https://github.com/sheharyaar/lunatik
cd lunatik
git checkout netfilter-hook
sudo apt install lua5.4         # dependency (Debian / Ubuntu)
make                            # builds modules
sudo make install               # installs modules into /lib/modules/lua
cd ..
```

Install snihook:

```sh
git clone https://github.com/jperon/lunatik_snihook
cd lunatik_snihook
sudo apt install luarocks && sudo luarocks install moonscript  # optional dependency (if one wants to make change to sources)
make                                                           # generates Lua files from MoonScript sources
sudo make install                                              # installs the extension to Xtables directory, and lua files to module directory
```

## Usage

```
sudo lunatik run snihook/hook                        # runs the Lua kernel script
echo "add github.com" | sudo tee /dev/sni_whitelist  # opens access to https://github.com (and subdomains of github.com)
echo "del github.com" | sudo tee /dev/sni_whitelist  # removes access to https://github.com (and subdomains not open otherwise)
sudo lunatik stop snihook/hook                       # stops the Lua kernel script
```

