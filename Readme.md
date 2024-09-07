# All further development happens [there](https://github.com/luainkernel/snihook)


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
LUNATIK_DIR=$PWD
git checkout netfilter-hook
# dependencies (Debian / Ubuntu). `pahole` could need to be manually upgraded to higher version.
sudo apt install lua5.4 pahole linux-source
sudo cp /sys/kernel/btf/vmlinux /usr/lib/modules/`uname -r`/build/
cd /tmp ; tar xaf /usr/src/linux-source-VERSION.tar.bz2  # replace VERSION by relevant value
cd linux-source-VERSION/tools/bpf/resolve_btfids/        # idem
sudo mkdir -p /usr/src/linux-headers-`uname -r`/tools/bpf/resolve_btfids/
sudo cp resolve_btfids /usr/src/linux-headers-`uname -r`/tools/bpf/resolve_btfids/
cd $LUNATIK_DIR
make                             # builds modules
sudo make install                # installs modules into /lib/modules/lua
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

```sh
sudo lunatik spawn snihook/main                      # runs the Lua kernel script
echo "add github.com" | sudo tee /dev/sni_whitelist  # opens access to https://github.com (and subdomains of github.com)
echo "del github.com" | sudo tee /dev/sni_whitelist  # removes access to https://github.com (and subdomains not open otherwise)
sudo lunatik stop snihook/main                       # stops the Lua kernel script
```

Note: By default, unallowed domains will get logged (`journalctl -t kernel -g sniblock`), but not blocked.
To effectively block them, set `activate = true` in `/lib/modules/lua/snihook/config.lua`.
