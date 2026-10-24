# Blocker

A small Windows command line tool that blocks websites for every browser and app on the PC. It installs itself as a background service that starts on boot.

Written in [Odin](https://odin-lang.org) as a single file with no dependencies beyond the Windows API.

```
blocker block youtube.com reddit.com
blocker except music.youtube.com
blocker dns cloudflare_family
blocker install
```

## How it works

Blocker runs a small DNS server on `127.0.0.1:53` and `[::1]:53` and points the DNS settings of every connected network adapter at it.

- Lookups for blocked domains get a "no such domain" (NXDOMAIN) answer, so the site can't be reached.
- All other lookups are forwarded to the DNS provider you pick.
- Before changing an adapter, the original setting is saved to disk, so it can be restored even after a crash. When the service stops, the original settings are put back.
- Every 2 seconds the service rereads the config and checks the adapters, so changes apply right away and new networks (e.g. switching Wi-Fi) are picked up.

A rule matches the domain and all of its subdomains. If both a block rule and an exception match a name, the more specific one wins. So `block youtube.com` together with `except music.youtube.com` blocks `www.youtube.com` and `m.youtube.com` but allows `music.youtube.com`. You can paste a URL and only its domain is kept: `https://www.youtube.com/watch` is saved as `youtube.com`.

## Building

Requires the [Odin compiler](https://odin-lang.org/docs/install/).

```
odin build .
```

## Usage

```
blocker <command> [args]
```

| Command | Description |
| --- | --- |
| `help` | Print available commands and DNS providers |
| `install` | Install and start the background service |
| `uninstall` | Stop and remove the background service, restore DNS settings |
| `status` | Show blocked domains, exceptions, DNS provider and service state |
| `run` | Block in the current terminal instead of as a service (Ctrl+C stops) |
| `block <domain>...` | Block a domain and all of its subdomains |
| `unblock <domain>...` | Remove a domain from the block list |
| `except <domain>...` | Allow part of a blocked domain, e.g. `music.youtube.com` |
| `unexcept <domain>...` | Remove an exception |
| `dns [provider]` | Set the DNS provider for everything that isn't blocked, or list them |

Everything except `help`, `status` and listing DNS providers requires administrator rights. When run from a normal terminal they show a UAC prompt, run elevated in the background and print the result in the same terminal. `run` instead opens in a new administrator window, since it keeps running until you press Ctrl+C or close it.

Only one blocker can be active at a time: `run` refuses to start while the service is running, and `install` refuses while `run` is active.

Browsers keep their own DNS cache and open connections, so restart the browser if a blocked site still loads.

### Installing the service

Place `blocker.exe` where you want it to live (for example `C:\Program Files\blocker\`), then run:

```
blocker install
```

The service runs the executable from the location it was installed from, so don't move or delete it afterwards. To move it, run `blocker uninstall`, move the file and install again.

### DNS providers

| Name | Servers | Notes |
| --- | --- | --- |
| `default` | your network's | same as without blocker, used when none is set |
| `cloudflare` | 1.1.1.1, 1.0.0.1 | |
| `cloudflare_security` | 1.1.1.2, 1.0.0.2 | blocks malware |
| `cloudflare_family` | 1.1.1.3, 1.0.0.3 | blocks malware + adult content |
| `google` | 8.8.8.8, 8.8.4.4 | |
| `quad9` | 9.9.9.9, 149.112.112.112 | blocks malware |
| `opendns` | 208.67.222.222, 208.67.220.220 | |
| `opendns_family` | 208.67.222.123, 208.67.220.123 | blocks adult content |
| `cleanbrowsing_security` | 185.228.168.9, 185.228.169.9 | blocks malware |
| `cleanbrowsing_adult` | 185.228.168.10, 185.228.169.11 | blocks adult content |
| `cleanbrowsing_family` | 185.228.168.168, 185.228.169.168 | blocks adult content + proxies/VPNs |
| `adguard` | 94.140.14.14, 94.140.15.15 | blocks ads + trackers |
| `adguard_family` | 94.140.14.15, 94.140.15.16 | blocks ads + trackers + adult content |

Custom IPv4 servers work too: `blocker dns 192.168.1.1` or `blocker dns 9.9.9.9,149.112.112.112`.

With `default`, blocker forwards to the servers each adapter had before it took over: its static servers, or the ones DHCP handed out. `blocker status` shows which ones those are.

## Files

Everything lives in `C:\ProgramData\blocker\`:

| File | Contents |
| --- | --- |
| `config.txt` | the DNS provider, block list and exceptions, one entry per line (`dns cloudflare`, `block youtube.com`, `except music.youtube.com`) |
| `state.txt` | the original DNS settings of each adapter, while blocking is active |
| `blocker.log` | what the service is doing, including every blocked lookup; cleared once it grows past 1 MB |

## Limitations

- **Browser "secure DNS" can bypass it.** Firefox's built-in DNS-over-HTTPS is turned off automatically. Chrome, Edge and Brave don't switch to it on their own, but a browser where you've enabled it manually goes around blocker.
- **UDP only.** DNS over TCP isn't served, which rarely matters for browsing.
- **Upstream servers must be IPv4.**

## If websites stop loading

If blocker crashes while blocking, Windows can be left pointing at a DNS server that isn't running. The service restarts itself after a crash and restores leftover settings when it starts. Otherwise, fix it with either of these:

1. `blocker uninstall`
2. In Settings, go to Network, pick your adapter, and set "DNS server assignment" to Automatic (DHCP)

## Configuration

Other settings are constants at the top of `main.odin`. Change them and rebuild:

| Constant | Default | Description |
| --- | --- | --- |
| `TICK_INTERVAL_MS` | 2 seconds | How often the config and adapters are checked |
| `UPSTREAM_TIMEOUT` | 2 seconds | How long to wait for an upstream DNS server |
| `DEFAULT_DNS` | `default` | Provider used when none is set |
| `PROVIDERS` | see above | The named DNS providers |

## License

MIT, see [license.txt](license.txt).
