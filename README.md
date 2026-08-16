# A pure Netfilter Firewall on Linux
## Website
[afirewall](https://flattop5377.github.io/afirewall/)
## Goals
   - Be resonably secure
   - Be easy to install, configure, and maintain
   - Be Ansible friendly
   - Use common tools and formats
## What this covers

A host, and only a host. afirewall hooks `input` and `output`, both with `policy drop`, plus a
`prerouting` chain that drops incoherent traffic before anything else looks at it.

**It does not hook `forward`.** Traffic a machine *routes* — a published container port, a DNAT to
another host, anything crossing a tunnel to somewhere else — does not pass through any chain this
package installs, and the kernel's own default at that hook is accept. So on a machine with
`ip_forward` turned on, afirewall governs what the machine itself answers and nothing it passes
along. If you need the forwarded path filtered, this is not yet the tool for it.

## Running alongside other things that write packet filter rules

afirewall keeps to its own four tables — `a-firewall-inbound-ipv4`, `a-firewall-outbound-ipv4` and
their IPv6 pair — and `afirewall stop` deletes exactly those. It never flushes the ruleset, so
nothing it does removes rules you or another tool put there. Two cases are worth knowing about
anyway.

### fail2ban

fail2ban works alongside afirewall without any configuration: a ban lands in the `filter` table at
priority 0, ahead of afirewall's input chain at priority 20, so the ban takes effect. Netfilter
requires a packet to survive *every* base chain at a hook, so neither tool can open a port the other
closed.

**But Debian's default `banaction` is iptables**, and installing afirewall to get a pure-nftables
host and then leaving that default gives you both. If that matters to you, pin it:

```
# /etc/fail2ban/jail.local
[DEFAULT]
banaction = nftables[type=multiport]
banaction_allports = nftables[type=allports]
```

afirewall does not write this for you. Changing another package's configuration is not a firewall's
job, and a package that edited `/etc/fail2ban` would be doing something you did not ask for.

### `nftables.service`

Debian ships `/etc/nftables.conf` beginning with `flush ruleset`, which deletes **every** table in
the kernel, afirewall's included, and then installs a `table inet filter` whose chains state no
policy — meaning accept. If `nftables.service` starts after the ruleset has been restored, the host
is left with no firewall and chains that admit everything, while the service reads as active.

afirewall persists through `netfilter-persistent`, which it installs itself as a plugin. It does not
need `nftables.service`, and enabling both is what creates the hazard:

```
# systemctl disable nftables.service
```

Leave it enabled only if you have made `/etc/nftables.conf` safe to load — an empty file will do —
and know which of the two runs last.

## Developer instructions
### Python environment setup
```
$ python3 -m venv .venv
$ . .venv/bin/activate
$ python3 -m pip install -r requirements.txt
```
### Tests
```
$ python3 -m unittest discover
```
