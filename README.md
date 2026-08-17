# A pure Netfilter Firewall on Linux
## Website
[afirewall](https://flattop5377.github.io/afirewall/)
## Goals
   - Be resonably secure
   - Be easy to install, configure, and maintain
   - Be Ansible friendly
   - Use common tools and formats
## Description
A firewall that uses nft only, is easily configured through Ansible, has some sane defaults for security, doesn't restrict the full flexibility of other pure netfilter firewall configuration, uses common or simple tools and formats, and integrates nicely with existing networking architecture.
## Using it

Three commands cover almost everything:

```
$ afirewall enable inbound.smtp     # open a service
{"changed": true, "flag": "inbound.smtp", "was": "disable", "now": "enable"}

$ afirewall disable inbound.smtp    # close it again
$ afirewall reload                  # rebuild the ruleset and load it
```

`enable` and `disable` only edit the configuration — **nothing reaches the kernel until `reload`**.
They refuse a flag nothing declares, so a typo is an error rather than a line that persists and
governs nothing. They print one JSON object and exit 0 whether or not anything changed, which is
what lets a configuration manager gate a single reload on `changed` and leave a converged host
quiet.

For a service this package does not ship a rule for:

```
$ afirewall add-service gemini --inbound --tcp 1965 \
      --posture enforce --because "an anonymous peer that replaces itself"
$ afirewall enable inbound.gemini
$ afirewall reload
```

`--posture` and `--because` are required and have no default. A rate limit that refuses excess and
one that merely counts it look identical in a ruleset, so this package will not write one without
being told which it is and why.

Seeing what it has actually stopped:

```
$ sudo afirewall counters

inbound                                     ipv4        ipv6
  source could not have arrived here         625           0
  not addressed to this host                   0           0
  TCP flags RFC 9293 forbids                   0           0
  non-first fragments                          0           -
  port zero, either direction                  0           0
```

Both families side by side, because that is where the asymmetries are — `nft list counters` prints
them in separate blocks a screen apart. A `-` means the counter is not loaded at all, which is not
the same as a zero: the host above is running a release with no IPv6 fragment chain in it.

For something that wants the numbers rather than a person:

```
$ sudo afirewall counters --json
{"counters": [{"direction": "inbound", "family": "ipv4",
               "name": "NUMBER_OF_SPOOFS_DROPPED",
               "label": "source could not have arrived here",
               "packets": 625, "bytes": 41300}, ...]}
```

One object, one line, each record carrying its own label and both packets and bytes. **A counter
that is not loaded has no record at all** — the same distinction the table draws with `-`, so a
consumer can tell "the rule is not there" from "the rule saw nothing".

**A zero is not a clean bill of health.** It has three causes and nothing on the host can tell them
apart: nothing of that kind arrived, the rule cannot be reached, or something upstream dropped it
first. `tools/lab.py` settles it by sending the traffic on purpose.

`afirewall --help` lists everything; most of the rest of that list is netfilter-persistent's
vocabulary arriving from the system rather than from you.

## What this covers

A host, and — unless you ask otherwise — only a host. afirewall hooks `input` and `output`, both
with `policy drop`, plus a `prerouting` chain that drops incoherent traffic before anything else
looks at it.

**It hooks `forward` only if you declare something forwarded.** Traffic a machine *routes* — a
published container port, a tunnel to somewhere else — passes no chain this package installs until
a service says otherwise, and the kernel's own default at that hook is accept. So by default
afirewall governs what the machine itself answers and nothing it passes along.

Declaring a forwarded service changes that, in both directions at once:

```
$ afirewall add-service app --forward --tcp 8080 --to 10.99.0.2 \
      --posture instrument --because "a service I run, on a machine I run"
$ afirewall enable forward.app
```

**The first forwarded service you enable is a one-way door.** Until then this host has no chain at
the forward hook and passes everything it routes; afterwards a chain exists there with `policy
drop`, and anything else being forwarded — a container runtime's published ports above all — is
refused unless it is declared too. `afirewall enable` says so at the moment you cross it.

**Translation is not built.** A namespace or container reached by DNAT from a private range needs a
`nat` table, and this package has never emitted one. What is covered is the *routed* case: a
destination this host can already route to.

## Running alongside other things that write packet filter rules

afirewall keeps to its own tables — `a-firewall-inbound-ipv4`, `a-firewall-outbound-ipv4` and their
IPv6 pair, plus an `a-firewall-forward-*` pair that exists only while something forwarded is enabled
— and `afirewall stop` deletes exactly those. It never flushes the ruleset, so nothing it does
removes rules you or another tool put there. Two cases are worth knowing about anyway.

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

The package's own tests need no root. The spec drills under `drills/` do more, and the ones that
matter most need both:

```
$ sudo .venv/bin/python -m pytest          # the drills, including the lab
$ sudo .venv/bin/python tools/lab.py       # the lab on its own
```

`tools/lab.py` builds three network namespaces — an outside, a host running this package's real
ruleset, and a service behind that host — and fires known-bad traffic at it: a spoofed source, a
NULL-flag segment, port zero, a non-first fragment, in both families, plus a forwarded service that
should be reachable and a port that should not. It is the only instrument here that can show a
counter fires, because a counter read against ambient traffic cannot tell a rule that works from one
nothing has aimed anything at.
