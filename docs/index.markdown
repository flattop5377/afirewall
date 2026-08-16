---
layout: home
title: A Pure Netfilter Firewall
---

**A host firewall you configure from Ansible with one `lineinfile` task, that loads on boot without
you wiring anything up, and that never touches iptables.**

*Status: Beta — feature complete, in production on the maintainer's own hosts.*
[Open issues](https://github.com/flattop5377/afirewall/issues)

---

## Configure it from Ansible

This is the reason afirewall exists, and everything else follows from it.

The configuration is a flat list of `<direction>.<service>: enable` lines. No nesting, no ordering,
no syntax to get wrong. That shape is chosen for one purpose: **a play can compose a host's firewall
by appending a single line**, so two roles that know nothing about each other can each open the port
they need without colliding, and without either one having to know the whole picture.

```yaml
- name: "this host answers on 443"
  ansible.builtin.lineinfile:
    path: /etc/afirewall/afirewall.conf
    line: "inbound.https: enable"
    regexp: "^inbound.https:.*$"
  register: firewall

- name: "apply it"
  ansible.builtin.command: /usr/sbin/afirewall reload
  when: firewall.changed
```

That is the whole integration. `register` plus `when: changed` means a converged host stays quiet
and only a real change reloads the ruleset.

### The pattern that makes it declarative

Adding a flag is easy. Making a host's firewall follow from *what the host is* takes one more step,
and it is worth taking: **restore the packaged defaults at the start of the run, then let each role
add what it needs.**

```yaml
# early, before any role has spoken
- name: "start from a known state"
  ansible.builtin.copy:
    src: afirewall.conf          # your baseline, in your repo
    dest: /etc/afirewall/afirewall.conf

# later, in the role that owns the service
- name: "mail arrives here"
  ansible.builtin.lineinfile:
    path: /etc/afirewall/afirewall.conf
    line: "{{ item }}: enable"
    regexp: "^{{ item }}:.*$"
  loop:
    - inbound.smtp
    - outbound.smtp
```

Because the run starts from a fixed baseline, the end state is a function of **which roles ran**.
Drop a host out of a group and the next converge stops opening that group's port — with no central
table mapping groups to rules, and nothing to remember to undo. Each fact stays in the role that
owns it.

### Reading back what the kernel is doing

The configuration file says what you asked for. The kernel says what you got, and they are different
questions:

```yaml
- name: "the firewall is actually loaded"
  ansible.builtin.command: nft list tables
  register: nft
  changed_when: false

- ansible.builtin.assert:
    that:
      - "'a-firewall-inbound-ipv4' in nft.stdout"
      - "'a-firewall-inbound-ipv6' in nft.stdout"
```

A package that is installed is not a firewall that is running. Ask.

---

## Pure nft. No iptables. Not one line.

nftables replaced iptables — it is in the kernel, it is what `iptables` itself is a compatibility
shim over on any current distribution, and new work happens there. afirewall generates nft and
nothing else.

It is a rule rather than a default, and it is kept even when it narrows the options — because
**one tool writing packet filter rules is the arrangement in which reading the ruleset tells you
what the host does.** A ruleset you can read end to end is worth more than one assembled from two
places.

Running alongside fail2ban works well; point its `banaction` at the nftables backend and both
tools stay in the same view:

```
# /etc/fail2ban/jail.local
[DEFAULT]
banaction = nftables[type=multiport]
banaction_allports = nftables[type=allports]
```

**Both directions default to drop.** Inbound *and* outbound, with no blanket
`ct state established,related accept` covering everything. A service's reply path is opened by that
service's own flag. That is deliberately unforgiving — a flag you forgot is a dead service rather
than a quiet one — and it is the whole reason the configuration is worth reviewing.

**And it stays out of the way of rules you add yourself.** afirewall keeps to four tables of its
own, and `afirewall stop` deletes exactly those — it never flushes the ruleset, so nothing it does
removes rules you or another tool put there. Its input chain sits at priority 20, behind the
standard filter hook, which is why a fail2ban ban still takes effect: netfilter requires a packet to
survive *every* base chain at a hook, so neither tool can open a port the other closed.

### What it does not cover

A host, and only a host. afirewall hooks `input` and `output`. Traffic a machine *routes* — a
published container port, a DNAT to somewhere else — passes the `forward` hook, where this package
installs nothing and the kernel's own default is accept. If you need the forwarded path filtered,
this is not yet the tool for it.

---

## It persists itself

afirewall installs as a **`netfilter-persistent` plugin**. There is no unit to enable, no
`nft -f` in a cron job, no `/etc/nftables.conf` to hand-edit. Install it, configure it, and it is
there after a reboot.

```
/usr/share/netfilter-persistent/plugins.d/afirewall
```

Which means the ruleset is regenerated from your configuration at boot rather than replayed from a
dump. Edit the config, reboot, and you get what the config says — not what the ruleset happened to
be when somebody last ran `save`.

**One thing worth knowing.** Debian's stock `/etc/nftables.conf` opens with `flush ruleset`, which
clears *every* table in the kernel and then installs chains that state no policy — meaning accept.
If `nftables.service` happens to start after the persistence plugin has restored your firewall, the
host is left open while `systemctl status nftables` reads green. Since afirewall persists itself,
the simplest arrangement is to let one thing restore the ruleset:

```sh
sudo systemctl disable --now nftables.service
```

---

## What it refuses before you configure anything

These chains run ahead of every service decision and read no flag at all, so a host gets them from
installing the package:

| chain | drops | |
|---|---|---|
| `SPOOFING` | source addresses that cannot legitimately arrive on the external device | both families |
| `INVALID_FLAGS` | TCP flag combinations [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html) does not permit — no flags at all, FIN with SYN, the scan fingerprints | both families |
| `PORT_ZERO` | port zero, in either direction | both families |
| `FRAGMENTS` | what should not be fragmented | IPv4 only |

Every one carries a **named counter**, so `nft list counters` tells you whether a rule has ever
fired. A drop rule that matches nothing looks exactly like one that is working, and this is the
difference.

ICMP is **limited, not closed** — 10/second per source. Blocking it wholesale breaks network
discovery and troubleshooting for whoever inherits the host, and the budget is generous against real
work: `ping` sends 1/second, and a traceroute's replies each arrive from a different router. Path
MTU discovery is carved out above the limit in both families, because a black-holed connection is
not a diagnostic.

---

## Install

```sh
sudo curl -fsSL -o /etc/apt/sources.list.d/flattop5377.sources \
  https://raw.githubusercontent.com/flattop5377/debrepo/master/conf/flattop5377.sources
sudo apt update
sudo apt install afirewall
```

The sources file is deb822 with the signing key **inline**, so there is no key dance and nothing is
trusted repository-wide. The suite is codename-neutral: the package is `Architecture: all` and pure
Python, so one build serves every Debian.

Check what you got before trusting it:

```sh
apt policy afirewall
apt-cache show afirewall | grep -E '^(Package|Version|Depends)'
```

It requires **nftables 1.0.2 or newer**. That floor is measured rather than assumed — a full
generated ruleset is parsed by `nft -c` on each version, and 0.9.8 and earlier reject it.

## Configure

Edit `/etc/afirewall/afirewall.conf` and run `afirewall reload`. Inbound and outbound are separate,
so enable the direction you actually need:

```
inbound.ssh: enable
outbound.ssh: enable
inbound.https: enable
outbound.dns: enable
```

A service with no template yet is an issue worth opening — the set that ships is the set somebody
needed, not a claim about what exists.

---

## Where this came from

This is a small project standing on other people's work, and the reasoning in the rules is
traceable to published sources rather than to folklore. If you disagree with a rule, these are what
to argue with.

**Firewalls this learned from**

* [Advanced Policy Firewall](https://www.rfxn.com/projects/advanced-policy-firewall/) — the shape of
  a policy-based firewall with a plain configuration file
* [SoByte, *Understanding netfilter and iptables*](https://www.sobyte.net/post/2022-04/understanding-netfilter-and-iptables/)

**netfilter and nftables**

* [nftables wiki — Netfilter hooks](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks)
* [nftables wiki — Meters](https://wiki.nftables.org/wiki-nftables/index.php/Meters)
* [nftables wiki — Matching connection tracking metainformation](https://wiki.nftables.org/wiki-nftables/index.php/Matching_connection_tracking_stateful_metainformation)
* [nftables wiki — Quick reference, `ct`](https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes#Ct)
* [netfilter Packet Filtering HOWTO](https://netfilter.org/documentation/HOWTO/packet-filtering-HOWTO-7.html)
* [nftables source — `expression.h`](https://git.netfilter.org/nftables/log/include/expression.h?id=4e0026dc8d8693aaf2caf8df6d657a116734e84e&showmsg=1)

**Standards the rules are derived from**

* [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html) — TCP. The permitted flag combinations,
  which is what `INVALID_FLAGS` drops the complement of
* [RFC 4890](https://www.rfc-editor.org/rfc/rfc4890.html) — filtering ICMPv6, and why neighbour
  discovery must not be rate-limited away
* [RFC 6633](https://www.rfc-editor.org/rfc/rfc6633.html) — deprecating ICMP Source Quench, which is
  why no rule accepts it

**IANA registries**

* [ICMP parameters](https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml) and
  [ICMPv6 parameters](https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml) —
  the types accepted, chosen from the registry rather than from a list found elsewhere
* [TCP parameters](https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1) —
  including the options this deliberately does *not* drop
* [IPv4 special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml)
  and [IPv6 special-purpose registry](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml) —
  the anti-spoofing lists, taken from the "Globally Reachable" column, with the entries deliberately
  left out named in the list files

**Debian packaging**

* [Debian packages in git](https://honk.sigxcpu.org/piki/development/debian_packages_in_git/)
* [Russ Allbery — Debian packaging with git](https://www.eyrie.org/~eagle/notes/debian/git.html)
* [debmake documentation](https://www.debian.org/doc/manuals/debmake-doc/index.en.html)
* [DEP-14](https://dep-team.pages.debian.net/deps/dep14/) — the branch layout this repository uses
