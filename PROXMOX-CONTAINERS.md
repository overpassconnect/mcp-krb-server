# Kerberos in Proxmox LXC containers

Two independent faults stop GSSAPI SSH into an unprivileged Proxmox container.
Both are invisible in the usual places, and the second one cannot be seen until
the first is fixed, so they are routinely met one after the other and mistaken
for a single intermittent problem.

Neither is specific to this kit. Any FreeIPA realm with containers hits them.

## Fault 1: an all-numeric first hostname label

Containers named `6.vms`, `10.vms` and so on are common, and Proxmox writes the
short first label into `/etc/hostname` at **every container start**.

glibc parses an all-numeric first label as an IPv4 literal, so `10` becomes
`0.0.0.10` and can never canonicalise back to the FQDN. sshd then cannot match
its own name against the `host/<fqdn>` principal in its keytab, and with
`GSSAPIStrictAcceptorCheck` at its default `yes` it **rejects valid tickets**.

**Symptom.** `Permission denied` with `gssapi-with-mic` offered and refused.
Authentication never completes. It appears only after a restart, which may be
weeks after the container was built.

**Fix**, once per container, over a password login or the Proxmox console:

```sh
sudo hostnamectl set-hostname <name>.<domain>
sudo touch /etc/.pve-ignore.hostname
sudo systemctl restart sshd
```

`.pve-ignore.hostname` is the load-bearing part. Without it Proxmox rewrites
`/etc/hostname` at the next start and the fix silently comes undone.

Confirm with `hostname -f`, which must print the FQDN, and
`sudo sshd -T | grep gssapistrictacceptorcheck`, which should still say `yes`.

**Do not disable the acceptor check instead.** `GSSAPIStrictAcceptorCheck no`
makes the symptom disappear without fixing anything, and hides the same fault on
every host that inherits the drop-in.

**Never put the marker in a golden template.** With `/etc/.pve-ignore.hostname`
present in a template, Proxmox cannot set the name at clone time either, so every
clone boots carrying the template's name.

## Fault 2: realm IDs outside the container's ID map

An unprivileged container maps only `100000-165535` by default. A FreeIPA realm
allocates uids and gids from a much higher base, so every realm account falls
outside every mapping the container has.

Kerberos never consults the ID map, so authentication **succeeds** and the
session dies one step later. That is what makes this hard to recognise.

**Symptom.** In the container's `journalctl -u ssh`:

```
sshd: Accepted gssapi-with-mic for <user> ... (krb5_kuserok)
sshd: fatal: initgroups: <user>: Invalid argument
```

From the client, and note that even `ssh -N`, which requests no session channel
at all, fails the same way:

```
Authenticated to <host> using "gssapi-with-mic".
client_loop: send disconnect: Broken pipe
```

`Could not create private keyring session` in the sssd log is a normal
unprivileged-container warning and is not the cause.

**Fix.** In `/etc/pve/lxc/<CTID>.conf` on the hypervisor, **all four lines**,
substituting your realm's ID base and range:

```
lxc.idmap: u 0 100000 65536
lxc.idmap: g 0 100000 65536
lxc.idmap: u <BASE> <BASE> <RANGE>
lxc.idmap: g <BASE> <BASE> <RANGE>
```

The first two are not optional. Declaring any `lxc.idmap` stops the default
mapping being implicit, so the base range has to be spelled out too.

Find `<BASE>` from the realm rather than guessing: `ipa idrange-find` on an IPA
server, or `id <someuser>` on an enrolled host and round down.

The hypervisor must also delegate those ranges, in `/etc/subuid` and
`/etc/subgid`:

```
root:<BASE>:<RANGE>
```

Then:

```sh
pct stop <CTID> && pct start <CTID>
```

A running container cannot pick this up, and neither can a reboot from inside.
Expect `Connection reset by peer` for a minute or two while it comes back.

**Before you restart.** Changing the map changes what every existing file in that
container's rootfs maps to. Files created under the old mapping keep their
on-disk ownership and may end up owned by an unexpected ID. Snapshot a container
holding real data, and read the full `pct config` for bind mounts rather than
only grepping for the idmap lines.

## Checking

Inside the container, `id <user>` should show the realm uid and the full group
list. Compare a broken container against a working one:

```sh
pct config <CTID> | grep -Ei 'unprivileged|idmap'
```

The working one carries the second pair of ranges; the broken one does not.

To see what the **running** container is actually enforcing, which is not
necessarily what the config file says:

```sh
cat /proc/$(lxc-info -n <CTID> -p -H)/uid_map
```

Two lines where the config has four means the container was never restarted
after the change, and a restart is the whole fix.

## Not these two

A third failure wears the same clothes and is neither of the above. If
`krb5_kuserok` passes and the log then shows:

```
pam_sss(sshd:account): Access denied for user <user>: 4 (System error)
```

that is SSSD, not the container. `4` is `PAM_SYSTEM_ERR`, meaning the HBAC rules
could not be **evaluated**, as opposed to being evaluated and denying (`6`).
Check whether the backend is alive:

```sh
journalctl -u sssd | grep -i watchdog
```

Repeated `terminated by own WATCHDOG` means `sssd_be` is wedged and respawning.
`id <user>` keeps working throughout, because NSS answers from the cache, so the
container looks healthy while nobody can log in. `systemctl restart sssd` clears
it. Do not go looking at the ID map for this one.
