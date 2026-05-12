# SSH Collection

Linwarden supports two SSH collection modes.

## Static Mode

Static mode is the default:

```bash
linwarden scan --sshd-mode static
```

It reads `sshd_config` and simple `Include` directives directly. This works for offline roots, mounted images, containers, and tests. It does not evaluate OpenSSH `Match` blocks.

## Effective Mode

Effective mode executes OpenSSH:

```bash
linwarden scan --sshd-mode effective
```

Linwarden runs:

```bash
sshd -T -f /etc/ssh/sshd_config
```

To evaluate OpenSSH `Match` blocks for a specific connection context, pass one or more `--sshd-match` entries:

```bash
linwarden scan --sshd-mode effective --sshd-match user=deploy --sshd-match addr=203.0.113.10
```

Linwarden joins those entries and passes them to OpenSSH as:

```bash
sshd -T -f /etc/ssh/sshd_config -C user=deploy,addr=203.0.113.10
```

Use `--sshd-binary` for non-standard paths or test wrappers:

```bash
linwarden scan --sshd-mode effective --sshd-binary /usr/sbin/sshd
```

`--sshd-mode auto` tries effective mode and falls back to static mode if `sshd -T` cannot run.
