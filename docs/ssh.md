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

Use `--sshd-binary` for non-standard paths or test wrappers:

```bash
linwarden scan --sshd-mode effective --sshd-binary /usr/sbin/sshd
```

`--sshd-mode auto` tries effective mode and falls back to static mode if `sshd -T` cannot run.
