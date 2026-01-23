# SSH Tunnel User Manager

Create restricted SSH users that can only create tunnels (SOCKS proxy, local port forwarding).

## Features

- Creates system users with no shell access, no home directory
- Configures sshd with hardened settings for tunnel users
- Supports both password and SSH key authentication
- Auto-generates secure passwords in interactive mode
- Installs and configures fail2ban for brute-force protection
- Blocks cron/at access for tunnel users
- Users can only create `-L` (local) and `-D` (SOCKS) tunnels, not `-R` (remote)

## Installation

### Quick Install (from releases)

```bash
curl -sSL https://raw.githubusercontent.com/net2share/sshtun-user/main/install.sh | sudo bash
```

### Build from Source

```bash
go build -o sshtun-user ./cmd/sshtun-user
sudo mv sshtun-user /usr/local/bin/
```

## Usage

### Interactive Mode

```bash
sudo sshtun-user
# or
sudo sshtun-user <username>
```

Prompts for username (if not provided), authentication method, and password. If fail2ban is not installed, prompts to install it.

### Non-Interactive Mode

```bash
# With password (warning: visible in process list)
sudo sshtun-user <username> --insecure-password <password>

# With SSH public key
sudo sshtun-user <username> --pubkey "ssh-ed25519 AAAA..."

# SSHD hardening only (no user creation)
sudo sshtun-user --configure-only

# Disable fail2ban
sudo sshtun-user <username> --no-fail2ban
```

**Note:** In non-interactive mode (when using `--insecure-password` or `--pubkey`), the username argument is required.

### Options

| Option                       | Description                                    |
| ---------------------------- | ---------------------------------------------- |
| `--insecure-password <pass>` | Set password (visible in process list/history) |
| `--pubkey <key>`             | Set SSH public key for key-based auth          |
| `--no-fail2ban`              | Skip fail2ban installation/configuration       |
| `--configure-only`           | Only apply sshd hardening, no user creation    |
| `--version`, `-v`            | Show version                                   |
| `--help`, `-h`               | Show help                                      |

## Client Usage

After creating a tunnel user, clients can connect:

```bash
# SOCKS proxy on local port 1080
ssh -D 1080 -N tunneluser@server

# Local port forwarding
ssh -L 8080:internal-host:80 -N tunneluser@server
```

For key-based auth, add `-i <private_key>`.

## What Gets Configured

### SSHD Hardening (`/etc/ssh/sshd_config.d/99-tunnel-*.conf`)

- Modern crypto algorithms only (curve25519, chacha20-poly1305, aes256-gcm)
- Connection rate limiting and keepalive
- Disabled: X11 forwarding, agent forwarding, remote forwarding, PTY
- ForceCommand prevents shell access
- Verbose logging for audit trails

### User Groups

- `sshtunnel-password`: Users with password authentication
- `sshtunnel-key`: Users with SSH key authentication

### Additional Restrictions

- Users are added to `/etc/cron.deny` and `/etc/at.deny` to prevent scheduled tasks
- Users are created as system users with `/usr/sbin/nologin` shell

### fail2ban (`/etc/fail2ban/jail.d/sshtunnel.conf`)

- Bans IPs after 5 failed attempts in 10 minutes
- 1-hour ban, doubling for repeat offenders (max 1 week)

## Supported Distributions

- Fedora, RHEL, CentOS, Rocky, Alma, Oracle Linux (dnf/yum)
- Debian, Ubuntu, Linux Mint, Pop!\_OS (apt)
- Arch, Manjaro, EndeavourOS (pacman)
- openSUSE, SLES (zypper)
- Alpine (apk)
