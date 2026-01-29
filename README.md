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
- Interactive menu for easy management
- Full user lifecycle: create, update, list, delete
- Clean uninstall of users and configuration

## Installation

### Quick Install (from releases)

```bash
curl -sSL https://raw.githubusercontent.com/net2share/sshtun-user/main/install.sh | sudo bash
```

### Build from Source

```bash
go build -o sshtun-user .
sudo mv sshtun-user /usr/local/bin/
```

## Usage

### Interactive Menu

Run without arguments to get an interactive menu:

```bash
sudo sshtun-user
```

The menu provides options to:
1. Create tunnel user
2. Update tunnel user
3. List tunnel users
4. Delete tunnel user
5. Configure sshd hardening
6. Uninstall

**Note:** Run "Configure sshd hardening" (option 5) first before creating users.

### CLI Commands

```bash
# Apply sshd hardening (run this first)
sudo sshtun-user configure

# Create a new tunnel user (interactive)
sudo sshtun-user create myuser

# Update an existing user (interactive)
sudo sshtun-user update myuser

# List all tunnel users
sudo sshtun-user list

# Delete a tunnel user
sudo sshtun-user delete myuser

# Uninstall - delete all users
sudo sshtun-user uninstall users

# Uninstall - remove configuration only (requires no users)
sudo sshtun-user uninstall config

# Uninstall - complete (users + configuration)
sudo sshtun-user uninstall all
```

### Non-Interactive Mode

```bash
# Create user with password (warning: visible in process list)
sudo sshtun-user create myuser --insecure-password "mypassword"

# Create user with SSH public key
sudo sshtun-user create myuser --pubkey "ssh-ed25519 AAAA..."

# Update user password
sudo sshtun-user update myuser --insecure-password "newpassword"

# Update user SSH key
sudo sshtun-user update myuser --pubkey "ssh-ed25519 AAAA..."

# Skip fail2ban during configure
sudo sshtun-user configure --no-fail2ban
```

### Options

| Option                       | Description                                    |
| ---------------------------- | ---------------------------------------------- |
| `--insecure-password <pass>` | Set password (visible in process list/history) |
| `--pubkey <key>`             | Set SSH public key for key-based auth          |
| `--no-fail2ban`              | Skip fail2ban installation/configuration       |
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

Tunnel users are detected by their membership in these groups.

### Additional Restrictions

- Users are added to `/etc/cron.deny` and `/etc/at.deny` to prevent scheduled tasks
- Users are created as system users with `/usr/sbin/nologin` shell

### fail2ban (`/etc/fail2ban/jail.d/sshtunnel.conf`)

- Bans IPs after 5 failed attempts in 10 minutes
- 1-hour ban, doubling for repeat offenders (max 1 week)

## Uninstall

The uninstall command provides options to clean up:

```bash
# Delete all tunnel users only
sudo sshtun-user uninstall users

# Remove configuration only (groups, sshd config) - requires no users
sudo sshtun-user uninstall config

# Complete uninstall (users + sshd config + groups)
sudo sshtun-user uninstall all
```

Or use the interactive menu for guided uninstall with confirmation prompts.

## Supported Distributions

- Fedora, RHEL, CentOS, Rocky, Alma, Oracle Linux (dnf/yum)
- Debian, Ubuntu, Linux Mint, Pop!\_OS (apt)
- Arch, Manjaro, EndeavourOS (pacman)
- openSUSE, SLES (zypper)
- Alpine (apk)
