# PasswordRotator

A Windows utility that rotates a local account password every 10 minutes while keeping autologon enabled.

## Overview

PasswordRotator keeps a single local Windows account's password unknown to any human while still allowing that account to log in, install, and run software. It does this by rotating the account password to a fresh strong random value every 10 minutes (via a SYSTEM scheduled task) and keeping Windows autologon enabled so that power-on lands directly at the desktop.

## Features

- **Cryptographically strong passwords**: Generates 24+ character passwords with upper/lowercase letters, digits, and symbols
- **Automatic rotation**: Password rotates every 10 minutes via SYSTEM scheduled task
- **Autologon support**: Keeps Windows autologon enabled for seamless access
- **LSA secure storage**: Password stored in LSA private secret, not registry
- **UAC compatibility**: Sets UAC ConsentPromptBehaviorAdmin=5 for secure elevation

## Security Considerations

### What It Defends Against
- Humans learning the password
- Interactive logon guessing/brute force
- Credential phishing
- Password reuse across machines

### What It Does NOT Defend Against
- Attackers who ALREADY have local admin/SYSTEM access on the machine (they can recover the password)

## Installation

```powershell
# Run as Administrator
.\PasswordRotator.exe --install

# Run once to set initial password (or reboot)
.\PasswordRotator.exe --rotate
```

## Usage

```
PasswordRotator.exe --install     Register SYSTEM tasks, enable autologon, set UAC=5 (requires admin)
PasswordRotator.exe --rotate      Rotate the password now and refresh autologon (runs as SYSTEM)
PasswordRotator.exe --uninstall   Remove tasks and disable autologon (password is left random, not blanked)
```

## Building

```powershell
# Run the build script
.\build.ps1

# Or build manually
dotnet publish -c Release -o ./releases/0.0.2
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.