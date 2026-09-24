# Running a VTA as a macOS background service (launchd)

This page covers running `vta` on a Mac so that it starts when you log in,
restarts if it crashes, and writes its log to a file. It uses a launchd
**LaunchAgent**. A template is at
[`deploy/macos/org.openvtc.vta.plist`](../../deploy/macos/org.openvtc.vta.plist).

Set the VTA up first. The agent runs a VTA that has already been set up; it
does not set one up. Run `vta setup` (or `vta setup --from <file>`, see
[Non-interactive setup](non-interactive-setup.md)) in a terminal, then check
that `vta --config <path>` starts and serves before you hand it to launchd.

## Agent or daemon

| | LaunchAgent (`~/Library/LaunchAgents`) | LaunchDaemon (`/Library/LaunchDaemons`) |
|---|---|---|
| Starts | when you log in | at boot, before anyone logs in |
| Runs as | you | root, or the `UserName` you set |
| Can read your login Keychain | yes | no |

The default secrets backend is `keyring`, and on macOS that is your login
Keychain. A LaunchDaemon starts before the Keychain is unlocked, so it cannot
load the master seed and the VTA does not start. **Use a LaunchAgent unless
you have moved the seed off the Keychain.**

If the VTA has to be running before anyone logs in (for example on a headless
Mac mini), first move the seed to a backend that does not need a login
session (see [Secret-storage backends](secret-backends.md)), then install the
same plist into `/Library/LaunchDaemons` with a `UserName` key. `config_seed`
and `plaintext` meet that requirement only by keeping the seed on disk, so
they are not a like-for-like substitute for the Keychain.

## Paths must be absolute

launchd starts processes with `/` as the current directory, and it expands
neither `~` nor `$HOME` in a plist.

- **Config file.** Without `--config` or `VTA_CONFIG_PATH`, the VTA reads
  `./config.toml`, which here means `/config.toml`. The template passes
  `--config` with an absolute path.
- **Data directory.** `[store] data_dir` defaults to the relative path
  `data/vta` and resolves against the working directory. Either set it to an
  absolute path in `config.toml`, or keep `WorkingDirectory` in the plist set
  to the directory that `config.toml` sits in (as the template does).
- **Binary.** `cargo install` puts `vta` in `~/.cargo/bin`. launchd does not
  read your shell's `PATH`, so give the full path.

## Install

```sh
# Fill in the template's __HOME__ placeholders and install it.
sed "s|__HOME__|$HOME|g" deploy/macos/org.openvtc.vta.plist \
  > ~/Library/LaunchAgents/org.openvtc.vta.plist
plutil -lint ~/Library/LaunchAgents/org.openvtc.vta.plist

# Load it. RunAtLoad starts it immediately, and at every later login.
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.openvtc.vta.plist
```

Check the paths in the installed file if your binary, config or data are not
in the template's locations (`~/.cargo/bin/vta`, `~/.config/vta/`).

The **first** start under launchd may bring up a macOS dialog asking whether
`vta` may use your Keychain. Choose **Always Allow**. Until someone answers
it, the VTA waits at startup.

## Everyday commands

```sh
launchctl print gui/$(id -u)/org.openvtc.vta      # state, PID, last exit code
tail -f ~/Library/Logs/vta.log                   # the VTA logs to stderr
launchctl kickstart -k gui/$(id -u)/org.openvtc.vta   # restart
launchctl bootout gui/$(id -u)/org.openvtc.vta   # stop and unload
```

`bootout` sends SIGTERM, and the VTA shuts down cleanly on it. It exits 0,
so launchd does not restart it.

## Restart behaviour

The template sets `KeepAlive` to `{ SuccessfulExit = false }`: launchd
restarts the VTA after any **non-zero** exit and leaves a clean exit alone.

A startup refusal also exits non-zero, so it is retried too. That covers a
missing signing identity (see `--allow-degraded`), a Keychain that refused
access, and a config error. `ThrottleInterval` (30 s) keeps those retries
apart. If `launchctl print` shows the job restarting over and over, the reason
is in the last lines of `vta.log`; nothing on screen reports it.

Do not change this to a bare `<key>KeepAlive</key><true/>`. That also
restarts after a clean shutdown, so `launchctl kill` could never stop the
VTA.

A backup restore (`vta/backup/*`, see [Backup and restore](backup-restore.md))
re-executes the process in place to apply the staged state. The PID stays the
same, so launchd sees no exit.

## Upgrading the binary

```sh
cargo install --path vta-service --force   # or however you install vta
launchctl kickstart -k gui/$(id -u)/org.openvtc.vta
```

The running process keeps the old binary until it restarts, so restart it
after every install. To confirm what is running, look for the new version in
the `vta.log` startup lines.

A rebuilt binary counts as a new application for Keychain access control, so
the Keychain dialog may come back after an upgrade. While the dialog is open,
the VTA is not running.

## Offline commands

Offline commands open the fjall store directly: `vta approvals …`,
`vta services …`, `vta did-mgmt …`, `vta acl …`, `vta keys …` and the rest.
They cannot run while the daemon holds the store's lock. Stop the agent first,
then start it again afterwards:

```sh
launchctl bootout gui/$(id -u)/org.openvtc.vta
vta --config ~/.config/vta/config.toml approvals list
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/org.openvtc.vta.plist
```

## Logs

The VTA writes its log to stderr, and the template sends stderr and stdout to
`~/Library/Logs/vta.log`, where Console.app can also show it. Set the level
with `RUST_LOG` (an `EnvFilter` directive, which overrides `[log] level`) and
the format with `VTA_LOG_FORMAT` (`text` or `json`) in the plist's
`EnvironmentVariables`.

launchd does not rotate this file. To rotate it, add a `newsyslog` rule:

```sh
# /etc/newsyslog.d/vta.conf  (needs sudo)
# logfile                                   mode count size(KB) when flags
/Users/<you>/Library/Logs/vta.log           644  5     10240    *    N
```

The `N` flag tells newsyslog not to signal any process. The VTA keeps its
file handle open after rotation, so run `launchctl kickstart -k …` for new
lines to go to the fresh file.

## Removing the service

```sh
launchctl bootout gui/$(id -u)/org.openvtc.vta
rm ~/Library/LaunchAgents/org.openvtc.vta.plist
```

This removes only the launchd job. It leaves the config, data directory and
Keychain entry in place.
