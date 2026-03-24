---
sidebar_position: 1
title: Manual mode
---

Manual mode is the interactive UI (prompts, menus, pickers). It starts when you run the CLI without a subcommand:

```bash
testbench-cli-reporter
```

You can pre-seed connection defaults so the prompts start with sensible values:

```bash
testbench-cli-reporter --server localhost:443 --login tt-admin --password admin
```

## Login flow

On startup the CLI prompts for:

1. **Server address** — validated as `hostname`, `hostname:port`, or `https://host:port/api/`
2. **Login name**
3. **Password**

## Main menu

After connecting, the main menu is assembled dynamically based on the detected TestBench server version and whether your account has administrator privileges.

```
┌──────────────────────────────────────────────────────┐
│  What do you want to do?                             │
├──────────────────────────────────────────────────────┤
│  Export JSON Report             (TestBench 4.x+)     │
│  Import JSON execution results  (TestBench 4.x+)     │
│  Export CSV Report              (TestBench ≥3.0.6.2) │
│  Export XML Report                                   │
│  Import XML execution results                        │
│  ▶ Administrator Actions        (admin only)         │
│  Browse Projects                                     │
│  Write history to config file                        │
│  Change connection                                   │
│  Quit                                                │
└──────────────────────────────────────────────────────┘
```

### Administrator submenu

Selecting **▶ Administrator Actions** opens a submenu:

```
┌─────────────────────────────────────────────────┐
│  What do you want to do?                        │
├─────────────────────────────────────────────────┤
│  Export Server Logs                             │
│  Export Project Users                           │
│  Request JWT Token           (TestBench 4.x+)   │
│  ◀︎ Back                                         │
└─────────────────────────────────────────────────┘
```

## Session keep-alive

The CLI automatically keeps the session alive by sending a heartbeat request every 5 minutes.
This ensures that the session does not expire due to inactivity while you are using the CLI.
BUT that also means, that a TestBench license is consumed during that time.

## Writing history to config file

The **Write history to config file** action serializes all completed actions from the current session into a JSON config file.
This file can then be used with `--config` to replay the same actions in automatic mode (see [Automatic mode](automatic-mode.md)).
