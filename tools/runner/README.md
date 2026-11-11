# Disposable runners

`runner.sh` runs GitHub Actions jobs of this repository on a Linux PC, each in a VM of its own that is deleted after
the job. Only the config file and the token file stay on the PC.

- `prepare` builds a base VM with Multipass: Ubuntu, Docker, build tools and the runner. It is stopped and only cloned.
- `run` takes jobs one at a time. For each it clones the base VM, registers the clone for exactly one job
  (`--ephemeral`), and deletes the clone and its registration afterwards. `once` does the same for one job.
- The VMs reach the internet, but no private network and nothing on the host except DHCP and DNS (an nftables table
  `lanlord_runner`, set again by `run` and `once`).
- `status` shows the VMs and the registered runners, `clean` deletes them and the firewall table.

## GitHub first, then this PC

The jobs in `ci.yml` and `codeql.yml` run on `${{ vars.RUNNER || 'ubuntu-latest' }}`: GitHub's runners, unless the
repository variable `RUNNER` names other ones. GitHub cannot give a job to whichever runner is free first, so `run`
watches the queue instead:

- A job that waits longer than `WAIT` minutes for GitHub's runners: `run` sets `RUNNER` to the first label of this
  runner, cancels the waiting runs and runs their unfinished jobs again, now here.
- After `BACK_AFTER` minutes it removes `RUNNER`, so new jobs try GitHub's runners again.
- When `run` stops, it removes `RUNNER` and gives jobs that wait for this runner back to GitHub's runners.

Publishing a release and the weekly security run stay on GitHub's runners.

## Setup

1. Install Multipass, jq, curl and nftables: `sudo snap install multipass && sudo apt install jq curl nftables`.
2. Create a fine-grained token on GitHub for this repository with read and write access to "Administration",
   "Actions" and "Variables", and save it in a file with mode `0600`.
3. Copy [runner.conf.example](runner.conf.example), for example to `~/.config/lanlord-runner/runner.conf`, and set
   `REPO` and `TOKEN_FILE`.
4. Build the base VM, then take jobs:

```sh
tools/runner/runner.sh prepare ~/.config/lanlord-runner/runner.conf
tools/runner/runner.sh run ~/.config/lanlord-runner/runner.conf
```

`run` stops with Ctrl-C and deletes the VM of the current job. Run `prepare` again for a newer runner or image.

## Pull requests from forks

A runner runs whatever a workflow asks for. Keep "Require approval for all external contributors" on under
Settings, Actions, General, so a workflow from a fork runs only after a maintainer approved it.
