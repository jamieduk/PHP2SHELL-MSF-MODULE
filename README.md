# php2shell Exposure Scanner

A non-intrusive Metasploit auxiliary scanner for collecting remote PHP version evidence relevant to **CVE-2026-109618** (OOM memory corruption) and **CVE-2026-109619** (stale global state / use-after-free).

**Platform:** Kali Purple with Metasploit Framework.

> [!WARNING]
> Use this module only against systems you own or have explicit written authorisation to test. It makes network requests and records findings. Do not scan production systems unless the test has been approved.

## Important limitations

This is a **version-evidence scanner, not an exploit**. It cannot prove remote code execution or establish exploitability.

- Makes at most two benign HTTP `GET` requests per target: the configured `TARGETURI`, then `/` only if PHP is not detected at the configured path.
- Checks response headers (`X-Powered-By`, `Server`, `Set-Cookie`) and obvious PHP body markers.
- Compares any disclosed PHP version with the vendor version matrix.
- Records HTTP service details and an exposure note; records a vulnerability only when a disclosed version falls in the stated affected range.
- Does **not** execute commands, upload payloads, create sessions, trigger memory corruption/use-after-free/OOM, send resource-exhaustion requests, or perform denial-of-service tests.

A result of **possibly exposed** means the disclosed version falls in an affected range; it does not confirm exploitability.

## CVE and version information

According to the source notes used for this module:

| Item | Information |
|---|---|
| CVEs | CVE-2026-109618 and CVE-2026-109619 |
| Severity | CVSS v4 9.2 (Critical), as stated in the source notes |
| Disclosure date | 21 October 2026, as stated in the source notes |
| Fixed releases | PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35 |
| Affected version comparison | Versions below the matching fixed release |
| End-of-life versions | PHP 8.1 and older; source notes mention backports for PHP 7.4, 8.0 and 8.1 |

**Distribution backports matter:** a Linux distribution may backport a security fix without changing the upstream version component. Remote version comparison can therefore produce false positives. Confirm the installed package/build and the actual PHP SAPI locally.

## Package contents

- `php2shell_exposure.rb` — Metasploit auxiliary module
- `spec/php2shell_exposure_spec.rb` — RSpec tests using a local mock HTTP server
- `install.sh` — installer
- `README.md` — this file

## Installation

### Recommended: automatic installation

From the package directory:

```bash
chmod +x install.sh
./install.sh
```

The installer detects the Metasploit framework tree associated with `msfconsole` on `PATH`, validates the Ruby file with `ruby -c`, backs up an existing copy, and reports where it installed the module.

To verify that the active `msfconsole` can find the module:

```bash
./install.sh --verify
```

Other installer modes:

```bash
# Install to the per-user module directory without root.
./install.sh --user

# Install to the system framework tree.
sudo ./install.sh --system

# Force a specific framework root.
MSF_ROOT=/opt/metasploit-framework sudo ./install.sh --system
```

Environment overrides:

- `MSF_ROOT` — explicitly select a Metasploit framework root.
- `MSF_USER_ROOT` — explicitly select the per-user `.msf4` directory.

### Module paths

System package installations commonly use:

```text
/usr/share/metasploit-framework/modules/auxiliary/scanner/http/
```

Other framework installations may use `/opt/metasploit-framework/...` or another package-specific path.

For a regular per-user installation:

```text
~/.msf4/modules/auxiliary/scanner/http/php2shell_exposure.rb
```

For the Metasploit Snap, use its confined per-user directory:

```text
~/snap/metasploit-framework/common/.msf4/modules/auxiliary/scanner/http/php2shell_exposure.rb
```

Snap installations are confined and use a different per-user directory; a module placed only in `~/.msf4` may not be visible to the Snap's `msfconsole`.

For manual installation, create the appropriate directory and copy `php2shell_exposure.rb` there. Then reload modules in Metasploit:

```text
reload_all
```

## Usage

Start Metasploit:

```bash
msfconsole
```

### Single-target HTTP check

```text
use auxiliary/scanner/http/php2shell_exposure
show options
set RHOSTS 192.0.2.10
set RPORT 80
set SSL false
set TARGETURI /
check
```

Replace the example address with an explicitly authorised target. Use `RHOSTS` (the documented option) rather than `RHOST`.

### HTTPS or a path-prefixed application

```text
use auxiliary/scanner/http/php2shell_exposure
set RHOSTS 192.0.2.25
set RPORT 8443
set SSL true
set VHOST app.internal.example
set TARGETURI /portal/
set CONNECT_TIMEOUT 5
set READ_TIMEOUT 15
run
```

### Multiple authorised hosts

Use only a target list or range covered by your authorisation:

```text
set RHOSTS 10.0.0.0/24
set THREADS 8
run
```

Alternatively, use a file containing authorised hosts:

```text
set RHOSTS file:/tmp/authorised_hosts.txt
run
```

The module description specifies a maximum of one concurrent thread per host. Keep concurrency appropriate for the target environment.

## Module options

| Option | Default | Description |
|---|---:|---|
| `RHOSTS` | — | One or more authorised target hosts |
| `RPORT` | `80` | Target TCP port |
| `SSL` | `false` | Negotiate TLS for HTTPS |
| `TARGETURI` | `/` | Base path of the PHP application |
| `VHOST` | — | HTTP `Host` value for name-based virtual hosting |
| `CONNECT_TIMEOUT` | `10` | Seconds allowed to establish the connection |
| `READ_TIMEOUT` | `20` | Seconds allowed for an HTTP response |
| `THREADS` | `1` | Concurrent scanner threads |
| `Proxies` | — | Metasploit proxy chain, where required |
| `HttpTrace` | `false` | Enable raw HTTP tracing for troubleshooting |

Check the active module's `show options` and `info -d` output for the exact options supported by the installed version.

## Understanding results

The module's result wording and confidence are based on remote evidence:

- **Possibly exposed:** a disclosed PHP version is below the matching fixed release. Confirm the actual installed package/build locally.
- **Patched (version evidence):** a disclosed PHP version is at or above the matching fixed release. This is version evidence, not proof that every backend is patched.
- **Inconclusive:** PHP is detected but its version is concealed. The scanner does not guess.
- **Unknown:** no usable HTTP response was received.
- **No PHP visible / safe check result:** PHP was not visible at the checked endpoint or a disclosed version was classified as fixed; this is not proof that the host is safe.

The `check` command reports a Metasploit `CheckCode` for each host. Exact wording may vary with the module implementation.

### False positives

- Distribution/LTS security backports can patch a package while retaining an upstream version string.
- A reverse proxy or CDN may provide stale or modified `X-Powered-By` values.

### False negatives and inconclusive results

- `expose_php=Off` may hide `X-Powered-By`.
- A proxy may strip or rewrite version headers.
- A patched front end may proxy to an unpatched PHP backend.
- Custom applications may remove or alter version information.

**Do not treat a remote safe or inconclusive result as proof of safety, and do not treat a possibly exposed result as proof of exploitability.**

## Metasploit database reporting

When the database is enabled, inspect recorded results with:

```text
hosts
services
notes -t php2shell.exposure
vulns
vulns -p 443
```

The module is intended to record:

- An HTTP(S) service entry
- A `php2shell.exposure` note containing disclosed versions, evidence sources, and confidence
- A vulnerability entry only when the disclosed version falls in the stated affected range, labelled as version-based with exploitability unconfirmed

## Confirming the installed PHP build

Where you have authorised shell/package access, confirm the actual version, package revision, and SAPI on the target host. For Debian/Ubuntu:

```bash
php -v
php -i | grep -i 'Core\|PHP Version'
dpkg -l | grep php
```

For RHEL-family systems:

```bash
rpm -qa | grep php
```

Check the PHP SAPI in use (`mod_php`, `php-fpm`, `php-cgi`, LiteSpeed, FrankenPHP, or another deployment) and confirm that the relevant worker processes use the patched build and intended configuration. The source notes also mention these temporary mitigation settings to review with the application's maintainer:

- `session.upload_progress.enabled=0`
- `fatal_error_backtraces=0`
- `memory_limit=-1`

Treat these as configuration considerations, not substitutes for installing the vendor's security fix.

## Running tests

The RSpec suite uses a local in-process mock HTTP server and is intended not to contact real targets.

From the Metasploit framework source tree:

```bash
cd /usr/share/metasploit-framework
bundle exec rspec spec/modules/auxiliary/scanner/http/php2shell_exposure_spec.rb
```

For a per-user installed spec, if the framework's test environment can load it:

```bash
cd /usr/share/metasploit-framework
bundle exec rspec ~/.msf4/spec/modules/auxiliary/scanner/http/php2shell_exposure_spec.rb
```

The stated test coverage includes:

- Version classification for affected, fixed, and end-of-life versions
- Header-based version extraction from `X-Powered-By` and `Server`
- Mock-server checks for affected, patched, hidden-version, and non-PHP responses

Run RSpec from the framework root so the framework's `spec_helper` can be resolved.

## Troubleshooting

**Module is not listed**

1. Run `reload_all` in `msfconsole`.
2. Confirm the filename is `php2shell_exposure.rb`.
3. Confirm the module defines `class MetasploitModule`.
4. Confirm the module was installed in the module path used by the active `msfconsole`, especially if using Snap.

**Module fails to load**

Run a Ruby syntax check against the installed file:

```bash
ruby -c /path/to/php2shell_exposure.rb
```

**Every target returns unknown**

Check `RHOSTS`, `RPORT`, `SSL`, `TARGETURI`, `VHOST`, connectivity, and whether a proxy is required. If needed, enable `HttpTrace` to inspect the requests and responses.

**Remote result differs from local `php -v`**

This can happen because headers may be hidden, stale, rewritten by a proxy, or inconsistent with distribution backports. Confirm the deployed package and SAPI locally.

**RSpec cannot find `spec_helper`**

Run the test from the Metasploit framework root rather than the package directory.

## References

The following references are listed in the source notes for the CVEs and version matrix. Verify their current contents before relying on them for incident response or patch decisions.

1. [CVE-2026-109619 advisory — stale global state](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
2. [CVE-2026-109618 advisory — OOM corruption](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
3. [PHP release announcement](https://www.php.net/archive/2026.php#2026-10-21-5)
4. [Rapid7 Emergent Threat Response blog](https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php/)
5. [NCSC-NL operational repository — php2shell](https://github.com/NCSC-NL/php2shell)
6. [NHS England cyber alert CC-4875](https://digital.nhs.uk/cyber-alerts/2026/cc-4875)
7. [CERT-EU Security Advisory 2026-018](https://cert.europa.eu/publications/security-advisories/2026-018/)

## Legal and ethical use

Only scan systems explicitly authorised for testing. Although this scanner is designed to be non-destructive, it sends active HTTP requests and stores findings. If you cannot establish that a test is permitted and appropriate for the target, do not run it.
