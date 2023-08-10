# pfSense-pkg-crowdsec

This package integrates CrowdSec in pfSense. A public beta should be released soon.

It provides a basic UI with settings to configures the Security Engine and the Firewall Remediation Component (bouncer).

Three types of configuration are supported:

- Small: remediation only. Use this to protect a set of existing servers already running CrowdSec. The remediation component
  feeds the Packet Filter with the blocklists received by the main CrowdSec instance (*).

- Medium: like Small but can also detect attacks by parsing logs in the pfSense machine. Attack data is sent to the CrowdSec
  instance for analysis and possibly sharing.

- Large: deploy a fully autonomous CrowdSec Security Engine on the pfSense machine and allow other servers to connect to it.
  Requires a persistent /var directory (no RAM disk) and a slightly larger pfSense machine, depending on the amount of data
  to be processed.

(*) If you are already using a Blocklist Mirror, this replaces it while being faster and not requiring pfBlockerNG.
