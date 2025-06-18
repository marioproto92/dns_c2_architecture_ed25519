
# DNS C2 Architecture with Ed25519 Signature: A Silent Evolution in Remote Control

**Designed and implemented by Mario Protopapa (alias DeBuG)**

---

## Introduction

In the context of advanced Red Team operations and persistent threat campaigns (APT), the C2 infrastructure represents the backbone of communication between the operator and compromised systems. In this highly monitored and hostile environment, a C2 must be discreet, resilient, and controllable. The architecture I present here, conceived and built by myself, leverages one of the most overlooked yet ubiquitous protocols-DNS and reinforces it with the security of Ed25519 digital signatures.

## Overall Architecture

The system is composed of two main components: the C2 client and a registrar, which acts as the generator and signer of DNS payloads. The client is designed to query DNS domains built deterministically but varying over time. The goal is to allow the malware to contact a continuously shifting infrastructure and recognize only valid, cryptographically signed responses. The client-server logic is based on a pull paradigm: the client queries, but only if the server has published a valid command will it be accepted and executed.

## Dynamic Domain Construction

A key element is the dynamic derivation of the domain to query. Every hour, the client calculates a label based on a salt and a UTC timestamp rounded to the hour. The salt varies according to the operating environment: if the client detects a virtualized environment (VMware, VirtualBox, KVM), it uses a specific salt for virtual environments; otherwise, it uses one for physical hosts. This allows segmentation of the infrastructure and differentiation between real and sandboxed environments.

The label is computed using SHA-256, retaining only the first 12 characters of the hexadecimal output. This label is then appended to one of the predefined TLDs, producing the final domain. The client will query up to three different TLDs (e.g., `.com`, `.net`, `.cloud`), also selected based on the environment.

## The DNS TXT Record as Command Channel

The heart of communication lies in the `_auth.<host>` DNS TXT record. Here, a base64-url-safe encoded JSON blob is published. This blob contains six key fields: the host domain, a validity range (`not_before` and `valid_until`), a command, an optional action, and a cryptographic signature.

The client receives the TXT record, decodes it, verifies the signature using a locally stored public key, and checks the timestamps to ensure the command is currently valid. Only if all checks pass will the client execute the specified action.

## Signing Mechanism and Security

The system’s security relies on Ed25519 to sign every command. The registrar, the server-side tool, is responsible for key generation and payload signing. Keys are stored in base64-url-safe format in `ed25519_priv.b64` and `ed25519_pub.b64`. The signed message is a concatenation of the fields `host|not_before|valid_until|command|action`, ensuring all parts of the message are protected.

## Client Operational Parameters

The `client_ed25519.py` script accepts two main parameters:
- `--dns-server`: allows specifying an alternative DNS resolver, useful if the malware wants to avoid the system’s default resolver, often monitored.
- `--dns-port`: defines the communication port (default is 53). In highly restrictive environments, communication can be diverted to an alternative port.

The client is designed to be resilient: it queries multiple domains, verifies every received payload, and acts only on signed and time-bound commands.

## Registrar Functionality

The registrar is a flexible and powerful tool. It allows you to:
- Generate and rotate signing keys
- Dynamically derive the label from a timestamp and salt
- Build a signed and encoded JSON payload
- Print DNS A and TXT records to publish
- Automatically update a `zone_records.txt` file to simulate a controlled DNS environment

Important parameters include:
- `--tld`, `--salt`, `--timestamp`, `--valid-minutes`: define the domain structure
- `--cmd`, `--action`: specify client behavior
- `--rotate-key`: forces regeneration of the Ed25519 key pair

The registrar output consists of two records: an A record pointing to a dummy IP (default `127.0.0.66`) and a TXT record containing the signed payload.

## Operational Simulations and Realistic Use Cases

This architecture is well-suited for advanced operational contexts. In an ICS infrastructure, for example, the malware can remain dormant for weeks, querying DNS hourly. Only when the registrar publishes a valid (signed and time-bound) command will the client take action, such as triggering a second-stage payload (`RUN_STAGE_2`).

In air-gapped environments, the architecture can operate on internal or simulated DNS resolvers. The payload can be loaded via manually modified zone files or transported through physical media.

## Key Rotation and Revocation Mechanisms

A well-designed system must also manage revocation. Key rotation is automated via the `--rotate-key` option. To invalidate compromised keys, a blacklist mechanism can be implemented in resolvers, or the client can be configured to accept only signatures issued after a specific date.

## Antiforensics and Evasion Techniques

The use of DNS already makes the system stealthy, but further measures can be implemented: label obfuscation, DNS over HTTPS, fileless execution, time-based or environment-based triggers (e.g., presence of specific files).

## Defensive Countermeasures and Detection

For Blue Teams, detecting this architecture requires detailed DNS logging and behavioral analysis. The presence of `_auth.*` queries may be a clue, but contextual understanding is necessary. A payload with high entropy in TXT records, especially in domains not serving email or SPF, could be another indicator.

## Compatibility and Integration

The registrar can be extended as a module in existing C2 frameworks (e.g., Mythic, Cobalt Strike), acting as a backend for signed commands. The client can be embedded in loaders or droppers, leveraging its standalone nature.

## Multi-Client Resilience Design

A commonly overlooked aspect of C2 architecture is scalability in the presence of many active agents distributed across different networks and contexts. The system described here is built with a segmentation logic based on labels and salts. By using distinct salts for different target types (VMs, physical hosts, sandboxes) and combining them with specific timestamps, it is possible to orchestrate commands for separate agent groups.

This approach enables the activation of only specific nodes during an operational phase, drastically reducing network noise and interception surface. The use of multiple TLDs also allows logical separation of control groups by geographic area, functional role, or target type, maintaining full compatibility with the existing client code.

## Stealth Client Persistence

Long-term implant survival in hostile environments requires persistence techniques that avoid traditional IoCs. The client can be configured for fileless execution, launching directly from memory using methods like `memfd_create`, or hidden as a script within legitimate system processes.

For post-reboot persistence, native OS vectors can be leveraged: on Linux via disguised cronjobs or `systemd` timers with plausible names; on Windows via `RunOnce` registry keys, WMI subscriptions, or DLL sideloading.

The fact that the client does not actively connect to a server but only queries DNS every hour helps avoid clear network logs or beaconing patterns. This behavior, combined with dynamically changing domain names, allows the malware to remain latent and undetected for long periods, ready to activate only when necessary.

## Detailed Source Code Analysis

### client_ed25519.py

This script represents the malware/implant that queries the DNS channel for commands. At the beginning, it imports essential modules, including `argparse` for argument handling, `dns.resolver` for DNS queries, and `nacl.signing` for Ed25519 signature verification.

The `is_vm()` function detects whether the client is running in a virtualized environment by reading `/sys/class/dmi/id/product_name` and checking for known patterns. This detection influences salt selection for domain generation, enabling infection segmentation.

`gen_label()` calculates the domain label, a SHA-256 hash of the `salt|timestamp` values. This mechanism deterministically generates domains that vary every hour.

`fetch_txt_record()` performs the DNS query on the `_auth.<host>` subdomain, waits for a TXT response, decodes the base64 content, and converts it into a JSON object.

The key function `verify_payload()` performs digital signature verification using the Ed25519 public key. It also ensures the command is temporally valid, preventing the client from executing outdated or premature instructions.

Finally, `main()` orchestrates the entire process: generates the label, selects the TLD, queries DNS, verifies, and—if valid—executes the command or displays the exfiltration action.

### registrar_ed25519_cli.py

This script handles payload generation and management. The `load_or_generate()` function creates or loads the Ed25519 keys. If `--rotate-key` is used, it generates a new pair and saves the files.

`derive_label()` constructs the label exactly as in the client, maintaining sync. This is crucial: if both use the same salt and timestamp, the computed domain will be identical.

The `build_payload()` function prepares the JSON with all required fields and signs it with the private key, protecting the command from tampering.

`encode_txt()` base64-url-safe encodes the entire JSON, producing the string that goes into the TXT DNS record.

The `update_zone()` function modifies `zone_records.txt`, adding a dummy A record and the signed command in the TXT record. This file can be used in simulated DNS environments.

The final `main()` handles all CLI parameters, calculates the timestamp, signs the payload, prints the records, and updates the zone file if requested.

## Conclusion

This C2 architecture is the result of a study aimed at balancing security, stealth, and operational effectiveness. By using DNS as a transport medium and Ed25519 for integrity enforcement, I designed a system that offers full operational control while remaining invisible to most detection systems.

This is not merely a stylistic exercise but a practical approach to silent persistence and cryptographically bound target control.

**Mario Protopapa**  
*Alias DeBuG*
