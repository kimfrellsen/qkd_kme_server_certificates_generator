# TLS certificate generator for ETSI GS QKD 014 KME server

This script allows you to automatically generate all TLS certificates to operate the KME ETSI GS QKD 014 server https://github.com/thomasarmel/qkd_kme_server correctly for your network topology.

So that you can avoid manual and error-prone operations using OpenSSL commands.

---

## Installation

Install Rust programming language, as explained at https://www.rust-lang.org/tools/install.

```bash
git clone https://github.com/thomasarmel/qkd_kme_server_certificates_generator.git
cd qkd_kme_server_certificates_generator
cargo run --release -- your_config_file.json5
```

## Configuration file

Configuration file is in [JSON5](https://json5.org/) format. It's an enhanced version of JSON allowing for example comments.

The sections of the configuration file are:

- **`cert_exp_time_days`** *(integer)*
  Expiration date from today for all generated certificates, in days.

- **`ca_cert_exp_time_days`** *(integer)*
  Expiration date from today for all generated Certificate Authority (CA) certificates, in days.

- **`certs_dir`** *(string)*
  Directory where all generated certificates and keys will be stored. It will be created if it does not exist.

- **`kmes`** *(array of objects)*
  List of KME servers to generate certificates for. Each object has the following fields:
  
  - **`id`** *(integer, 64-bit)*
    Unique ID of the KME in the whole network, as a 64-bit integer.

    Please note that SAE and KME IDs are different, meaning a SAE and a KME can share the same ID.
  - **`addr_for_saes`** *(string)*
    Address (IP or DNS name) that SAEs will use to connect to this KME.
  - **`addr_for_kmes`** *(string)*
    Address (IP or DNS name) that other KMEs will use to connect to this KME.
  - **`client_pfx_certificate_password`** *(string)*
    Password to protect the PKCS#12 file containing the client certificate and private key that KME will use to authenticate to other KMEs.
  - **`saes`** *(array of objects)*
    List of SAEs connected to this KME. Each object has the following fields:
    
    - **`id`** *(integer, 64-bit)*
      Unique ID of the SAE in the whole network, as a 64-bit integer.

      Please note that SAE and KME IDs are different, meaning a SAE and a KME can share the same ID.
    - **`client_certificate_serial`** *(array of u8)*
      Serial number of the client certificate that SAE will use to authenticate to this KME, as an array of u8 bytes (example: `[0x70, 0xf4, 0x4f, 0x56, 0xc, 0x3f, 0x27, 0xd4, 0xb2, 0x11, 0xa4, 0x78, 0x13, 0xaf, 0xd0, 0x3c, 0x3, 0x81, 0x3b, 0x8e]`).
    - **`client_pfx_certificate_password`** *(string)*
        Password to protect the PKCS#12 file containing the client certificate and private key that SAE will use to authenticate to this KME.

Please find an example configuration file at [certificates_config_example.json5](./certificates_config_example.json5).
      
## Generated certificates

The following directories and files will be created in the directory specified by the `certs_dir` field of the configuration file:

- **inter_kmes/** directory containing all certificates and keys used for KME-to-KME mutual authentication:
  - **ca_kme{kme_id}.crt** CA certificate used to sign KME {kme_id} server certificate. You should probably add this CA certificate to the trusted CA list of all other KMEs in the network.
  - **ca_kme{kme_id}.key** private key corresponding to **ca_kme{kme_id}.crt**.
  - **kme{kme_id}_server.crt** server certificate of KME {kme_id}, signed by **ca_kme{kme_id}.crt**. This certificate will be presented to other KMEs when they connect to this KME.
  - **kme{kme_id}_server.key** private key corresponding to **kme{kme_id}_server.crt**.
  - **kme{kme_id}-to-kme{other_kme_id}.pfx** PKCS#12 file containing the client certificate and private key that KME {kme_id} will use to authenticate to KME {other_kme_id}, signed by **ca_kme{other_kme_id}.crt**. The password to protect this file is the `client_pfx_certificate_password` field of KME {kme_id} in the configuration file.
  - **kme{kme_id}-to-kme{other_kme_id}.pem** PEM file containing the client certificate and private key that KME {kme_id} will use to authenticate to KME {other_kme_id}, signed by **ca_kme{other_kme_id}.crt**. This file is equivalent of **kme{kme_id}-to-kme{other_kme_id}.pfx** and it is not password-protected.
- **kme-{kme_id}-local-zone** directory containing all certificates and keys used for SAE-to-KME mutual authentication for SAEs connected to KME {kme_id}:
  - **ca.crt** CA certificate used to sign all SAE client certificates belonging to {kme_id}, and {kme_id} SAE interface server certificate. You should probably add this CA certificate to the trusted CA list of all SAEs connected to this KME.
  - **ca.key** private key corresponding to **ca.crt**.
  - **kme_server.crt** server certificate of KME {kme_id} SAE interface, signed by **ca.crt**. This certificate will be presented to SAEs when they connect to this KME.
  - **kme_server.key** private key corresponding to **kme_server.crt**
  - **client_{sae_id}.pfx** PKCS#12 file containing the client certificate and private key that SAE {sae_id} will use to authenticate to this KME, signed by **ca.crt**. The password to protect this file is the `client_pfx_certificate_password` field of SAE {sae_id} in the configuration file.
  - **client_{sae_id}.pem** PEM file containing the client certificate and private key that SAE {sae_id} will use to authenticate to this KME, signed by **ca.crt**. This file is equivalent of **client_{sae_id}.pfx** and it is not password-protected.
  - **client_{sae_id}.crt** client certificate that SAE {sae_id} will use to authenticate to this KME, signed by **ca.crt**.
  - **client_{sae_id}.key** private key corresponding to **client_{sae_id}.crt**.