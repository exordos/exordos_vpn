# Genesis element: VPN

## Operator CLI

```bash
# List user's certs
$ genesis-vpn-cli list --user-id myuser
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━━━━┓
┃ uuid                                 ┃ user_id  ┃ name ┃ status ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━━━━┩
│ 7759546f-007a-4efc-a37f-08aaf427a05f │ myuser   │ main │ ACTIVE │
└──────────────────────────────────────┴──────────┴──────┴────────┘

# Create new config
$ genesis-vpn-cli create USER_NAME CERT_NAME

# Regen config
$ genesis-vpn-cli generate_config 7759546f-007a-4efc-a37f-08aaf427a05f
Configuration file generated at /etc/openvpn/easy-rsa/configs/myuser.main.ovpn

# Block cert (user won't be connected with this cert in this case)
$ genesis-vpn-cli disable 7759546f-007a-4efc-a37f-08aaf427a05f
```

### Server config recommendations
- use openvpn-DCO kernel module if you're ready to be a beta-tester of kernel-6.16+ and openvpn2.7 server (old DKMS-based DCO has some [stability problems](https://github.com/OpenVPN/ovpn-dco/issues/56))
- DCO doesn't support mssfix, so we need to be sure to set the MTU explicitly (see issues [#61](https://github.com/OpenVPN/ovpn-dco/issues/61) and [#31](https://github.com/OpenVPN/ovpn-dco/issues/31)):
  ```
  tun-mtu 1380
  ```
  - note that **1380** bytes is a sweet spot, any larger may have problems with mobile hotspots or average internet providers easily
- **TCP** is *recommended* to use by default. Use **UDP** *only* if you can easily control clients and debug their problems. UDP has some drawbacks: it can't check connectivity easily, and you might see disruptions (instead of explicit disconnections) on timeouts or when multiple machines connect with the same certificate.

### Client specifics and recommendations

#### Common
- see [etc/genesis_vpn/client_config.j2](etc/genesis_vpn/client_config.j2) for config optimized for majority of clients:
  - inline files should be declared without additional `inline` phrase
  - use `key-direction 1` with inline `tls-auth` block instead of `tls-auth 1 inline`
- **It's recommended** not to push any `DOMAIN-SEARCH` records from server and just use private DNS for everything, unfortunately clients without `DOMAIN-SEARCH` support may just ignore all DNS pushes, which is equal to not working private DNS at all

#### Windows

- OpenVPN Connect (proprietary)
  - doesn't support `inline` key word, use only inline file containers with specified names
  - can't use split-DNS, but uses pushed DNS for everything
  - **WARNING**: If any `DOMAIN-SEARCH` option is pushed from the server, the clien will totally ignore pushed DNS information. To prevent this, either avoid pushing `DOMAIN-SEARCH` options, or have the client explicitly ignore them with the config line `pull-filter ignore "dhcp-option DOMAIN-SEARCH"`.

- OpenVPN community (**recommended**)
  - can't use split-DNS, but uses pushed DNS for everything

- pritunl
  - uses old version of community client, so works nearly the same

#### Macos

- Tunnelblick
  - can't use split-DNS, but uses pushed DNS for everything

#### Linux

- OpenVPN from console
  - don't set DNS by itself on connect, please search for `openvpn-systemd-resolved` package and/or add in config (distribution-specific):
    ```
    up /etc/openvpn/update-systemd-resolved
    down /etc/openvpn/update-systemd-resolved
    ```

- OpenVPN KDE plugin (**recommended**)
  - can't use split-DNS, but uses pushed DNS for everything

- OpenVPN Gnome plugin
  - can use split-DNS, BUT can't use pushed DNS for everything if `DOMAIN-SEARCH` is empty
  - if you have problems with DNS
    - set VPN DNS explicitly (**recommended**)
    - or, get all private domain names and set it manually via your local split-DNS

#### Iphone

- OpenVPN Connect (**recommended**)
  - can't use split-DNS, but uses pushed DNS for everything

#### Android

- OpenVPN Connect (**recommended**)
  - can't use split-DNS, but uses pushed DNS for everything
