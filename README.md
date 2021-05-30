# sshesame

An easy to set up and use SSH honeypot, a fake SSH server that lets anyone in and logs their activity

`sshesame` accepts and logs SSH connections and activity (channels, requests), without doing anything on the host (e.g. executing commands, making network requests).

[![asciicast](https://asciinema.org/a/Rb0MFuB4ifodScIiirxOtOxOu.svg)](https://asciinema.org/a/Rb0MFuB4ifodScIiirxOtOxOu)

## Installation

### From source

```
go get github.com/jaksi/sshesame
```

## Usage

```
sshesame [-config sshesame.yaml]
```

### Configuration

A configuration file can optionally be passed using the `-config` flag.
Without using one, sane defaults will be used and RSA, ECDSA and Ed25519 host keys will be generated and stored.

A [sample configuration file](sshesame.yaml) with explanations for the configuration options is included.
A [minimal configuration file](openssh.yaml) which tries to mimic an OpenSSH server is also included.

Debug and error logs are written to standard error. Session (activity) logs by default are written to standard out, unless the `logfile` config option is set.

## Annotated sample output

### TCP connection

```
INFO[0002] Connection accepted                           remote_address=[...]
```

### Authentication

#### None (no password or public key), denied

```
INFO[0002] Client attempted to authenticate              client_version="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2" method=none remote_addr=[...] session_id=[...] success=false user=jaksi
```

#### Public key, denied

```
INFO[0002] Public key authentication attempted           client_version="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2" public_key_fingerprint=[...] remote_addr=[...] session_id=[...] success=false user=jaksi
INFO[0002] Client attempted to authenticate              client_version="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2" method=publickey remote_addr=[...] session_id=[...] success=false user=jaksi
```

#### Password, accepted

```
INFO[0005] Password authentication attempted             client_version="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2" password=hunter2 remote_addr=[...] session_id=[...] success=true user=jaksi
INFO[0005] Client attempted to authenticate              client_version="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2" method=password remote_addr=[...] session_id=[...] success=true user=jaksi
INFO[0005] SSH connection established                    client_version="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2" remote_addr=[...] session_id=[...] user=jaksi
```

#### Session channel for a shell

```
INFO[0005] New channel requested                         accepted=true channel_extra_data= channel_id=0 channel_type=session client_version="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2" remote_addr=[...] session_id=[...] user=jaksi
INFO[0005] Channel request received                      accepted=true channel_id=0 client_version="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2" remote_addr=[...] request_payload="Term: xterm-256color, Size: 120x30 (0x0 px), Modes: [...]" request_type=pty-req request_want_reply=true session_id=[...] user=jaksi
INFO[0005] Channel request received                      accepted=true channel_id=0 client_version="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2" remote_addr=[...] request_payload="LANG=C.UTF-8" request_type=env request_want_reply=false session_id=[...] user=jaksi
INFO[0005] Channel request received                      accepted=true channel_id=0 client_version="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2" remote_addr=[...] request_payload= request_type=shell request_want_reply=true session_id=[...] user=jaksi
INFO[0015] Channel closed                                channel_id=0 channel_input="cat /etc/passwd\r" client_version="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2" remote_addr=[...] session_id=[...] user=jaksi
```

#### TCP/IP channel  (`ssh [...] -L 8080:github.com:80`)

```
INFO[0013] New channel requested                         accepted=true channel_extra_data="127.0.0.1:53288 -> github.com:80" channel_id=1 channel_type=direct-tcpip client_version="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2" remote_addr=[...] session_id=[...] user=jaksi
INFO[0013] Channel closed                                channel_id=1 channel_input="GET / HTTP/1.1\r\nHost: github.com\r\nAccept: */*\r\nUser-Agent: curl/7.68.0\r\n\r\n" client_version="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2" remote_addr=[...] session_id=[...] user=jaksi
```

#### Connection closed

```
INFO[0015] SSH connection closed                         client_version="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.2" remote_addr=[...] session_id=[...] user=jaksi
INFO[0015] Connection closed                             remote_address=[...]
```
