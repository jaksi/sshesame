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
sshesame [-config sshesame.yaml] [-json_logging]
```

### Configuration

A configuration file can optionally be passed using the `-config` flag.
Without using one, sane defaults will be used and RSA, ECDSA and Ed25519 host keys will be generated and stored.

A [sample configuration file](sshesame.yaml) with explanations for the configuration options is included.
A [minimal configuration file](openssh.yaml) which tries to mimic OpenSSH  is also included.

Logs are human readable by default. JSON logging can optionally be enabled using the `-json_logging` flag.

Debug and error logs are written to standard error. Session (activity) logs are written to standard out.

## Annotated sample output

### TCP connection

```
msg="Connection accepted" remote_address=[...]
```

### Authentication

#### None (no password or public key), denied

```
msg="Client attempted to authenticate" client_version=[...] method=none remote_addr=[...] session_id=[...] success=false user=jaksi
```

#### Public key, denied

```
msg="Public key authentication attempted" client_version=[...] public_key_fingerprint=[...] remote_addr=[...] session_id=[...] success=false user=jaksi
msg="Client attempted to authenticate" client_version=[...] method=publickey remote_addr=[...] session_id=[...] success=false user=jaksi
```

#### Password, accepted

```
msg="Password authentication attempted" client_version=[...] password=hunter2 remote_addr=[...] session_id=[...] success=true user=jaksi
msg="Client attempted to authenticate" client_version=[...] method=password remote_addr=[...] session_id=[...] success=true user=jaksi
msg="SSH connection established" client_version=[...] remote_addr=[...] session_id=[...] user=jaksi
```

#### Session channel for a shell

```
msg="New channel requested" accepted=true channel_extra_data= channel_id=0 channel_type=session client_version=[...] remote_addr=[...] session_id=[...] user=jaksi
msg="Channel request received" accepted=true channel_id=0 client_version=[...] remote_addr=[...] request_payload="Term: xterm-256color, Size: 423x79 (0x0 px), Modes: [...] request_type=pty-req request_want_reply=true session_id=[...] user=jaksi
msg="Channel request received" accepted=true channel_id=0 client_version=[...] remote_addr=[...] request_payload="LANG=C.UTF-8" request_type=env request_want_reply=false session_id=[...] user=jaksi
msg="Channel request received" accepted=true channel_id=0 client_version=[...] remote_addr=[...] request_payload= request_type=shell request_want_reply=true session_id=[...] user=jaksi
msg="Channel closed" channel_id=0 channel_input="cat /etc/passwd\r" client_version=[...] remote_addr=[...] session_id=[...] user=jaksi
```

#### TCP/IP channel  (`ssh [...] -L 8080:github.com:80`)

```
msg="New channel requested" accepted=true channel_extra_data="127.0.0.1:57958 -> github.com:80" channel_id=1 channel_type=direct-tcpip client_version=[...] remote_addr=[...] session_id=[...] user=jaksi
msg="Channel closed" channel_id=1 channel_input="GET /jaksi/sshesame HTTP/1.1\r\nHost: github.com\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\n\r\n" client_version=[...] remote_addr=[...] session_id=[...] user=jaksi
```

#### Connection closed

```
msg="SSH connection closed" client_version=[...] remote_addr=[...] session_id=[...] user=jaksi
msg="Connection closed" remote_address=[...]
```