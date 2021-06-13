# sshesame

An easy to set up and use SSH honeypot, a fake SSH server that lets anyone in and logs their activity

`sshesame` accepts and logs SSH connections and activity (channels, requests), without doing anything on the host (e.g. executing commands, making network requests).

[![asciicast](https://asciinema.org/a/V099PxjofAz16XwRxdqUDWAJv.svg)](https://asciinema.org/a/V099PxjofAz16XwRxdqUDWAJv)

## Installation and usage

### From source

```
go get github.com/jaksi/sshesame
sshesame [-config sshesame.yaml] [-data_dir /etc/sshesame]
```

### Docker

Images are automatically pushed to [Docker Hub](https://hub.docker.com/repository/docker/jaksi/sshesame).

```
docker run -it --rm -p 2022:2022 -v sshesame-data:/data [-v $PWD/sshesame.yaml:/config.yaml] jaksi/sshesame
```

### Configuration

A configuration file can optionally be passed using the `-config` flag.
Without specifying one, sane defaults will be used and RSA, ECDSA and Ed25519 host keys will be generated and stored in the directory specified in the `-data_dir` flag.

A [sample configuration file](sshesame.yaml) with explanations for the configuration options is included.
A [minimal configuration file](openssh.yaml) which tries to mimic an OpenSSH server is also included.

Debug and error logs are written to standard error. Session (activity) logs by default are written to standard out, unless the `logfile` config option is set.

## Annotated sample output

### TCP connection

```
INFO[0003] Connection accepted
  remote_address="127.0.0.1:51465"
```

### Authentication

#### None (no password or public key), denied

```
INFO[0003] Client attempted to authenticate
  client_version=SSH-2.0-OpenSSH_8.1
  method=none
  remote_address="127.0.0.1:51465"
  session_id=6rd5eCU0zdKt+jJgm6jrMKDRT4nGDYSAWSKwyYJtIdw
  success=false
  user=jaksi
```

#### Public key, denied

```
INFO[0003] Public key authentication attempted
  client_version=SSH-2.0-OpenSSH_8.1
  public_key_fingerprint="SHA256:uUdTmvEHN6kCAoE4RJWsxr8+fGTGhCpAhBaWgmMVqNk"
  remote_address="127.0.0.1:51465"
  session_id=6rd5eCU0zdKt+jJgm6jrMKDRT4nGDYSAWSKwyYJtIdw
  success=false
  user=jaksi
INFO[0003] Client attempted to authenticate
  client_version=SSH-2.0-OpenSSH_8.1
  method=publickey
  remote_address="127.0.0.1:51465"
  session_id=6rd5eCU0zdKt+jJgm6jrMKDRT4nGDYSAWSKwyYJtIdw
  success=false
  user=jaksi
```

#### Password, accepted

```
INFO[0003] Password authentication attempted
  client_version=SSH-2.0-OpenSSH_8.1
  password=hunter2
  remote_address="127.0.0.1:51465"
  session_id=6rd5eCU0zdKt+jJgm6jrMKDRT4nGDYSAWSKwyYJtIdw
  success=true
  user=jaksi
INFO[0003] Client attempted to authenticate
  client_version=SSH-2.0-OpenSSH_8.1
  method=password
  remote_address="127.0.0.1:51465"
  session_id=6rd5eCU0zdKt+jJgm6jrMKDRT4nGDYSAWSKwyYJtIdw
  success=true
  user=jaksi
INFO[0003] SSH connection established
  client_version=SSH-2.0-OpenSSH_8.1
  remote_address="127.0.0.1:51465"
  session_id=6rd5eCU0zdKt+jJgm6jrMKDRT4nGDYSAWSKwyYJtIdw
  user=jaksi
```

#### Session channel for a shell

```
INFO[0003] New channel requested
  accepted=true
  channel_extra_data=
  channel_id=0
  channel_type=session
  client_version=SSH-2.0-OpenSSH_8.1
  remote_address="127.0.0.1:51465"
  session_id=6rd5eCU0zdKt+jJgm6jrMKDRT4nGDYSAWSKwyYJtIdw
  user=jaksi
INFO[0003] Channel request received
  accepted=true
  channel_id=0
  client_version=SSH-2.0-OpenSSH_8.1
  remote_address="127.0.0.1:51465"
  request_payload="Term: xterm-256color, Size: 204x58 (1428x812 px), Modes: VINTR=3, VLNEXT=22, INPCK=0, IXANY=1, IXOFF=0, ISIG=1, ECHOK=0, TTY_OP_ISPEED=9600, IGNPAR=0, INLCR=0, IMAXBEL=1, ONOCR=0, ONLRET=0, VERASE=127, VSTART=17, ICANON=1, ECHO=1, ECHONL=0, NOFLSH=0, PENDIN=1, VEOL=255, VEOL2=255, VREPRINT=18, OCRNL=0, VEOF=4, VKILL=21, VSUSP=26, IGNCR=0, OPCODE_42=1, TOSTOP=0, IEXTEN=1, ECHOKE=1, TTY_OP_OSPEED=9600, ONLCR=1, VSTOP=19, VDISCARD=15, PARMRK=0, ECHOE=1, ECHOCTL=1, CS7=1, VQUIT=28, VWERASE=23, IXON=0, OPOST=1, CS8=1, PARODD=0, VDSUSP=25, ISTRIP=0, ICRNL=1, PARENB=0, VSTATUS=20"
  request_type=pty-req
  request_want_reply=true
  session_id=6rd5eCU0zdKt+jJgm6jrMKDRT4nGDYSAWSKwyYJtIdw
  user=jaksi
INFO[0003] Channel request received
  accepted=true
  channel_id=0
  client_version=SSH-2.0-OpenSSH_8.1
  remote_address="127.0.0.1:51465"
  request_payload="LANG=en_IE.UTF-8"
  request_type=env
  request_want_reply=false
  session_id=6rd5eCU0zdKt+jJgm6jrMKDRT4nGDYSAWSKwyYJtIdw
  user=jaksi
INFO[0003] Channel request received
  accepted=true
  channel_id=0
  client_version=SSH-2.0-OpenSSH_8.1
  remote_address="127.0.0.1:51465"
  request_payload=
  request_type=shell
  request_want_reply=true
  session_id=6rd5eCU0zdKt+jJgm6jrMKDRT4nGDYSAWSKwyYJtIdw
  user=jaksi
INFO[0006] Channel input received
  channel_id=0
  client_version=SSH-2.0-OpenSSH_8.1
  input="cat /etc/passwd"
  remote_address="127.0.0.1:51465"
  session_id=6rd5eCU0zdKt+jJgm6jrMKDRT4nGDYSAWSKwyYJtIdw
  user=jaksi
INFO[0011] Channel closed
  channel_id=0
  client_version=SSH-2.0-OpenSSH_8.1
  remote_address="127.0.0.1:51465"
  session_id=6rd5eCU0zdKt+jJgm6jrMKDRT4nGDYSAWSKwyYJtIdw
  user=jaksi
```

#### TCP/IP channel  (`ssh [...] -L 8080:github.com:80`)

```
INFO[0009] New channel requested
  accepted=true
  channel_extra_data="127.0.0.1:51466 -> github.com:80"
  channel_id=1
  channel_type=direct-tcpip
  client_version=SSH-2.0-OpenSSH_8.1
  remote_address="127.0.0.1:51465"
  session_id=6rd5eCU0zdKt+jJgm6jrMKDRT4nGDYSAWSKwyYJtIdw
  user=jaksi
INFO[0009] Channel input received
  channel_id=1
  client_version=SSH-2.0-OpenSSH_8.1
  input="GET / HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAccept: */*\r\nUser-Agent: curl/7.64.1\r\n\r\n"
  remote_address="127.0.0.1:51465"
  session_id=6rd5eCU0zdKt+jJgm6jrMKDRT4nGDYSAWSKwyYJtIdw
  user=jaksi
INFO[0009] Channel closed
  channel_id=1
  client_version=SSH-2.0-OpenSSH_8.1
  remote_address="127.0.0.1:51465"
  session_id=6rd5eCU0zdKt+jJgm6jrMKDRT4nGDYSAWSKwyYJtIdw
  user=jaksi
```

#### Connection closed

```
INFO[0011] SSH connection closed
  client_version=SSH-2.0-OpenSSH_8.1
  remote_address="127.0.0.1:51465"
  session_id=6rd5eCU0zdKt+jJgm6jrMKDRT4nGDYSAWSKwyYJtIdw
  user=jaksi
INFO[0011] Connection closed
  remote_address="127.0.0.1:51465"
```
