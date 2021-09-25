# sshesame

An easy to set up and use SSH honeypot, a fake SSH server that lets anyone in and logs their activity

`sshesame` accepts and logs SSH connections and activity (channels, requests), without doing anything on the host (e.g. executing commands, making network requests).

[![asciicast](https://asciinema.org/a/VSqzZi1oPA0FhQDyqht22iA6k.svg)](https://asciinema.org/a/VSqzZi1oPA0FhQDyqht22iA6k)

## Installation and usage

> :warning: **The [`sshesame` package](https://packages.debian.org/stable/sshesame) in the official Debian (and derivatives) repositories may be (probably is) outdated.**

### From source

```
$ git clone https://github.com/jaksi/sshesame.git
$ cd sshesame
$ go build
```

### GitHub releases

Linux, macOS and Windows binaries for several architectures are built and released automatically and are available on the [Releases page](https://github.com/jaksi/sshesame/releases).

### Snap

Snaps for several architectures are built and released automatically and are available on the [Snap Store](https://snapcraft.io/sshesame).

> :warning: **The snap can only access files (configs, keys, logs) in the user's home directory.**

```
$ snap install sshesame
```

### Usage

```
$ sshesame -h
Usage of sshesame:
  -config string
    	optional config file
  -data_dir string
    	data directory to store automatically generated host keys in (default "...")
```

Debug and error logs are written to standard error. Activity logs by default are written to standard out, unless the `logging.file` config option is set.

### Docker

Images for amd64, arm64 and armv7 are built and published automatically and are available on the [Packages page](https://github.com/jaksi/sshesame/pkgs/container/sshesame).

#### CLI

```
$ docker run -it --rm\
    -p 127.0.0.1:2022:2022\
    -v sshesame-data:/data\
    [-v $PWD/sshesame.yaml:/config.yaml]\
    ghcr.io/jaksi/sshesame
```

#### Dockerfile

```dockerfile
FROM ghcr.io/jaksi/sshesame
#COPY sshesame.yaml /config.yaml
```

#### Docker Compose

```yaml
services:
  sshesame:
    image: ghcr.io/jaksi/sshesame
    ports:
      - "127.0.0.1:2022:2022"
    volumes:
      - sshesame-data:/data
      #- ./sshesame.yaml:/config.yaml
volumes:
  sshesame-data: {}
```

### Configuration

A configuration file can optionally be passed using the `-config` flag.
Without specifying one, sane defaults will be used and an RSA, ECDSA and Ed25519 host key will be generated and stored in the directory specified in the `-data_dir` flag.

A [sample configuration file](sshesame.yaml) with default settings and explanations for all configuration options is included.  
A [minimal configuration file](openssh.yaml) which tries to mimic an OpenSSH server is also included.

## Sample output

```
2021/07/04 00:37:05 [127.0.0.1:64515] authentication for user "jaksi" without credentials rejected
2021/07/04 00:37:05 [127.0.0.1:64515] authentication for user "jaksi" with public key "SHA256:uUdTmvEHN6kCAoE4RJWsxr8+fGTGhCpAhBaWgmMVqNk" rejected
2021/07/04 00:37:07 [127.0.0.1:64515] authentication for user "jaksi" with password "hunter2" accepted
2021/07/04 00:37:07 [127.0.0.1:64515] connection with client version "SSH-2.0-OpenSSH_8.1" established
2021/07/04 00:37:07 [127.0.0.1:64515] [channel 1] session requested
2021/07/04 00:37:07 [127.0.0.1:64515] [channel 1] PTY using terminal "xterm-256color" (size 158x48) requested
2021/07/04 00:37:07 [127.0.0.1:64515] [channel 1] environment variable "LANG" with value "en_IE.UTF-8" requested
2021/07/04 00:37:07 [127.0.0.1:64515] [channel 1] shell requested
2021/07/04 00:37:16 [127.0.0.1:64515] [channel 1] input: "cat /etc/passwd"
2021/07/04 00:37:17 [127.0.0.1:64515] [channel 1] closed
2021/07/04 00:37:17 [127.0.0.1:64515] connection closed
```
