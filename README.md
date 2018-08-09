# sshesame
A fake SSH server that lets everyone in and logs their activity

## Warning
This software, just like any other, might contain bugs. Given the popular nature of SSH, you probably shouldn't run it unsupervised as root on a production server on port 22. Use common sense.

## Motivation
I was just curious what all these guys were up to:
```
sshd[8128]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=<client>  user=root
sshd[8128]: Failed password for root from <client> port 37510 ssh2
sshd[8128]: Received disconnect from <client> port 37510:11:  [preauth]
sshd[8128]: Disconnected from <client> port 37510 [preauth]
sshd[8141]: Received disconnect from <client> port 59353:11:  [preauth]
sshd[8141]: Disconnected from <client> port 59353 [preauth]
sshd[8151]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=<client>  user=root
sshd[8151]: Failed password for root from <client> port 63785 ssh2
sshd[8159]: Received disconnect from <client> port 24889:11:  [preauth]
sshd[8159]: Disconnected from <client> port 24889 [preauth]
```

## Details
`sshesame` accepts and logs
* every password authentication request,
* every SSH channel open request and
* every SSH request

**without actually executing anything on the host**.

For more details, read the [relevant RFC](https://tools.ietf.org/html/rfc4254).

## Installing
### From source
* [Install go](https://golang.org/doc/install) (version 1.4 or newer required)
* `go get -u github.com/PRKD/sshesame`

## Usage
```
$ sshesame -h
Usage of sshesame:
  -Path_log string
    	The file that will contain the log (default "os.Stdout")
  -host_key string
    	a file containing a private key to use
  -json_logging
    	enable logging in JSON
  -listen_address string
    	the local address to listen on (default "localhost")
  -motd_file string
    	a file that will contain motd
  -port uint
    	the port number to listen on (default 2022)
  -server_version string
    	The version identification of the server (RFC 4253 section 4.2 requires that this string start with "SSH-2.0-") (default "SSH-2.0-sshesame")

```
Consider creating a private key to use with sshesame, for example using `ssh-keygen`.

## Example output
```
Connection: client=<client>:45782
Login: client=<client>:45782, user="root", password="cisco"
Established SSH connection: client=<client>:45782
New channel: clinet=<client>:45782, type=direct-tcpip, payload={DestinationAddress:<something> DestinationPort:110 SourceAddress:192.168.0.1 SourcePort:0}
Failed to read from channel: EOF
New channel: clinet=<client>:45782, type=direct-tcpip, payload={DestinationAddress:<something> DestinationPort:143 SourceAddress:192.168.0.1 SourcePort:0}
Failed to read from channel: EOF
New channel: clinet=<client>:45782, type=direct-tcpip, payload={DestinationAddress:<something> DestinationPort:587 SourceAddress:192.168.0.1 SourcePort:0}
Failed to read from channel: EOF
New channel: clinet=<client>:45782, type=direct-tcpip, payload={DestinationAddress:<something> DestinationPort:587 SourceAddress:192.168.0.1 SourcePort:0}
Failed to read from channel: EOF
New channel: clinet=<client>:45782, type=session, payload=[]
Request: client=<client>:45782, channel=session, type=exec, payload={Command:/sbin/ifconfig}
Failed to read from terminal: EOF
New channel: clinet=<client>:45782, type=session, payload=[]
Request: client=<client>:45782, channel=session, type=exec, payload={Command:cat /proc/meminfo}
Failed to read from terminal: EOF
New channel: clinet=<client>:45782, type=session, payload=[]
Request: client=<client>:45782, channel=session, type=exec, payload={Command:2>/dev/null sh -c 'cat /lib/libdl.so* || cat /lib/librt.so* || cat /bin/cat || cat /sbin/ifconfig'}
Failed to read from terminal: EOF
New channel: clinet=<client>:45782, type=session, payload=[]
Request: client=<client>:45782, channel=session, type=exec, payload={Command:cat /proc/version}
Failed to read from terminal: EOF
New channel: clinet=<client>:45782, type=session, payload=[]
Request: client=<client>:45782, channel=session, type=exec, payload={Command:uptime}
Failed to read from terminal: EOF
Disconnect: client=<client>:45782
```
So what happened here?
* A client logged in with the user "root" and the password "cisco"
* Using TCP/IP forwarding over SSH, they tried to connect to a few remote mail servers over POP3 (port 110), IMAP (port 143) and Submission (port 587)
* They tried to execute a few commands to get some information about the host

Again, if you're interested in the technical details of SSH, read the [RFC](https://tools.ietf.org/html/rfc4254).

## Known issues
* No exit-status request is sent in response to exec requests
* A terminal is created on session channels even if no shell request is received
