package channel

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/PRKD/sshesame/request"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"net"
	s "strings"
	"strconv"
	"os"
)

// RFC 4254
type x11 struct {
	SourceAddress string
	SourcePort    uint32
}

func (payload x11) String() string {
	return net.JoinHostPort(payload.SourceAddress, strconv.Itoa(int(payload.SourcePort)))
}

type tcpip struct {
	DestinationAddress string
	DestinationPort    uint32
	SourceAddress      string
	SourcePort         uint32
}

func (payload tcpip) String() string {
	return fmt.Sprintf("%v -> %v",
		net.JoinHostPort(payload.SourceAddress, strconv.Itoa(int(payload.SourcePort))),
		net.JoinHostPort(payload.DestinationAddress, strconv.Itoa(int(payload.DestinationPort))))
}
func findCommand(commands map[string]string , command string) string{
		for k,v := range commands {
				if (s.Contains(command,k)) {
						return v
				} 
		}
		return "false"
}

func populateCommandList() map[string]string {
		commands := make(map[string]string)
		commands["uname"] = "Linux toker 2.6.31-22-generic-pae #69-Ubuntu SMP Wed Nov 24 09:04:58 UTC 2010 i686"
		commands["hostname"] = "root@localhost.localdomain" 
		commands["ps"] = `  PID TTY      STAT   TIME COMMAND
    1 ?        Ss     0:04 /sbin/init
    2 ?        S      0:00 [kthreadd]
    3 ?        S      0:00 [ksoftirqd/0]
    5 ?        S<     0:00 [kworker/0:0H]
    7 ?        S      0:00 [rcu_sched]
    8 ?        S      0:00 [rcu_bh]
    9 ?        S      0:00 [migration/0]
   10 ?        S      0:00 [watchdog/0]
   11 ?        S      0:00 [kdevtmpfs]
   12 ?        S<     0:00 [netns]
   13 ?        S<     0:00 [perf]
   14 ?        S      0:00 [khungtaskd]
   15 ?        S<     0:00 [writeback]
   16 ?        SN     0:00 [ksmd]
   17 ?        S<     0:00 [crypto]
   18 ?        S<     0:00 [kintegrityd]
   19 ?        S<     0:00 [bioset]
   20 ?        S<     0:00 [kblockd]
   21 ?        S<     0:00 [ata_sff]
   22 ?        S<     0:00 [md]
   23 ?        S<     0:00 [devfreq_wq]
   27 ?        S      0:00 [kswapd0]
   28 ?        S<     0:00 [vmstat]
   29 ?        S      0:00 [fsnotify_mark]
   30 ?        S      0:00 [ecryptfs-kthrea]
   46 ?        S<     0:00 [kthrotld]
   47 ?        S<     0:00 [acpi_thermal_pm]
   48 ?        S      0:00 [vballoon]
   49 ?        S<     0:00 [bioset]
   50 ?        S<     0:00 [bioset]
   51 ?        S<     0:00 [bioset]
   52 ?        S<     0:00 [bioset]
   53 ?        S<     0:00 [bioset]
   54 ?        S<     0:00 [bioset]
   55 ?        S<     0:00 [bioset]
   56 ?        S<     0:00 [bioset]
   57 ?        S<     0:00 [bioset]
   58 ?        S      0:00 [scsi_eh_0]
   59 ?        S<     0:00 [scsi_tmf_0]
   60 ?        S      0:00 [scsi_eh_1]
   61 ?        S<     0:00 [scsi_tmf_1]
   66 ?        S<     0:00 [ipv6_addrconf]
   79 ?        S<     0:00 [deferwq]
   80 ?        S<     0:00 [charger_manager]
  117 ?        S<     0:00 [bioset]
  118 ?        S<     0:00 [bioset]
  119 ?        S<     0:00 [bioset]
  120 ?        S      0:00 [scsi_eh_2]
  121 ?        S<     0:00 [bioset]
  122 ?        S<     0:00 [bioset]
  123 ?        S<     0:00 [scsi_tmf_2]
  124 ?        S<     0:00 [bioset]
  125 ?        S<     0:00 [bioset]
  126 ?        S<     0:00 [bioset]
  127 ?        S<     0:00 [kpsmoused]
  481 ?        S<     0:00 [raid5wq]
  511 ?        S<     0:00 [bioset]
  535 ?        S      0:00 [jbd2/vda1-8]
  536 ?        S<     0:00 [ext4-rsv-conver]
  597 ?        S<     0:00 [kworker/0:1H]
  613 ?        Ss     0:02 /lib/systemd/systemd-journald
  626 ?        S      0:00 [kauditd]
  627 ?        S<     0:00 [iscsi_eh]
  642 ?        S<     0:00 [ib_addr]
  645 ?        S<     0:00 [ib_mcast]
  646 ?        S<     0:00 [ib_nl_sa_wq]
  647 ?        S<     0:00 [ib_cm]
  650 ?        S<     0:00 [iw_cm_wq]
  653 ?        S<     0:00 [rdma_cm]
  657 ?        Ss     0:00 /sbin/lvmetad -f
  687 ?        Ss     0:00 /lib/systemd/systemd-udevd
  791 ?        S<     0:00 [kvm-irqfd-clean]
  936 ?        Ssl    0:00 /lib/systemd/systemd-timesyncd
  983 ?        S<sl   0:01 /sbin/auditd -n
 1425 ?        Ss     0:00 /sbin/iscsid
 1426 ?        S<Ls   0:02 /sbin/iscsid
 1431 ?        Ss     0:00 /usr/sbin/cron -f
 1437 ?        Ss     0:00 /usr/sbin/acpid
 1452 ?        Ss     0:00 /usr/sbin/sshd -D
 1454 ?        Ssl    0:00 /usr/sbin/rsyslogd -n
 1458 ?        Ssl    0:00 /usr/lib/snapd/snapd
 1460 ?        Ss     0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation`

		commands["ls"] = `total 666
drwxrwxr-x+  53 root  admin  1802 12 Dec 19:12 Applications
drwxr-xr-x+  60 root  wheel  2040 19 Nov 11:26 Library
drwxr-xr-x@   2 root  wheel    68 21 Feb  2017 Network
drwxr-xr-x@   4 root  wheel   136 25 Nov 13:43 System
drwxr-xr-x    7 root  admin   238 17 Oct 07:39 Users
drwxr-xr-x@   3 root  wheel   102  7 Dec 18:49 Volumes
drwxr-xr-x@  38 root  wheel  1292 25 Nov 13:43 bin
drwxrwxr-t@   2 root  admin    68 21 Feb  2017 cores
dr-xr-xr-x    3 root  wheel  7803  5 Dec 08:44 dev
lrwxr-xr-x@   1 root  wheel    11 11 Jul 13:28 etc -> private/etc
dr-xr-xr-x    2 root  wheel     1  5 Dec 08:50 home
-rw-r--r--@   1 root  wheel   313 22 Dec  2016 installer.failurerequests
dr-xr-xr-x    2 root  wheel     1  5 Dec 08:50 net
drwxr-xr-x@   4 root  wheel   136 11 Aug 12:23 opt
drwxr-xr-x@   6 root  wheel   204 11 Jul 13:29 private
drwxr-xr-x@  63 root  wheel  2142 25 Nov 13:43 sbin
lrwxr-xr-x@   1 root  wheel    11 11 Jul 13:28 tmp -> private/tmp
drwxr-xr-x@  10 root  wheel   340 11 Jul 13:45 usr
lrwxr-xr-x@   1 root  wheel    11 11 Jul 13:29 var -> private/var`
		return commands
}


func Handle(remoteAddr net.Addr, newChannel ssh.NewChannel , sshmap map[string]string, motd string) {
	var payload interface{} = newChannel.ExtraData()
	//commandList := make(map[string]string)
	//commandList["uname"] = "Kernel 2.2.2.2.2"
	commands := populateCommandList()
	
	switch newChannel.ChannelType() {
	case "x11":
		parsedPayload := x11{}
		err := ssh.Unmarshal(newChannel.ExtraData(), &parsedPayload)
		if err != nil {
			log.Warning("Failed to parse payload:", err.Error())
			break
		}
		payload = parsedPayload
	case "forwarded-tcpip":
		// Server initiated forwarding
		fallthrough
	case "direct-tcpip":
		// Client initiated forwarding
		parsedPayload := tcpip{}
		err := ssh.Unmarshal(newChannel.ExtraData(), &parsedPayload)
		if err != nil {
			log.Warning("Failed to parse payload:", err.Error())
			break
		}
		payload = parsedPayload
	}
	log.WithFields(log.Fields{
		"client":  remoteAddr,
		"channel": newChannel.ChannelType(),
		"payload": payload,
	}).Info("Channel requested")
	channel, channelRequests, err := newChannel.Accept()
	if err != nil {
		log.Warning("Failed to accept channel:", err.Error())
		return
	}
	defer channel.Close()
	go request.Handle(remoteAddr, newChannel.ChannelType(), channelRequests)
	name, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	if newChannel.ChannelType() == "session" {
		var prompt string = ":/$ "
		if remoteAddr.String()="root" {
		prompt="~#"
		}
		terminal := terminal.NewTerminal(channel, sshmap[remoteAddr.String()]+"@"+name+prompt)
		terminal.Write([]byte(motd))
		for {
			fmt.Println(sshmap[remoteAddr.String()])
			line, err := terminal.ReadLine()
			if err != nil {
				if err == io.EOF {
					log.WithFields(log.Fields{
						"client":  remoteAddr,
						"channel": newChannel.ChannelType(),
					}).Info("Terminal closed")
					request.SendExitStatus(channel)
				} else {
					log.Warning("Failed to read from terminal:", err.Error())
				}
				break
			}
			response := findCommand(commands,line)
			if (response != "false" ) {
				terminal.Write([]byte(response+"\n"))
		}
			log.WithFields(log.Fields{
				"client":  remoteAddr,
				"channel": newChannel.ChannelType(),
				"line":    line,
			}).Info("Channel input received")
		}
	} else {
		data := make([]byte, 256)
		for {
			length, err := channel.Read(data)
			if err != nil {
				if err == io.EOF {
					log.WithFields(log.Fields{
						"client":  remoteAddr,
						"channel": newChannel.ChannelType(),
					}).Info("Channel closed")
				} else {
					log.Warning("Failed to read from channel:", err.Error())
				}
				break
			}
			log.WithFields(log.Fields{
				"client":  remoteAddr,
				"channel": newChannel.ChannelType(),
				"data":    string(data[:length]),
			}).Info("Channel input received")
		}
	}
}
