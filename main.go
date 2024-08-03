package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/adrg/xdg"
	"github.com/jaksi/sshutils"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	infoLogger    *log.Logger
	warningLogger *log.Logger
	errorLogger   *log.Logger
)

func init() {
	infoLogger = log.New(os.Stderr, "INFO ", log.LstdFlags)
	warningLogger = log.New(os.Stderr, "WARNING ", log.LstdFlags)
	errorLogger = log.New(os.Stderr, "ERROR ", log.LstdFlags)
}

func main() {
	configFile := flag.String("config", "", "optional config file")
	dataDir := flag.String("data_dir", path.Join(xdg.DataHome, "sshesame"), "data directory to store automatically generated host keys in")
	flag.Parse()

	cfg := &config{}
	configString := ""
	if *configFile != "" {
		configBytes, err := os.ReadFile(*configFile)
		if err != nil {
			errorLogger.Fatalf("Failed to read config file: %v", err)
		}
		configString = string(configBytes)
	}
	err := cfg.load(configString, *dataDir)
	if err != nil {
		errorLogger.Fatalf("Failed to load config: %v", err)
	}
	reloadSignals := make(chan os.Signal, 1)
	defer close(reloadSignals)
	go func() {
		for signal := range reloadSignals {
			infoLogger.Printf("Reloading config due to %s", signal)
			configBytes, err := os.ReadFile(*configFile)
			if err != nil {
				warningLogger.Printf("Failed to read config file: %v", err)
			}
			configString = string(configBytes)
			err = cfg.load(configString, *dataDir)
			if err != nil {
				warningLogger.Printf("Failed to reload config: %v", err)
			}
		}
	}()
	signal.Notify(reloadSignals, syscall.SIGHUP)

	listener, err := sshutils.Listen(cfg.Server.ListenAddress, cfg.sshConfig)
	if err != nil {
		errorLogger.Fatalf("Failed to listen for connections: %v", err)
	}
	defer listener.Close()

	infoLogger.Printf("Listening on %v", listener.Addr())

	if cfg.Logging.MetricsAddress != "" {
		http.Handle("/metrics", promhttp.Handler())
		infoLogger.Printf("Serving metrics on %v", cfg.Logging.MetricsAddress)
		go func() {
			if err := http.ListenAndServe(cfg.Logging.MetricsAddress, nil); err != nil {
				errorLogger.Fatalf("Failed to serve metrics: %v", err)
			}
		}()
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			warningLogger.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleConnection(conn, cfg)
	}
}
