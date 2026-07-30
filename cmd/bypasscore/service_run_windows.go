//go:build windows

package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/eugene/bypasscore/common/errors"
)

// runAsPlatformService reports whether the process was started by the Windows
// Service Control Manager and, if so, runs the daemon under SCM control. On
// other platforms (and for regular console invocations) it returns false.
func runAsPlatformService() (bool, error) {
	inService, err := svc.IsWindowsService()
	if err != nil {
		return false, errors.New("detect windows service: ").Base(err)
	}
	if !inService {
		return false, nil
	}
	return true, svc.Run(windowsServiceName(), &windowsService{})
}

// windowsServiceName matches the name passed to `bypasscore install -name ...`
// (default "bypasscore"); the SCM requires svc.Run to use the registered name.
func windowsServiceName() string {
	if name := os.Getenv("BYPASSCORE_SERVICE_NAME"); name != "" {
		return name
	}
	return defaultServiceName
}

// defaultServiceConfigPath is the config path the installed service runs with.
func defaultServiceConfigPath() string {
	return filepath.Join(programDataDir(), defaultServiceName, "config.json")
}

type windowsService struct{}

func (s *windowsService) Execute(args []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- runServiceDaemon(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case req := <-requests:
			switch req.Cmd {
			case svc.Interrogate:
				status <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel() // graceful shutdown via the daemon's baseCtx
				select {
				case <-errCh:
				case <-time.After(25 * time.Second):
				}
				return false, 0
			}
		case err := <-errCh:
			if err != nil {
				return true, 1 // service-specific error
			}
			return false, 0
		}
	}
}

// runServiceDaemon loads the config referenced by the service binPath
// arguments ("-config <path> -run") and runs the runtime daemon until ctx is
// cancelled by an SCM stop request.
func runServiceDaemon(ctx context.Context) error {
	fs := flag.NewFlagSet("bypasscore-service", flag.ContinueOnError)
	configPath := fs.String("config", defaultServiceConfigPath(), "path to config file")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	cfg, configHash, err := loadConfigAndHash(*configPath)
	if err != nil {
		return errors.New("load config: ").Base(err)
	}
	registerDialerFactory()
	return runRuntimeDaemon(ctx, *configPath, cfg, configHash)
}
