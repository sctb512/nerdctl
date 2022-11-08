package fanotify

import (
	"fmt"
	"io"
	"os"
	"sort"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/containerd/containerd/oci"
	"github.com/containerd/stargz-snapshotter/analyzer/fanotify"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/spf13/cobra"
)

type FanotifyContext struct {
	fanotifier         *fanotify.Fanotifier
	accessedFiles      []string
	persistentPath     string
	fanotifierClosed   bool
	fanotifierClosedMu sync.Mutex
}

func GenerateFanotifyOpts(cmd *cobra.Command) ([]oci.SpecOpts, *FanotifyContext, error) {
	var opts []oci.SpecOpts
	if needFanotify, _ := cmd.Flags().GetBool("fanotify"); needFanotify {
		// Spawn a fanotifier process in a new mount namespace.
		fanotifier, err := fanotify.SpawnFanotifier("/proc/self/exe")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to spawn fanotifier: %w", err)
		}
		opts = append(opts, oci.WithLinuxNamespace(runtimespec.LinuxNamespace{
			Type: runtimespec.MountNamespace,
			Path: fanotifier.MountNamespacePath(), // use mount namespace that the fanotifier created
		}))
		return opts, &FanotifyContext{
			fanotifier:     fanotifier,
			accessedFiles:  make([]string, 0),
			persistentPath: "accessed_files.txt",
		}, nil
	}
	return nil, nil, fmt.Errorf("no need to generate fanotify Opts")
}

func (fanotifierCtx *FanotifyContext) StartFanotifyMonitor() error {
	if fanotifierCtx == nil {
		return fmt.Errorf("fanotifierCtx is nil")
	}
	if fanotifierCtx.fanotifier == nil {
		return fmt.Errorf("fanotifier is nil")
	}

	if err := fanotifierCtx.fanotifier.Start(); err != nil {
		return fmt.Errorf("failed to start fanotifier: %w", err)
	}

	persistentFd, err := os.Create(fanotifierCtx.persistentPath)
	if err != nil {
		persistentFd.Close()
		return err
	}

	go func() {
		for {
			path, err := fanotifierCtx.fanotifier.GetPath()
			if err != nil {
				if err == io.EOF {
					fanotifierCtx.fanotifierClosedMu.Lock()
					isFanotifierClosed := fanotifierCtx.fanotifierClosed
					fanotifierCtx.fanotifierClosedMu.Unlock()
					if isFanotifierClosed {
						break
					}
				}
				for _, file := range fanotifierCtx.accessedFiles {
					logrus.Infoln(file)
				}
				break
			}
			if !fanotifierCtx.accessedFileExist(path) {
				fmt.Fprintln(persistentFd, path)
				fanotifierCtx.accessedFiles = append(fanotifierCtx.accessedFiles, path)
			}
		}
	}()

	return nil
}

func (fanotifierCtx *FanotifyContext) StopFanotifyMonitor() error {
	if fanotifierCtx == nil {
		return fmt.Errorf("fanotifierCtx is nil")
	}
	if fanotifierCtx.fanotifier == nil {
		return fmt.Errorf("fanotifier is nil")
	}

	// Wait until the task exit
	// var status containerd.ExitStatus
	// var killOk bool
	// if aOpts.waitOnSignal { // NOTE: not functional with `terminal` option
	// 	log.G(ctx).Infof("press Ctrl+C to terminate the container")
	// 	status, killOk, err = waitOnSignal(ctx, container, task)
	// 	if err != nil {
	// 		return "", err
	// 	}
	// } else {
	// 	if aOpts.period <= 0 {
	// 		aOpts.period = defaultPeriod
	// 	}
	// 	log.G(ctx).Infof("waiting for %v ...", aOpts.period)
	// 	status, killOk, err = waitOnTimeout(ctx, container, task, aOpts.period, waitLine)
	// 	if err != nil {
	// 		return "", err
	// 	}
	// }
	// if !killOk {
	// 	log.G(ctx).Warnf("failed to exit task %v; manually kill it", task.ID())
	// } else {
	// 	code, _, err := status.Result()
	// 	if err != nil {
	// 		return "", err
	// 	}
	// 	log.G(ctx).Infof("container exit with code %v", code)
	// 	if _, err := task.Delete(ctx); err != nil {
	// 		return "", err
	// 	}
	// }

	fanotifierCtx.fanotifierClosedMu.Lock()
	fanotifierCtx.fanotifierClosed = true
	fanotifierCtx.fanotifierClosedMu.Unlock()

	if err := fanotifierCtx.fanotifier.Close(); err != nil {
		return fmt.Errorf("failed to cleanup fanotifier")
	}

	return nil
}

func (fanotifierCtx *FanotifyContext) accessedFileExist(filePath string) bool {
	tmpAccessedFiles := make([]string, len(fanotifierCtx.accessedFiles))
	copy(tmpAccessedFiles, fanotifierCtx.accessedFiles)
	sort.Strings(tmpAccessedFiles)
	if index := sort.SearchStrings(tmpAccessedFiles, filePath); index < len(tmpAccessedFiles) && tmpAccessedFiles[index] == filePath {
		return true
	}
	return false
}
