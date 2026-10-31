package csi

import (
	"strings"

	"golang.org/x/sys/unix"
	mount "k8s.io/mount-utils"
)

// TmpfsMounter mounts and unmounts with syscalls instead of exec'ing
// mount(8), so the driver runs in a distroless image. Mount-point detection
// comes from mount-utils.
type TmpfsMounter struct {
	mount.Interface
}

func NewTmpfsMounter() *TmpfsMounter {
	return &TmpfsMounter{Interface: mount.New("")}
}

func (m *TmpfsMounter) Mount(source, target, fstype string, options []string) error {
	return unix.Mount(source, target, fstype, unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, strings.Join(options, ","))
}

func (m *TmpfsMounter) Unmount(target string) error {
	return unix.Unmount(target, 0)
}
