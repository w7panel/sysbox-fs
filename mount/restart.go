package mount

import "github.com/nestybox/sysbox-fs/domain"

// SnapshotMounts preserves the original immutable-mount policy across daemon
// replacement; parsing the current tree as a new initial tree would silently
// make workload-created mounts immutable.
func (mi *mountInfoParser) SnapshotMounts() []*domain.MountInfo {
	out := make([]*domain.MountInfo, 0, len(mi.mpInfo))
	for _, info := range mi.mpInfo {
		out = append(out, info)
	}
	return out
}

func (mi *mountInfoParser) RestoreMounts(infos []*domain.MountInfo) {
	for _, info := range infos {
		info.Mip = mi
		mi.mpInfo[info.MountPoint] = info
		mi.idInfo[info.MountID] = info
		mi.fsIdInfo[info.MajorMinorVer] = append(mi.fsIdInfo[info.MajorMinorVer], info)
		if info.MpInode != 0 {
			mi.inInfo[info.MpInode] = append(mi.inInfo[info.MpInode], info)
		}
	}
}

// RefreshRecoveredMounts updates only paths already protected by the original
// policy after a new FUSE mount is overlaid at those paths.
func (mi *mountInfoParser) RefreshRecoveredMounts(paths []string, parsed domain.MountInfoParserIface) {
	current := parsed.(*mountInfoParser)
	for _, path := range paths {
		old, ok := mi.mpInfo[path]
		if !ok {
			continue
		}
		next := current.mpInfo[path]
		if next == nil {
			continue
		}
		delete(mi.idInfo, old.MountID)
		mi.mpInfo[path] = next
		mi.idInfo[next.MountID] = next
		next.Mip = mi
	}
	// Rebuild derived indices; mount identity changed but the protected path set did not.
	mi.inInfo = make(map[domain.Inode][]*domain.MountInfo)
	mi.fsIdInfo = make(map[string][]*domain.MountInfo)
	for _, info := range mi.mpInfo {
		mi.fsIdInfo[info.MajorMinorVer] = append(mi.fsIdInfo[info.MajorMinorVer], info)
		if info.MpInode != 0 {
			mi.inInfo[info.MpInode] = append(mi.inInfo[info.MpInode], info)
		}
	}
}
