package mount

import (
	"encoding/json"
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
)

func TestRestartPreservesOriginalMountPolicy(t *testing.T) {
	original, _ := newMountInfoParser(nil, nil, false, false, false, nil)
	original.RestoreMounts([]*domain.MountInfo{
		{MountID: 10, MountPoint: "/proc/meminfo", MajorMinorVer: "0:20", MpInode: 100},
		{MountID: 11, MountPoint: "/sys", MajorMinorVer: "0:21", MpInode: 101},
	})
	encoded, err := json.Marshal(original.SnapshotMounts())
	if err != nil {
		t.Fatal(err)
	}
	var saved []*domain.MountInfo
	if err := json.Unmarshal(encoded, &saved); err != nil {
		t.Fatal(err)
	}
	restored, _ := newMountInfoParser(nil, nil, false, false, false, nil)
	restored.RestoreMounts(saved)
	current, _ := newMountInfoParser(nil, nil, false, false, false, nil)
	current.RestoreMounts([]*domain.MountInfo{
		{MountID: 20, MountPoint: "/proc/meminfo", MajorMinorVer: "0:30", MpInode: 200},
		{MountID: 21, MountPoint: "/workload", MajorMinorVer: "0:31", MpInode: 201},
	})
	restored.RefreshRecoveredMounts([]string{"/proc/meminfo", "/workload"}, current)
	if len(restored.mpInfo) != 2 || restored.mpInfo["/workload"] != nil {
		t.Fatal("workload mount became immutable")
	}
	if restored.idInfo[10] != nil || restored.idInfo[20] == nil || restored.idInfo[11] == nil {
		t.Fatal("mount IDs were not refreshed selectively")
	}
	if len(restored.inInfo[100]) != 0 || len(restored.fsIdInfo["0:20"]) != 0 || len(restored.inInfo[200]) != 1 {
		t.Fatal("stale mount identity retained")
	}
	if restored.mpInfo["/proc/meminfo"].Mip != restored {
		t.Fatal("parser owner not restored")
	}
}
