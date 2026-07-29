package nsenter

import "testing"

func TestIsPayloadMountpoint(t *testing.T) {
	for _, test := range []struct {
		path   string
		prefix string
		want   bool
	}{
		{"/dev/.sysbox-procfs-123", ".sysbox-procfs-", true},
		{"/dev/.sysbox-sysfs-123", ".sysbox-sysfs-", true},
		{"/.sysbox-procfs-123", ".sysbox-procfs-", false},
		{"/dev/not-sysbox", ".sysbox-procfs-", false},
	} {
		if got := isPayloadMountpoint(test.path, test.prefix); got != test.want {
			t.Errorf("isPayloadMountpoint(%q, %q) = %v, want %v", test.path, test.prefix, got, test.want)
		}
	}
}
