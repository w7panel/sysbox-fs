package seccomp

import "testing"

func TestUseParentUserns(t *testing.T) {
	tests := []struct {
		name                       string
		process, parent, container uint64
		want                       bool
	}{
		{"direct child", 30, 20, 20, true},
		{"same userns", 20, 10, 20, false},
		{"unrelated userns", 30, 10, 20, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := useParentUserns(tt.process, tt.parent, tt.container); got != tt.want {
				t.Fatalf("useParentUserns(%d, %d, %d) = %t, want %t", tt.process, tt.parent, tt.container, got, tt.want)
			}
		})
	}
}
