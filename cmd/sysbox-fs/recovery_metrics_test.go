package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecoveryMetricsSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics.sock")
	r := &recoveryRunner{attempts: 3, succeeded: 2, failed: 1, faultEvents: 4, frequentFaults: 1}
	for _, elapsed := range []time.Duration{5 * time.Millisecond, 200 * time.Millisecond, 1200 * time.Millisecond} {
		r.observeDuration(elapsed)
	}
	stop, err := r.serveMetrics(path)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", path)
	}}}
	resp, err := client.Get("http://unix/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"sysbox_fs_recovery_attempts_total 3\n",
		"sysbox_fs_recovery_successes_total 2\n",
		"sysbox_fs_recovery_failures_total 1\n",
		"sysbox_fs_recovery_fault_events_total 4\n",
		"sysbox_fs_recovery_frequent_fault_processes_total 1\n",
		"# TYPE sysbox_fs_recovery_duration_seconds histogram\n",
		"sysbox_fs_recovery_duration_seconds_bucket{le=\"0.25\"} 2\n",
		"sysbox_fs_recovery_duration_seconds_bucket{le=\"+Inf\"} 3\n",
		"sysbox_fs_recovery_duration_seconds_sum 1.405000000\n",
		"sysbox_fs_recovery_duration_seconds_count 3\n",
	} {
		if !strings.Contains(string(body), line) {
			t.Fatalf("missing %q in %q", line, body)
		}
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/plain; version=0.0.4" {
		t.Fatalf("status=%d content-type=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	stop()
	if _, err := net.Dial("unix", path); err == nil {
		t.Fatal("metrics socket survived shutdown")
	}
}
