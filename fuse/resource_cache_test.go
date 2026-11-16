package fuse

import (
	"context"
	"io"
	"testing"
	"time"

	bfuse "bazil.org/fuse"
	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/mocks"
	"github.com/nestybox/sysbox-fs/sysio"
	"github.com/stretchr/testify/mock"
)

type testCachePolicy struct{ ttl time.Duration }

func (p *testCachePolicy) ResourceCacheTTL() time.Duration       { return p.ttl }
func (p *testCachePolicy) SetResourceCacheTTL(ttl time.Duration) { p.ttl = ttl }

type testSharedContainer struct{ domain.ContainerIface }
type testCacheReader struct {
	domain.HandlerIface
	req *domain.HandlerRequest
}

func (r *testCacheReader) Read(_ domain.IOnodeIface, req *domain.HandlerRequest) (int, error) {
	r.req = req
	return 0, io.EOF
}

func TestSharedStateKeepsServingContainerTTL(t *testing.T) {
	shared := &testSharedContainer{}
	owner := &domain.ResourceOwner{ID: 1}
	for _, ttl := range []time.Duration{0, 25 * time.Millisecond, 150 * time.Millisecond} {
		handlers := &mocks.HandlerServiceIface{}
		reader := &testCacheReader{}
		handlers.On("LookupHandler", mock.Anything).Return(reader, true).Once()

		service := &FuseServerService{ios: sysio.NewIOService(domain.IOOsFileService), hds: handlers}
		server := &fuseServer{container: shared, resourceOwner: owner, cachePolicy: &testCachePolicy{ttl}, service: service}
		file := NewFile(&domain.HandlerRequest{Name: "uptime", Path: "/proc/uptime"}, &bfuse.Attr{Mode: 0444}, server)
		if err := file.Read(context.Background(), &bfuse.ReadRequest{Size: 64}, &bfuse.ReadResponse{}); err != nil {
			t.Fatal(err)
		}
		handlers.AssertExpectations(t)
		if reader.req.Container != shared || reader.req.ResourceOwner != owner || reader.req.ResourceCacheTTL != ttl {
			t.Fatalf("serving TTL %s: %#v", ttl, reader.req)
		}
	}
}
