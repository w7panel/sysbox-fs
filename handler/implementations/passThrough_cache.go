package implementations

import (
	"fmt"
	"io"
	"strings"
	"syscall"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/fuse"
	"golang.org/x/sync/singleflight"
)

var readCacheMissGroup singleflight.Group

func (h *PassThrough) readCacheMiss(
	cntr domain.ContainerIface,
	process domain.ProcessIface,
	namespaces []domain.NStype,
	n domain.IOnodeIface,
	req *domain.HandlerRequest) (int, error) {

	key := h.readCacheMissKey(cntr, n.Path(), req.Offset, len(req.Data), namespaces, req.NoCache)
	result, err, _ := readCacheMissGroup.Do(key, func() (interface{}, error) {
		data := make([]byte, len(req.Data))

		if !req.NoCache {
			cntr.Lock()
			sz, cacheErr := cntr.Data(n.Path(), req.Offset, &data)
			cntr.Unlock()
			if cacheErr != nil && cacheErr != io.EOF {
				return nil, fuse.IOerror{Code: syscall.EINVAL}
			}
			if !(req.Offset == 0 && sz == 0 && cacheErr == io.EOF) {
				return data[:sz], nil
			}
		}

		sz, fetchErr := h.fetchFile(process, namespaces, n, req.Offset, &data)
		if fetchErr != nil {
			return nil, fuse.IOerror{Code: syscall.EINVAL}
		}
		if sz == 0 {
			return []byte{}, nil
		}

		if !req.NoCache {
			cntr.Lock()
			setErr := cntr.SetData(n.Path(), req.Offset, data)
			cntr.Unlock()
			if setErr != nil {
				return nil, fuse.IOerror{Code: syscall.EINVAL}
			}
		}

		return data[:sz], nil
	})
	if err != nil {
		return 0, err
	}

	data := result.([]byte)
	req.Data = data
	return len(data), nil
}

func (h *PassThrough) readCacheMissKey(
	cntr domain.ContainerIface,
	path string,
	offset int64,
	readLen int,
	namespaces []domain.NStype,
	noCache bool) string {

	return fmt.Sprintf("%s|%s|%d|%d|%t|%s", cntr.ID(), path, offset, readLen, noCache, strings.Join(namespaces, ","))
}
