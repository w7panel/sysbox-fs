package implementations

import (
	"fmt"
	"os"

	"github.com/nestybox/sysbox-fs/domain"
)

// Do not reuse registration-time cgroups: both init and nested processes may
// move after registration. Only reads within this single request share a view.
func requestResourceView(req *domain.HandlerRequest) domain.ResourceViewIdentity {
	return req.ResourceView(func() domain.ResourceViewIdentity {
		cg := cgroupForPid(req.Pid)
		ns, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", req.Pid))
		return domain.ResourceViewIdentity{CgroupV2: cg.v2Path, CgroupV1: cg.v1, Pidns: ns}
	})
}

func requestCgroup(req *domain.HandlerRequest) cgroupView {
	identity := requestResourceView(req)
	return cgroupView{v2Path: identity.CgroupV2, v1: identity.CgroupV1}
}
