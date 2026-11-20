package implementations

import (
	"fmt"
	"os"

	"github.com/nestybox/sysbox-fs/domain"
)

// Do not reuse registration-time cgroups: both init and nested processes may
// move after registration. Only reads within this single request share a view.
func requestCgroupIdentity(req *domain.HandlerRequest) domain.ResourceViewIdentity {
	return req.ResourceView(func() domain.ResourceViewIdentity {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", req.Pid))
		if err != nil {
			return domain.ResourceViewIdentity{Err: err}
		}
		cg := parseCgroupView(data)
		if cg.v2Path == "" && len(cg.v1) == 0 {
			return domain.ResourceViewIdentity{Err: fmt.Errorf("no cgroup for pid %d", req.Pid)}
		}
		return domain.ResourceViewIdentity{CgroupV2: cg.v2Path, CgroupV1: cg.v1}
	})
}

func requestResourceView(req *domain.HandlerRequest) domain.ResourceViewIdentity {
	identity := requestCgroupIdentity(req)
	if identity.Err != nil {
		return identity
	}
	identity.Pidns, identity.Err = req.PIDNamespace(func() (string, error) {
		ns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", req.Pid))
		if err == nil && ns == "" {
			err = fmt.Errorf("no pid namespace for pid %d", req.Pid)
		}
		return ns, err
	})
	return identity
}

func requireRequestResourceView(req *domain.HandlerRequest) error {
	if req == nil || req.Pid == 0 {
		return nil
	}
	return requestResourceView(req).Err
}

func requireRequestCgroup(req *domain.HandlerRequest) error {
	if req == nil || req.Pid == 0 {
		return nil
	}
	return requestCgroupIdentity(req).Err
}

func requestCgroup(req *domain.HandlerRequest) cgroupView {
	identity := requestCgroupIdentity(req)
	return cgroupView{v2Path: identity.CgroupV2, v1: identity.CgroupV1}
}
