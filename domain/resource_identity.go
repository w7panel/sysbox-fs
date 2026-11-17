package domain

// ResourceIdentity is the runtime's registration-time init identity. Cgroups
// can change afterwards; this seed must never replace a request's live view.
type ResourceIdentity struct {
	CgroupData    string
	Pidns         string
	InitStartTime uint64
}

// Optional for legacy container implementations and older runtime clients.
type ResourceIdentityContainer interface {
	ResourceIdentity() ResourceIdentity
	SetResourceIdentity(ResourceIdentity)
}

// ResourceViewIdentity is sampled once per request, including nested callers.
type ResourceViewIdentity struct {
	CgroupV2 string
	CgroupV1 map[string]string
	Pidns    string
	Err      error
}

func (r *HandlerRequest) ResourceView(load func() ResourceViewIdentity) ResourceViewIdentity {
	r.resourceViewOnce.Do(func() { r.resourceView = load() })
	return r.resourceView
}
