package fuse

import (
	"testing"

	"github.com/nestybox/sysbox-fs/domain"
	"github.com/nestybox/sysbox-fs/mocks"
)

func TestFuseResourceOwnerReleasedOnce(t *testing.T) {
	owner := &domain.ResourceOwner{ID: 1}
	handlers := &mocks.HandlerServiceIface{}
	handlers.On("ReleaseResourceOwner", owner).Once()
	service := &FuseServerService{hds: handlers}
	server := &fuseServer{resourceOwner: owner}
	service.releaseResourceOwner(server)
	service.releaseResourceOwner(server)
	handlers.AssertExpectations(t)
}
