// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package routing

import "context"

// RouterAccess provides access into some things necessary for testing
type RouterAccess struct {
	router *Router
}

func NewRouterAccess(r *Router) *RouterAccess {
	return &RouterAccess{router: r}
}

func (r *RouterAccess) StoragePrefixByAPIPath(ctx context.Context, path string) (string, bool) {
	return r.router.MatchingStoragePrefixByAPIPath(ctx, path)
}
