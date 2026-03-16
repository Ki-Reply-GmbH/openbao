// Copyright (c) 2025 Brent Saner
// SPDX-License-Identifier: MIT

package totp

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type NanoEpoch time.Time

func (n NanoEpoch) MarshalJSON() (b []byte, err error) {
	t := time.Time(n)
	if t.IsZero() {
		return b, err
	}
	b = fmt.Appendf(nil, "%d.%d", t.Unix(), t.Nanosecond())
	return b, err
}

func (n *NanoEpoch) UnmarshalJSON(b []byte) (err error) {
	if len(b) == 0 {
		return err
	}

	s, ns, ok := strings.Cut(string(b), ".")
	if !ok {
		return err
	}

	var sec int64
	var nsec int64
	if sec, err = strconv.ParseInt(s, 10, 64); err != nil {
		return err
	}

	if nsec, err = strconv.ParseInt(ns, 10, 64); err != nil {
		return err
	}

	*n = NanoEpoch(time.Unix(sec, nsec))
	return err
}
