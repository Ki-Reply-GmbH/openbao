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
		return
	}
	b = fmt.Appendf(nil, "%d.%d", t.Unix(), t.Nanosecond())
	return
}

func (n *NanoEpoch) UnmarshalJSON(b []byte) (err error) {
	if len(b) == 0 {
		return
	}

	var sec int64
	var nsec int64
	spl := strings.SplitN(string(b), ".", 2)

	// Theoretically should always be true. But alas, better safe than sorry.
	if spl[0] != "" {
		if sec, err = strconv.ParseInt(spl[0], 10, 64); err != nil {
			return
		}
	}
	if len(spl) == 2 {
		if nsec, err = strconv.ParseInt(spl[1], 10, 64); err != nil {
			return
		}
	}

	*n = NanoEpoch(time.Unix(sec, nsec))
	return
}
