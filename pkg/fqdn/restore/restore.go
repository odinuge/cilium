// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// The restore package provides data structures important to restoring
// DNS proxy rules. This package serves as a central source for these
// structures.
// Note that these are marshaled as JSON and any changes need to be compatible
// across an upgrade!
package restore

import (
	"sort"
)

// DNSRules contains IP-based DNS rules for a set of ports (e.g., 53)
type DNSRules map[uint16]IPRules

// IPRules is an unsorted collection of IPrules
type IPRules []IPRule

// IPRule stores the allowed destination IPs for a DNS names matching a regex
type IPRule struct {
	// v1.12 and older versions depend on having this value provided as a string, but for future
	// improvements we gracefully handle reading it as nil as well. We always ensure that we currently
	// never write nil in order to break rolling back to v1.12 or earlier.
	Re  *string
	IPs map[string]struct{} // IPs, nil set is wildcard and allows all IPs!
}

// Sort is only used for testing
// Sorts in place, but returns IPRules for convenience
func (r IPRules) Sort() IPRules {
	sort.SliceStable(r, func(i, j int) bool {
		if r[i].Re != nil && r[j].Re != nil {
			return *r[i].Re < *r[j].Re
		}
		if r[i].Re != nil {
			return true
		}
		return false
	})
	return r
}

// Sort is only used for testing
// Sorts in place, but returns DNSRules for convenience
func (r DNSRules) Sort() DNSRules {
	for port, ipRules := range r {
		if len(ipRules) > 0 {
			ipRules = ipRules.Sort()
			r[port] = ipRules
		}
	}
	return r
}
