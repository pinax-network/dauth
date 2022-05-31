// Copyright 2019 dfuse Platform Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authenticator

import (
	"net"
	"net/http"
	"strings"
)

func RealIPFromRequest(r *http.Request) string {

	var remoteIP string

	if remoteAddr, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if ip := net.ParseIP(remoteAddr); ip != nil {
			remoteIP = ip.String()
		}
	}

	if xff := strings.Trim(r.Header.Get("X-Forwarded-For"), ","); len(xff) > 0 {
		addrs := strings.Split(xff, ",")
		lastFwd := addrs[len(addrs)-1]
		if ip := net.ParseIP(lastFwd); ip != nil {
			remoteIP = ip.String()
		}
	} else if xri := r.Header.Get("X-Real-Ip"); len(xri) > 0 {
		if ip := net.ParseIP(xri); ip != nil {
			remoteIP = ip.String()
		}
	}

	return remoteIP
}

func RealIP(forwardIPs string) string {
	if forwardIPs != "" {
		addresses := strings.Split(forwardIPs, ",")
		return strings.TrimSpace(addresses[0])
	}

	return "0.0.0.0"
}
