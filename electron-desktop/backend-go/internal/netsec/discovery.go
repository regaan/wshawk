package netsec

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func hostname(target string) (string, error) {
	target = strings.TrimSpace(target)
	if parsed, err := url.Parse(target); err == nil && parsed.Hostname() != "" {
		target = parsed.Hostname()
	}
	target = strings.Trim(target, "[]")
	if target == "" || strings.ContainsAny(target, "\r\n\x00 /\\") {
		return "", errors.New("valid hostname or IP is required")
	}
	return target, nil
}

func DNS(ctx context.Context, target string) (map[string]any, error) {
	host, err := hostname(target)
	if err != nil {
		return nil, err
	}
	resolver := net.DefaultResolver
	addresses, addressErr := resolver.LookupHost(ctx, host)
	cname, _ := resolver.LookupCNAME(ctx, host)
	mx, _ := resolver.LookupMX(ctx, host)
	ns, _ := resolver.LookupNS(ctx, host)
	txt, _ := resolver.LookupTXT(ctx, host)
	if addressErr != nil && len(addresses) == 0 {
		return nil, addressErr
	}
	mxValues := make([]map[string]any, 0, len(mx))
	for _, item := range mx {
		mxValues = append(mxValues, map[string]any{"host": item.Host, "preference": item.Pref})
	}
	nsValues := make([]string, 0, len(ns))
	for _, item := range ns {
		nsValues = append(nsValues, item.Host)
	}
	return map[string]any{"host": host, "addresses": addresses, "cname": cname, "mx": mxValues, "ns": nsValues, "txt": txt, "records": addresses}, nil
}

func Subdomains(ctx context.Context, target string, names []string) (map[string]any, error) {
	root, err := hostname(target)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		names = []string{"www", "api", "app", "admin", "auth", "dev", "staging", "test", "ws", "socket", "graphql", "cdn", "static", "mail"}
	}
	if len(names) > 500 {
		return nil, errors.New("subdomain list exceeds 500 names")
	}
	canaries := make([]string, 0, 2)
	for index := 0; index < 2; index++ {
		value := make([]byte, 10)
		if _, err := rand.Read(value); err != nil {
			return nil, fmt.Errorf("create wildcard DNS canary: %w", err)
		}
		canaries = append(canaries, "wshawk-nohost-"+hex.EncodeToString(value)+"."+root)
	}
	return discoverSubdomains(ctx, root, names, canaries, net.DefaultResolver.LookupHost)
}

type subdomainResult struct {
	Name          string   `json:"name"`
	Addresses     []string `json:"addresses"`
	WildcardMatch bool     `json:"wildcard_match"`
}

type lookupHostFunc func(context.Context, string) ([]string, error)

func discoverSubdomains(ctx context.Context, root string, names, canaries []string, lookup lookupHostFunc) (map[string]any, error) {
	wildcardAddresses := map[string]bool{}
	wildcardChecks := 0
	for _, canary := range canaries {
		addresses, lookupErr := lookup(ctx, canary)
		if lookupErr != nil || len(addresses) == 0 {
			continue
		}
		wildcardChecks++
		for _, address := range addresses {
			wildcardAddresses[address] = true
		}
	}
	wildcardDetected := len(canaries) >= 2 && wildcardChecks == len(canaries)
	type result struct {
		Name      string
		Addresses []string
	}
	jobs := make(chan string)
	found := make(chan result, len(names))
	var wait sync.WaitGroup
	for index := 0; index < 10; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for name := range jobs {
				candidate := strings.TrimSpace(name) + "." + root
				addresses, lookupErr := lookup(ctx, candidate)
				if lookupErr == nil && len(addresses) > 0 {
					found <- result{Name: candidate, Addresses: addresses}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, name := range names {
			select {
			case jobs <- name:
			case <-ctx.Done():
				return
			}
		}
	}()
	wait.Wait()
	close(found)
	items := []subdomainResult{}
	ambiguous := []subdomainResult{}
	resolved := []subdomainResult{}
	for item := range found {
		wildcardMatch := false
		if wildcardDetected {
			for _, address := range item.Addresses {
				if wildcardAddresses[address] {
					wildcardMatch = true
					break
				}
			}
		}
		candidate := subdomainResult{Name: item.Name, Addresses: item.Addresses, WildcardMatch: wildcardMatch}
		resolved = append(resolved, candidate)
		if wildcardMatch {
			ambiguous = append(ambiguous, candidate)
		} else {
			items = append(items, candidate)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	sort.Slice(ambiguous, func(i, j int) bool { return ambiguous[i].Name < ambiguous[j].Name })
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].Name < resolved[j].Name })
	wildcardValues := make([]string, 0, len(wildcardAddresses))
	for address := range wildcardAddresses {
		wildcardValues = append(wildcardValues, address)
	}
	sort.Strings(wildcardValues)
	return map[string]any{"target": root, "subdomains": items, "candidates": resolved, "ambiguous": ambiguous, "checked": len(names), "wildcard_detected": wildcardDetected, "wildcard_addresses": wildcardValues, "wildcard_filtered": len(ambiguous)}, ctx.Err()
}

func PortScan(ctx context.Context, target, rawPorts string, timeoutMS int) (map[string]any, error) {
	host, err := hostname(target)
	if err != nil {
		return nil, err
	}
	ports, err := parsePorts(rawPorts)
	if err != nil {
		return nil, err
	}
	if timeoutMS <= 0 {
		timeoutMS = 750
	}
	if timeoutMS > 5000 {
		timeoutMS = 5000
	}
	type result struct {
		Port    int    `json:"port"`
		Service string `json:"service"`
		Banner  string `json:"banner,omitempty"`
	}
	jobs := make(chan int)
	open := make(chan result, len(ports))
	var wait sync.WaitGroup
	for index := 0; index < 50; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			dialer := net.Dialer{Timeout: time.Duration(timeoutMS) * time.Millisecond}
			for port := range jobs {
				connection, dialErr := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
				if dialErr == nil {
					_ = connection.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
					buffer := make([]byte, 512)
					count, _ := connection.Read(buffer)
					connection.Close()
					banner := strings.TrimSpace(strings.Map(func(char rune) rune {
						if char == '\r' || char == '\n' || char == '\t' || char >= 0x20 && char <= 0x7e {
							return char
						}
						return -1
					}, string(buffer[:count])))
					open <- result{Port: port, Service: serviceName(port), Banner: banner}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, port := range ports {
			select {
			case jobs <- port:
			case <-ctx.Done():
				return
			}
		}
	}()
	wait.Wait()
	close(open)
	items := []result{}
	for item := range open {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Port < items[j].Port })
	return map[string]any{"target": host, "open_ports": items, "ports_scanned": len(ports)}, ctx.Err()
}

func parsePorts(raw string) ([]int, error) {
	if strings.TrimSpace(raw) == "" {
		return []int{21, 22, 25, 53, 80, 110, 143, 443, 445, 3000, 3306, 5432, 6379, 8000, 8080, 8443, 9000, 9200}, nil
	}
	values := map[int]bool{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, _ := strconv.Atoi(bounds[0])
			end, _ := strconv.Atoi(bounds[1])
			if start < 1 || end > 65535 || start > end || end-start > 1023 {
				return nil, errors.New("invalid or oversized port range")
			}
			for port := start; port <= end; port++ {
				values[port] = true
			}
		} else {
			port, err := strconv.Atoi(part)
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid port %q", part)
			}
			values[port] = true
		}
		if len(values) > 1024 {
			return nil, errors.New("port list exceeds 1024")
		}
	}
	ports := make([]int, 0, len(values))
	for port := range values {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports, nil
}
func serviceName(port int) string {
	return map[int]string{21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 443: "https", 3306: "mysql", 5432: "postgresql", 6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch"}[port]
}
