// Copyright 2020 Dale Farnsworth. All rights reserved.

// Dale Farnsworth
// 1007 W Mendoza Ave
// Mesa, AZ  85210
// USA
//
// dale@farnsworth.org

// dnshole is free software: you can redistribute it and/or modify
// it under the terms of version 3 of the GNU General Public License
// as published by the Free Software Foundation.
//
// dnshole is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with dnshole.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// dnsholeMarkerLine separates the original hosts contents from
// the additional content added by dnshole.
const dnsholeMarkerLine = "# ==== dnshole ===="

const (
	allow = iota
	block
)

// concurrency is the maximum number of files/urls to retrieve concurrently.
var concurrency int

// callConcurrently calls fcn count times with at most concurrency
// instances of fcn running concurrently.
func callConcurrently(concurrency int, count int, fcn func(int)) {
	semaphore := make(chan struct{}, concurrency)
	done := make(chan struct{})

	defer func() {
		close(semaphore)
		close(done)
	}()

	for i := 0; i < count; i += 1 {
		go func(i int) {
			semaphore <- struct{}{}
			fcn(i)
			done <- struct{}{}
			<-semaphore
		}(i)
	}

	// Wait for all the function calls to complete.
	for i := 0; i < count; i += 1 {
		<-done
	}
}

// listDesc contains the information needed to fetch and parse a list
// of domains.
type listDesc struct {
	url        string // The url containing the list of domains.
	fieldIndex int    // The, space separated, index of the domain on a line, origin 1.
	allowBlock int    // whether the list is a allowlist or a blocklist
}

// listDescs holds all of the list descripters read from the config file.
var listDescs []listDesc

// parseDomains returns the domain names from field fieldIndex on a line.
func parseDomains(line string, fieldIndex int) []string {
	i := strings.Index(line, "#")
	if i >= 0 {
		line = line[:i]
	}

	fields := strings.Fields(line)
	if fieldIndex >= len(fields) {
		return nil
	}
	return fields[fieldIndex:]
}

// getBlocklistDomains returns all of the domain names in the
// blocklisted urls and not in the allowlisted urls of listDescs.
func getBlocklistDomains() []string {
	tr := http.DefaultTransport.(*http.Transport)
	tr.TLSHandshakeTimeout = time.Duration(30) * time.Second
	tr.ResponseHeaderTimeout = time.Duration(30) * time.Second

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(120) * time.Second,
	}

	if insecureSSL {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	allowDomainsList := make([][]string, 0)
	blockDomainsList := make([][]string, 0)

	callConcurrently(concurrency, len(listDescs), func(i int) {
		url := listDescs[i].url
		index := listDescs[i].fieldIndex
		wb := listDescs[i].allowBlock

		var reader io.Reader
		if !strings.Contains(url, "://") {
			file, err := os.Open(url)
			if err != nil {
				log.Fatal(err)
			}
			reader = file
		} else {
			res, err := client.Get(url)
			if err == nil && res.StatusCode != 200 {
				err = fmt.Errorf("Get \"%s\" returned status %d", url, res.StatusCode)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: %s\n", err)
				return
			}
			reader = res.Body
		}
		domains := make([]string, 0)
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			line := scanner.Text()
			if wb == allow {
				if strings.HasPrefix(line, dnsholeMarkerLine) {
					break
				}
			}

			parsedDomains := parseDomains(line, index)
			domains = append(domains, parsedDomains...)
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}

		switch wb {
		case allow:
			allowDomainsList = append(allowDomainsList, domains)
		case block:
			blockDomainsList = append(blockDomainsList, domains)
		}
	})

	allowDomainMap := make(map[string]bool)
	for _, domains := range allowDomainsList {
		for _, domain := range domains {
			allowDomainMap[domain] = true
		}
	}

	blockDomainMap := make(map[string]bool)
	for _, domains := range blockDomainsList {
		for _, domain := range domains {
			if !allowDomainMap[domain] {
				blockDomainMap[domain] = true
			}
		}
	}

	blockDomains := make([]string, 0)
	for domain := range blockDomainMap {
		blockDomains = append(blockDomains, domain)
	}

	sort.Strings(blockDomains)

	return blockDomains
}

func sameFile(filenameA, filenameB string) bool {
	statA, err := os.Stat(filenameA)
	if err != nil {
		return false
	}

	statB, err := os.Stat(filenameB)
	if err != nil {
		return false
	}

	if !os.SameFile(statA, statB) {
		return false
	}

	return true
}

// createNewHostsFile copies the original hosts file to newHostsFilename
// and then adds the new blocklisted domains to it.
func createNewHostsFile(outputFilename string, domains []string) {
	var err error
	host, err := os.Open(hostsFilename)
	if err != nil {
		log.Fatal(err)
	}
	defer host.Close()

	var newHost *os.File
	if outputFilename == "-" {
		newHost = os.Stdout
	} else {
		newHost, err = os.Create(outputFilename)
		if err != nil {
			log.Fatal(err)
		}
	}

	var lastLine string

	scanner := bufio.NewScanner(host)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, dnsholeMarkerLine) {
			break
		}
		fmt.Fprintln(newHost, line)
		lastLine = line
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	if !blankRE.MatchString(lastLine) {
		fmt.Fprintln(newHost, "")
	}

	fmt.Fprintln(newHost, dnsholeMarkerLine+" Do not edit this line or following lines.")
	fmt.Fprintln(newHost, "# They are automatically generated by dnshole.")
	timeStr := time.Now().Format(" Monday 2006-01-02 15:04:05 MST")
	fmt.Fprintln(newHost, "# Generated"+timeStr)
	fmt.Fprintln(newHost, "")

	for _, domain := range domains {
		fmt.Fprintf(newHost, "0.0.0.0 %s\n", domain)
	}

	if err := newHost.Close(); err != nil {
		log.Fatal(err)
	}
}

var blankRE *regexp.Regexp

func init() {
	blankRE = regexp.MustCompile(`^\s*$`)
}

func appendListDesc(allowBlock int, fields []string, filename string, lineCount int) {
	if len(fields) != 3 {
		log.Fatalf("%s:%d: wrong number of fields\n", filename, lineCount)
	}
	fieldIndex, err := strconv.Atoi(fields[1])
	if err != nil {
		log.Fatalf("%s:%d: non-numeric field index\n", filename, lineCount)
	}
	fieldIndex -= 1
	if fieldIndex < 0 {
		log.Fatalf("%s:%d: field index must be greater than 0\n", filename, lineCount)
	}
	url := fields[2]

	listDescs = append(listDescs, listDesc{url, fieldIndex, allowBlock})
}

func processConfigLine(line string, filename string, lineCount int) {
	if strings.HasPrefix(line, "#") {
		return
	}
	if blankRE.MatchString(line) {
		return
	}

	fields := strings.Fields(line)
	switch strings.ToLower(fields[0]) {
	case "allowlist":
		appendListDesc(allow, fields, filename, lineCount)

	case "blocklist":
		appendListDesc(block, fields, filename, lineCount)

	case "concurrency":
		if len(fields) != 2 {
			log.Fatalf("%s:%d: wrong number of fields\n", filename, lineCount)
		}
		var err error
		concurrency, err = strconv.Atoi(fields[1])
		if err != nil {
			log.Fatalf("%s:%d: non-numeric concurrency\n", filename, lineCount)
		}

	default:
		log.Fatalf("%s:%d: unknown directive: %s\n", filename, lineCount, fields[0])
	}

}

func readConfigFile(filename string) {
	config, err := os.Open(configFilename)
	if err != nil {
		log.Fatal(err)
	}
	defer config.Close()

	listDescs = make([]listDesc, 0)

	lineCounter := 1
	scanner := bufio.NewScanner(config)
	for scanner.Scan() {
		processConfigLine(scanner.Text(), filename, lineCounter)
		lineCounter += 1
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

var configFilename string
var hostsFilename string
var outputFilename string
var wantHelp bool
var insecureSSL bool

func init() {
	log.SetPrefix(filepath.Base(os.Args[0]) + ": ")
	log.SetFlags(log.Lshortfile)

	flag.BoolVar(&wantHelp,
		"help",
		false,
		"Show this usage description.",
	)

	flag.BoolVar(&insecureSSL,
		"insecure-ssl",
		false,
		"Ignore problems with host security certificates",
	)

	flag.StringVar(&configFilename,
		"config",
		"/etc/dnshole/dnshole.conf",
		"Configuration file name",
	)

	flag.StringVar(&outputFilename,
		"output",
		"",
		"Output file name, \"-\" means stdout (default is <hosts_filename>)",
	)

	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr,
			"Usage: %s: [flags] <hosts_filename>\n",
			os.Args[0])

		fmt.Fprintln(os.Stderr, "Flags:")
		flag.PrintDefaults()
		os.Exit(1)
	}
}

func main() {
	flag.Parse()

	if len(flag.Args()) != 1 || wantHelp {
		flag.Usage()
	}

	hostsFilename = flag.Args()[0]

	if outputFilename == "" {
		outputFilename = hostsFilename
	}

	readConfigFile(configFilename)

	// allowlist the domains already in the hosts file
	listDescs = append(listDescs, listDesc{hostsFilename, 2, allow})

	domains := getBlocklistDomains()

	if !sameFile(hostsFilename, outputFilename) {
		createNewHostsFile(outputFilename, domains)
	} else {
		dir := filepath.Dir(hostsFilename)
		outputFilename = filepath.Join(dir, "dnshole_tmp_hosts")
		createNewHostsFile(outputFilename, domains)
		os.Rename(outputFilename, hostsFilename)
	}
}
