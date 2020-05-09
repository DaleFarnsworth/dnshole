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
	white = iota
	black
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

var tr = &http.Transport{
	TLSHandshakeTimeout:   time.Duration(30) * time.Second,
	ResponseHeaderTimeout: time.Duration(30) * time.Second,
}

var client = &http.Client{
	Transport: tr,
	Timeout:   time.Duration(120) * time.Second,
}

// listDesc contains the information needed to fetch and parse a list
// of domains.
type listDesc struct {
	url        string // The url containing the list of domains.
	fieldIndex int    // The, space separated, index of the domain on a line, origin 1.
	whiteBlack int    // whether the list is a whitelist or a blacklist
}

// listDescs holds all of the list descripters read from the config file.
var listDescs []listDesc

// parseDomain returns the domain name from field fieldIndex on a line.
func parseDomain(line string, fieldIndex int) string {
	if strings.HasPrefix(line, "#") {
		return ""
	}

	fields := strings.Fields(line)
	if fieldIndex >= len(fields) {
		return ""
	}

	return fields[fieldIndex]
}

// getBlacklistDomains returns all of the domain names in the
// blacklisted urls and not in the whitelisted urls of listDescs.
func getBlacklistDomains() []string {
	whiteDomainsList := make([][]string, 0)
	blackDomainsList := make([][]string, 0)

	callConcurrently(concurrency, len(listDescs), func(i int) {
		url := listDescs[i].url
		index := listDescs[i].fieldIndex
		wb := listDescs[i].whiteBlack

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
			if wb == white {
				if strings.HasPrefix(line, dnsholeMarkerLine) {
					break
				}
			}
			domain := parseDomain(line, index)
			if domain != "" {
				domains = append(domains, domain)
			}
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}

		switch wb {
		case white:
			whiteDomainsList = append(whiteDomainsList, domains)
		case black:
			blackDomainsList = append(blackDomainsList, domains)
		}
	})

	whiteDomainMap := make(map[string]bool)
	for _, domains := range whiteDomainsList {
		for _, domain := range domains {
			whiteDomainMap[domain] = true
		}
	}

	blackDomainMap := make(map[string]bool)
	for _, domains := range blackDomainsList {
		for _, domain := range domains {
			if !whiteDomainMap[domain] {
				blackDomainMap[domain] = true
			}
		}
	}

	blackDomains := make([]string, 0)
	for domain := range blackDomainMap {
		blackDomains = append(blackDomains, domain)
	}

	sort.Strings(blackDomains)

	return blackDomains
}

func sameFile(filenameA, filenameB string) bool {
	inputStat, err := os.Stat(hostsFilename)
	if err != nil {
		return false
	}

	outputStat, err := os.Stat(outputFilename)
	if err != nil {
		return false
	}

	if !os.SameFile(inputStat, outputStat) {
		return false
	}

	return true
}

// createNewHostsFile copies the original hosts file to newHostsFilename
// and then adds the new blacklisted domains to it.
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

func appendListDesc(whiteBlack int, fields []string, filename string, lineCount int) {
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

	listDescs = append(listDescs, listDesc{url, fieldIndex, whiteBlack})
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
	case "whitelist":
		appendListDesc(white, fields, filename, lineCount)

	case "blacklist":
		appendListDesc(black, fields, filename, lineCount)

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

func init() {
	log.SetPrefix(filepath.Base(os.Args[0]) + ": ")
	log.SetFlags(log.Lshortfile)

	flag.BoolVar(&wantHelp,
		"help",
		false,
		"Show this usage description.",
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

	// whitelist the domains already in the hosts file
	listDescs = append(listDescs, listDesc{hostsFilename, 2, white})

	domains := getBlacklistDomains()

	if !sameFile(hostsFilename, outputFilename) {
		createNewHostsFile(outputFilename, domains)
	} else {
		dir := filepath.Dir(hostsFilename)
		outputFilename = filepath.Join(dir, "dnshole_tmp_hosts")
		createNewHostsFile(outputFilename, domains)
		os.Rename(outputFilename, hostsFilename)
	}
}
