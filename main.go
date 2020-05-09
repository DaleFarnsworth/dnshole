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

// hostsFilename is the name of the system's hosts file.
const defaultHostsFilename = "/etc/hosts"

// dnsholeMarkerLine separates the original hosts contents from
// the additional content added by dnshole.
const dnsholeMarkerLine = "# ==== dnshole ===="

// concurrency is the maximum number of urls to retrieve concurrently.
var concurrency int

var inputOutputSameFile bool

// whitelistMap contains the list of domains that dnshole should not
// override.  It is a map to facilitate fast lookup.
var whitelistMap map[string]bool

// whitelistWildcards contains whitelist entries beginning with '*'
var whitelistWildcards []string

// getExistingHostDomains returns a slice containing the domain names
// specified in the original hosts file.
func getExistingHostDomains() []string {
	host, err := os.Open(inputFilename)
	if err != nil {
		log.Fatal(err)
	}
	defer host.Close()

	domains := make([]string, 0)
	scanner := bufio.NewScanner(host)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, dnsholeMarkerLine) {
			break
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, domain := range fields[1:] {
			domains = append(domains, domain)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return domains
}

// This function initializes whitelistMap
func populateKeepDomainMap() {
	keepDomains := []string{
		"localhost",
		"localhost.localdomain",
		"local",
		"broadcasthost",
		"ip6-localhost",
		"ip6-loopback",
		"ip6-localnet",
		"ip6-mcastprefix",
		"ip6-allnodes",
		"ip6-allrouters",
		"ip6-allhosts",
		"0.0.0.0",
	}

	for _, domain := range keepDomains {
		whitelistMap[domain] = true
	}

	hostDomains := getExistingHostDomains()
	for _, domain := range hostDomains {
		whitelistMap[domain] = true
	}
}

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

	domain := fields[fieldIndex]
	if whitelistMap[domain] {
		return ""
	}

	for _, wil := range whitelistWildcards {
		if strings.HasSuffix(domain, wil[1:]) {
			return ""
		}
	}

	return domain
}

// getDomains returns all of the domain names from the urls contained
// in listDescs.
func getDomains() []string {
	domainsList := make([][]string, len(listDescs))

	callConcurrently(concurrency, len(listDescs), func(i int) {
		url := listDescs[i].url
		fieldIndex := listDescs[i].fieldIndex

		res, err := client.Get(url)
		if err == nil && res.StatusCode != 200 {
			err = fmt.Errorf("Get \"%s\" returned status %d", url, res.StatusCode)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %s\n", err)
			return
		}
		domains := make([]string, 0)
		scanner := bufio.NewScanner(res.Body)
		for scanner.Scan() {
			domain := parseDomain(scanner.Text(), fieldIndex)
			if domain != "" {
				domains = append(domains, domain)
			}
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}

		domainsList[i] = domains
	})

	domainMap := make(map[string]bool)

	for _, domains := range domainsList {
		for _, domain := range domains {
			domainMap[domain] = true
		}
	}

	domains := make([]string, 0)
	for domain := range domainMap {
		domains = append(domains, domain)
	}

	sort.Strings(domains)

	return domains
}

// createNewHostsFile copies the original hosts file to newHostsFilename
// and then adds the new dnshole domains to it.
func createNewHostsFile(domains []string) {
	var err error
	host, err := os.Open(inputFilename)
	if err != nil {
		log.Fatal(err)
	}
	defer host.Close()

	var newHost *os.File
	if outputFilename == "-" {
		newHost = os.Stdout
	} else {
		inputStat, err := os.Stat(inputFilename)
		if err != nil {
			log.Fatal(err)
		}

		outputStat, err := os.Stat(outputFilename)
		if err == nil && os.SameFile(inputStat, outputStat) {
			inputOutputSameFile = true
			dir := filepath.Dir(inputFilename)
			outputFilename = filepath.Join(dir, "dnshole_tmp_hosts")
		}

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

// blankRE holds a compiled regexp matching a line containing only whitespace.
var blankRE *regexp.Regexp

func init() {
	blankRE = regexp.MustCompile(`^\s*$`)
}

// processConfigLine processes a single config file line contained in line.
func processConfigLine(line string, filename string, lineCount int) {
	if strings.HasPrefix(line, "#") {
		return
	}
	if blankRE.MatchString(line) {
		return
	}

	fields := strings.Fields(line)
	switch strings.ToLower(fields[0]) {
	case "list":
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
		listDescs = append(listDescs, listDesc{url, fieldIndex})

	case "concurrency":
		if len(fields) != 2 {
			log.Fatalf("%s:%d: wrong number of fields\n", filename, lineCount)
		}
		var err error
		concurrency, err = strconv.Atoi(fields[1])
		if err != nil {
			log.Fatalf("%s:%d: non-numeric concurrency\n", filename, lineCount)
		}

	case "whitelist":
		if len(fields) != 2 {
			log.Fatalf("%s:%d: wrong number of fields\n", filename, lineCount)
		}
		whiteDomain := fields[1]
		if whiteDomain[0] == '*' {
			whitelistWildcards = append(whitelistWildcards, whiteDomain)
		} else {
			whitelistMap[fields[1]] = true
		}

	default:
		log.Fatalf("%s:%d: unknown directive: %s\n", filename, lineCount, fields[0])
	}

}

// readConfig reads and processes dnshole's config file.
func readConfig(filename string) {
	config, err := os.Open(configFilename)
	if err != nil {
		log.Fatal(err)
	}
	defer config.Close()

	listDescs = make([]listDesc, 0)
	whitelistMap = make(map[string]bool)
	whitelistWildcards = make([]string, 0)

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

// configFilename holds the name of dnshole's config file.
var configFilename string

// inputFilename holds the name of a specified input file
var inputFilename string

// outputFilename holds the name of a specified output file
var outputFilename string

// wantHelp causes a help message to be printed if true.
var wantHelp bool

// This init function initialize the log and flag packages.
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
		"/etc/dnshole.conf",
		"Configuration file name",
	)

	flag.StringVar(&inputFilename,
		"input",
		defaultHostsFilename,
		"Input file name",
	)

	flag.StringVar(&outputFilename,
		"output",
		"",
		"Output file name, \"-\" means stdout (default same as input)",
	)

	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr,
			"Usage: %s: [flags] [<input file name>]\n",
			os.Args[0])

		fmt.Fprintln(os.Stderr, "Flags:")
		flag.PrintDefaults()
		os.Exit(1)
	}
}

// main directs the overall execution of the program.
func main() {
	flag.Parse()

	if wantHelp {
		flag.Usage()
	}

	switch len(flag.Args()) {
	case 0:

	case 1:
		if inputFilename != defaultHostsFilename {
			flag.Usage()
		}
		inputFilename = flag.Args()[0]

	default:
		flag.Usage()
	}

	if outputFilename == "" {
		outputFilename = inputFilename
	}

	whitelistMap = make(map[string]bool)
	readConfig(configFilename)

	populateKeepDomainMap()

	domains := getDomains()
	createNewHostsFile(domains)

	if inputOutputSameFile {
		os.Rename(outputFilename, inputFilename)
	}
}
