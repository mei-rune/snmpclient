package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

type IPRange struct {
	start uint32
	end   uint32
	cur   uint32
}

func (self *IPRange) Reset() {
	self.cur = self.start - 1
}

func (self *IPRange) HasNext() bool {
again:
	if self.cur >= self.end {
		return false
	}
	self.cur++

	var b [4]byte
	binary.BigEndian.PutUint32(b[:], self.cur)
	if b[3] == 0 || b[3] == 255 {
		goto again
	}
	return true
}

func (self *IPRange) Current() net.IP {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], self.cur)
	return net.IPv4(b[0], b[1], b[2], b[3])
}

// Parses a dotted octet IP address into an unsigned 32-bit int
func parseIPV4(s string) uint32 {
	ip := net.ParseIP(s)
	if nil == ip {
		return 0
	}
	return binary.BigEndian.Uint32(ip.To4())
}

// Parses a string IP address range into an IPRange
func ParseIPRange(raw string) (*IPRange, error) {
	start, end := uint32(0), uint32(0)

	fields := strings.Split(raw, "-")
	if 2 != len(fields) {
		ip := parseIPV4(raw)
		if 0 != ip {
			return &IPRange{start: ip, end: ip, cur: ip - 1}, nil
		}
		_, ipNet, e := net.ParseCIDR(raw)
		if nil != e {
			return nil, errors.New("syntex error: please input corrent sytex, such 'xxx.xxx.xxx.xxx-yyy.yyy.yyy.yyy - '" + raw + "'")
		}
		start = binary.BigEndian.Uint32(ipNet.IP.To4())
		ones, bits := ipNet.Mask.Size()
		end = start + (uint32(1) << uint32(bits-ones))
	} else {
		start = parseIPV4(fields[0])
		end = parseIPV4(fields[1])
	}
	if 0 == start {
		return nil, errors.New("start address is syntex error - '" + raw + "'")
	}
	if 0 == end {
		return nil, errors.New("end address is syntex error - '" + raw + "'")
	}
	if start > end {
		return nil, errors.New("start address geater than end address - '" + raw + "'")
	}
	return &IPRange{start: start, end: end, cur: start - 1}, nil
}

// Returns a dotted octet format of the ip address
func ipString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip>>24&0xFF, ip>>16&0xFF, ip>>8&0xFF, ip&0xFF)
}

// Returns the start and end IP's of an IPRange
func (ipr IPRange) String() string {
	return fmt.Sprintf("%s-%s", ipString(ipr.start), ipString(ipr.end))
}

// // package main

// import (
// 	"io"

// 	"os"

// 	"fmt"

// 	"path"

// 	"sort"

// 	"sync"

// 	"bufio"

// 	"runtime"

// 	"strings"

// 	"net/http"

// 	"archive/zip"

// 	"encoding/xml"

// 	"encoding/json"

// 	"path/filepath"

// 	"encoding/binary"
// )

// const (
// 	TEMP = "Temp"

// 	SOURCE_URL = "http://www.iblocklist.com/lists.xml"

// 	SOURCE_CONFIG = "config.json"

// 	LIST_URL = "http://list.iblocklist.com/?list=%s&fileformat=p2p&archiveformat=zip"

// 	OUTPUT_FILE = "ipfilter.dat"

// 	// # of threads for downloading lists

// 	NUM_THREADS = 8
// )

// var (
// 	workingDirectory string
// )

// // Used for reading the list from iblocklist

// // and for writing the configuration file

// type Config struct {
// 	Lists []List `xml:"list"`
// }

// // A single list item

// type List struct {
// 	List string `xml:"list"`

// 	Name string `xml:"name"`

// 	Author string `xml:"author"`

// 	Description string `xml:"description"`

// 	Enabled bool
// }

// // Specifies an IP range with description

// type IPRange struct {
// 	Min, Max uint32

// 	Description string
// }

// type IPRangeList []IPRange

// // Satisfies sort.Interface

// func (iprl IPRangeList) Len() int {

// 	return len(iprl)

// }

// // Satisfies sort.Interface

// func (iprl IPRangeList) Less(a, b int) bool {

// 	return iprl[a].Less(iprl[b])

// }

// // Satisfies sort.Interface

// func (iprl IPRangeList) Swap(a, b int) {

// 	iprl[a], iprl[b] = iprl[b], iprl[a]

// }

// // Used above for sort.Interface

// func (ipr IPRange) Less(b interface{}) bool {

// 	return ipr.Min < b.(IPRange).Min

// }

// // Returns a dotted octet format of the ip address

// func IPToString(ip uint32) string {

// 	return fmt.Sprintf("%03d.%03d.%03d.%03d", ip>>24&0xFF, ip>>16&0xFF, ip>>8&0xFF, ip&0xFF)

// }

// // Returns the start and end IP's of an IPRange

// func (ipr IPRange) String() string {

// 	return fmt.Sprintf("%s - %s", IPToString(ipr.Min), IPToString(ipr.Max))

// }

// // Merges overlapping IP ranges together and returns a condensed list

// func MergeRanges(iprl IPRangeList) (merged IPRangeList, count uint32) {

// 	var (
// 		cursor, next IPRange

// 		i, j int
// 	)

// 	// For all IPRanges

// 	for i = 0; i < len(iprl); i = j {

// 		cursor = iprl[i]

// 		// For all IPRanges following the cursor

// 		for j = i + 1; j < len(iprl); j++ {

// 			next = iprl[j]

// 			// If the cursor overlaps this range

// 			if cursor.Max > next.Min {

// 				// Increment the merge count

// 				count++

// 				// If it's not a complete overlap

// 				// then set the cursor's new max

// 				if cursor.Max < next.Max {

// 					cursor.Max = next.Max

// 				}

// 			} else {

// 				// Cursor doesn't overlap this range so this cursor is complete

// 				break

// 			}

// 		}

// 		// Add cursor to the list of merged ranges

// 		merged = append(merged, cursor)

// 	}

// 	return

// }

// // Downloads a blocklist

// func Download(url string, filename string, sema chan int, wg *sync.WaitGroup) {

// 	// Wait for room on the semaphore

// 	sema <- 1

// 	fmt.Printf("Downloading %s\n", url)

// 	// Download the url

// 	r, err := http.Get(url)

// 	HandleError("Error retrieving source list: ", err)

// 	// Make sure we close the connection before we exit the function

// 	defer r.Body.Close()

// 	// Create the file to write the contents to

// 	destFile, err := os.Create(filename)

// 	HandleError("Error creating source list archive: ", err)

// 	// Copy the body to the file

// 	io.Copy(destFile, r.Body)

// 	destFile.Close()

// 	// Signal to the waitgroup that this job is finished

// 	if wg != nil {

// 		wg.Done()

// 	}

// 	// Release the semaphore

// 	<-sema

// }

// // Parses a dotted octet IP address into an unsigned 32-bit int

// func ParseIP(s string) uint32 {

// 	b := make([]uint8, 4)

// 	fmt.Sscanf(s, "%d.%d.%d.%d", &b[0], &b[1], &b[2], &b[3])

// 	return binary.BigEndian.Uint32(b)

// }

// // Parses a string IP address range into an IPRange

// func ReadIPRange(raw string) (ipr IPRange) {

// 	fields := strings.Split(raw, "-")

// 	ipr.Min, ipr.Max = ParseIP(fields[0]), ParseIP(fields[1])

// 	return

// }

// // Takes a reader and returns a list of IP Ranges

// func ReadBlockList(r io.Reader, rangeList *IPRangeList) {

// 	// Need buffering to read by lines

// 	buf := bufio.NewReader(r)

// 	// For each line in the file

// 	for line, _, err := buf.ReadLine(); err != io.EOF; line, _, err = buf.ReadLine() {

// 		var splitAt int

// 		l := strings.TrimSpace(string(line))

// 		// If it's a comment and can't be split at a ':' then skip it

// 		if splitAt = strings.LastIndex(l, ":"); splitAt == 1 || strings.HasPrefix(l, "#") || len(l) == 0 {

// 			continue

// 		}

// 		// Must be an IP range so parse it

// 		ipr := ReadIPRange(l[splitAt+1:])

// 		// Add it to the list

// 		*rangeList = append(*rangeList, IPRange{ipr.Min, ipr.Max, l[:splitAt]})

// 	}

// }

// // Reads the config file

// func ReadConfiguration() Config {

// 	_, err := os.Stat(path.Join(workingDirectory, SOURCE_CONFIG))

// 	// If we couldn't stat the config file then it doesn't exist, write one

// 	if err != nil {

// 		fmt.Println("No configuration file found, writing one...")

// 		fmt.Println("Getting new source list...")

// 		// Get the list of sources from iblocklist.com

// 		r, err := http.Get(SOURCE_URL)

// 		HandleError("Error retrieving source list: ", err)

// 		defer r.Body.Close()

// 		// Unmarshall the source list

// 		var config Config

// 		configDecoder := xml.NewDecoder(r.Body)

// 		err = configDecoder.Decode(&config)

// 		HandleError("Error unmarshalling configuration: ", err)

// 		// Create the config file

// 		sourceConfigFile, err := os.Create(SOURCE_CONFIG)

// 		HandleError("Error creating source configuration file: ", err)

// 		defer sourceConfigFile.Close()

// 		// Write an indented json form of the config to file

// 		data, err := json.MarshalIndent(config, "", "\t")

// 		sourceConfigFile.Write(data)

// 		fmt.Println("Writing source configuration...")

// 		fmt.Println("Enable some sources before re-running.")

// 		// User needs to enable some sources before this runs

// 		// so just exit after telling them

// 		os.Exit(1)

// 	}

// 	var config Config

// 	// Open the config file

// 	sourceConfigFile, err := os.Open(path.Join(workingDirectory, SOURCE_CONFIG))

// 	HandleError("Error opening source configuration file: ", err)

// 	defer sourceConfigFile.Close()

// 	fmt.Println("Reading source configuration...")

// 	// Unmarshall the config file

// 	configDecoder := json.NewDecoder(sourceConfigFile)

// 	err = configDecoder.Decode(&config)

// 	HandleError("Error decoding source configuration: ", err)

// 	// Check if there are any enabled sources

// 	existSources := false

// 	for _, source := range config.Lists {

// 		existSources = existSources || source.Enabled

// 	}

// 	// If there aren't any enabled sources then exit and tell the user to enable some

// 	if !existSources {

// 		fmt.Printf("No sources enabled in %s, enable some then run again.\n", SOURCE_CONFIG)

// 		os.Exit(1)

// 	}

// 	return config

// }

// // Writes ipfilter.dat in eDonkey//eMule blocklist format

// func WriteIPFilter(f *os.File, iprl []IPRange) {

// 	for _, ipr := range iprl {

// 		fmt.Fprintf(f, "%s , 000 , %s\n", ipr, ipr.Description)

// 	}

// }

// // For handling errors, useful for debugging

// func HandleError(msg string, err error) {

// 	if err != nil {

// 		_, file, line, ok := runtime.Caller(1)

// 		filename := filepath.Base(file)

// 		if ok {

// 			fmt.Printf("%s:%d: %s %s\n", filename, line, msg, err)

// 			os.Exit(1)

// 		}

// 	}

// }

// func main() {

// 	// Get the directory the binary lives in

// 	workingDirectory, _ = path.Split(os.Args[0])

// 	err := os.RemoveAll(path.Join(workingDirectory, TEMP))

// 	HandleError("Error removing temporary directory: ", err)

// 	err = os.Mkdir(path.Join(workingDirectory, TEMP), 0775)

// 	HandleError("Error creating temporary directory: ", err)

// 	// Read the configuration

// 	sourceList := ReadConfiguration()

// 	// Create a waitgroup and semaphore

// 	var wg sync.WaitGroup

// 	sema := make(chan int, NUM_THREADS)

// 	// For each of the sources

// 	for _, source := range sourceList.Lists {

// 		if source.Enabled {

// 			// Add a job to the waitgroup

// 			wg.Add(1)

// 			// It's enabled so start a goroutine to download it

// 			go Download(

// 				fmt.Sprintf(LIST_URL, source.List),

// 				path.Join(workingDirectory, TEMP, strings.ToLower(strings.Replace(source.Name, " ", "_", -1))+".zip"),

// 				sema,

// 				&wg)

// 		}

// 	}

// 	// Block until all the blocklists have been downloaded

// 	wg.Wait()

// 	rangeList := new(IPRangeList)

// 	// Get a list of all the archives for blocklists

// 	blockLists, err := filepath.Glob(path.Join(workingDirectory, TEMP, "*.zip"))

// 	HandleError("Error globbing for blocklist archives: ", err)

// 	// For each blocklist archive

// 	for _, listArchive := range blockLists {

// 		// Open the archive

// 		listArchiveZip, err := zip.OpenReader(listArchive)

// 		HandleError("Error opening list archive: ", err)

// 		defer listArchiveZip.Close()

// 		// For each file in the archive

// 		for _, file := range listArchiveZip.File {

// 			// Open the file

// 			fmt.Printf("Reading %s...\n", listArchive)

// 			blockListFile, err := file.Open()

// 			HandleError("Error reading blocklist: ", err)

// 			defer blockListFile.Close()

// 			// Parse the blocklist

// 			ReadBlockList(blockListFile, rangeList)

// 		}

// 	}

// 	// Sort the list of all ranges

// 	sort.Sort(rangeList)

// 	fmt.Printf("Sorted %d ranges...\n", rangeList.Len())

// 	// Merge all of the ranges and let the user know how many were merged

// 	mergedList, count := MergeRanges(*rangeList)

// 	fmt.Printf("Merged %d ranges...\n", count)

// 	// Create the output file

// 	outFile, err := os.Create(path.Join(workingDirectory, OUTPUT_FILE))

// 	HandleError("Error creating output file: ", err)

// 	defer outFile.Close()

// 	// Write the blocklist to file

// 	fmt.Println("Writing ranges to file...")

// 	WriteIPFilter(outFile, mergedList)

// 	fmt.Printf("Wrote %d ranges to file...\n", mergedList.Len())

// }
