package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/fatih/color"
	"github.com/karrick/godirwalk"
)

var printMutex = new(sync.Mutex)

var mode = flag.String("mode", "report", "the output mode, either \"report\" (every java archive pretty printed) or \"list\" (list of potentially vulnerable files)")
var includeZip = flag.Bool("include-zip", false, "include zip files in the scan")

func main() {
	// Parse the arguments and flags provided to the program.
	flag.Parse()

	stderr := log.New(os.Stderr, "", 0)

	if flag.Arg(0) == "" {
		stderr.Println("Usage: log4shelldetect [options] <path>")
		stderr.Println("Scans a file or folder recursively for Java programs that may be vulnerable to:")
		stderr.Println("- CVE-2021-44228 (Log4Shell) (v2.0.x - v2.14.x)")
		stderr.Println("- CVE-2021-45046 (v2.15.x)")
		stderr.Println("- CVE-2021-45105 (v2.16.x)")
		stderr.Println("by inspecting the class paths inside Java archives")
		stderr.Println("")
		stderr.Println("Options:")
		flag.PrintDefaults()
		os.Exit(2)
	}

	target := flag.Arg(0)

	// Identify if the provided path is a file or a folder.
	f, err := os.Stat(target)
	if err != nil {
		stderr.Println("Error accessing target path:", err)
		os.Exit(1)
	}

	if !f.IsDir() {
		// If it's a file, check it and then exit.
		checkJar(target, nil, 0, 0)
		return
	}

	// Create a multithreading pool with 8 goroutines (threads)
	// for concurrent scanning of jars.
	pool := make(chan struct{}, 8)

	var hasNotableResults uint32

	// Scan through the directory provided recursively.
	err = godirwalk.Walk(target, &godirwalk.Options{
		Callback: func(osPathname string, de *godirwalk.Dirent) error {
			// For each file in the directory, check if it ends in a known Java archive extension
			if shouldCheck(osPathname) {
				pool <- struct{}{}
				// If it is, take a goroutine (thread) from the thread pool
				// and check the jar.
				go func() {
					status, desc := checkJar(osPathname, nil, 0, 0)
					if *mode == "list" {
						switch status {
						case StatusVulnerable, StatusMaybe, StatusOld, StatusSecondOld, StatusThirdOld:
							atomic.StoreUint32(&hasNotableResults, 1)
						}
					} else {
						switch status {
						case StatusVulnerable, StatusMaybe, StatusOld, StatusPatched, StatusSecondOld, StatusThirdOld:
							atomic.StoreUint32(&hasNotableResults, 1)
						}
					}
					// Print the result of the check.
					printStatus(osPathname, status, desc)
					<-pool
				}()
			}

			return nil
		},
		ErrorCallback: func(osPathname string, err error) godirwalk.ErrorAction {
			// On directory traversal error, print a warning.
			printMutex.Lock()
			defer printMutex.Unlock()
			log.Printf("skipping %q: %v", osPathname, err)
			return godirwalk.SkipNode
		},
		Unsorted: true,
	})
	if err != nil {
		stderr.Println("Error scanning target path:", err)
		os.Exit(1)
	}

	// Wait for all goroutines (threads) to complete their work.
	for i := 0; i < cap(pool); i++ {
		pool <- struct{}{}
	}

	if hasNotableResults != 0 {
		os.Exit(3)
	}
}

func shouldCheck(filename string) bool {
	ext := strings.ToLower(path.Ext(filename))
	switch ext {
	case ".zip":
		if !*includeZip {
			return false
		}
		return true
	case ".jar", ".war", ".ear":
		return true
	}

	return false
}

// checkJar checks a given archive file and returns a status and description for whether
// or not the Log4Shell vulnerability is detected in the archive.
func checkJar(pathToFile string, rd io.ReaderAt, size int64, depth int) (status Status, desc string) {
	// checkJar also checks for embedded jars (jars inside jars) as this is fairly common occurrence
	// in some jar distributions.
	// Bail out if we're checking the 101st deep jar in a jar (i.e. jar in a jar in a jar in a jar, etc... 100 times).
	if depth > 100 {
		status = StatusUnknown
		desc = "reached recursion limit of 100 (why do you have so many jars in jars???)"
		return
	}

	err := func() error {
		// checkJar can either be provided the path to the jar file, or a byte stream reader.
		// If no reader is provided, we'll open the file and set it as the byte stream reader.
		if rd == nil {
			f, err := os.Open(pathToFile)
			if err != nil {
				return err
			}
			defer f.Close()

			// Stat the file to get the size.
			stat, err := f.Stat()
			if err != nil {
				return err
			}

			size = stat.Size()
			// Set the reader to the file.
			rd = f
		}

		// Create a zip reader (since .jars are actually just zip files)
		// to parse the jar file.
		zipRd, err := zip.NewReader(rd, size)
		if err != nil {
			return err
		}

		// Define some default variables.
		var vulnClassFound = false
		var secondPatchFound = false
		var thirdPatchFound = false
		var oldPatchFound = false
		var maybeClassFound = ""
		var worstSubStatus Status = StatusOK
		var worstDesc string

		// For each file in the .jar
		for _, file := range zipRd.File {
			// If the path matches the known vulnerable JndiLookup.class path,
			// track that the vulnerable class was found.
			if strings.HasSuffix(file.Name, "log4j/core/lookup/JndiLookup.class") {
				vulnClassFound = true
			}

			// If the path weakly matches the known vulnerable JndiLookup.class path,
			// track that it might have been found. This can potentially happen if
			// people are remapping class paths which can occasionally happen.
			// This could also result in false positives which is why it is
			// tracked as a "maybe".
			if strings.HasSuffix(file.Name, "lookup/JndiLookup.class") {
				maybeClassFound = file.Name
			}

			// JmsAppender is where the patch for Log4Shell is made in
			// the latest versions of Log4j. If we find it, we can extract it
			// and inspect it for the patched code.
			if strings.HasSuffix(file.Name, "JmsAppender$Builder.class") ||
				strings.HasSuffix(file.Name, "JndiManager.class") {
				err := func() error {
					// If for some reason the class file is bigger than 1 MB (it should be less then a few hundred kilobytes),
					// we abort.
					if file.UncompressedSize64 > 1024*1024 {
						return errors.New("JmsAppender is too big??")
					}

					// Open the file inside the jar.
					subRd, err := file.Open()
					if err != nil {
						return err
					}
					defer subRd.Close()

					// Extract it.
					data, err := io.ReadAll(subRd)
					if err != nil {
						return err
					}

					if bytes.Contains(data, []byte("allowedLdapHosts")) &&
						bytes.Contains(data, []byte("allowedJndiProtocols")) &&
						bytes.Contains(data, []byte("allowedLdapClasses")) {
						oldPatchFound = true
					}

					if bytes.Contains(data, []byte("log4j2.enableJndi")) {
						secondPatchFound = true
					}

					// 2.17 adds isJndiEnabled and 2.17.1 adds isJndiJdbcEnabled
					if bytes.Contains(data, []byte("isJndiEnabled")) &&
						!bytes.Contains(data, []byte("isJndiJdbcEnabled")) {
						thirdPatchFound = true
					}

					return nil
				}()
				if err != nil {
					log.Printf("error reading %q: %v", file.Name, err)
				}
			}

			// If there is a jar in the jar, recurse into it.
			if shouldCheck(file.Name) {
				var subStatus Status
				var subDesc string
				// If the jar is larger than 500 MB, this can be dangerous
				// to process as processing jars in jars is done in-memory,
				// so we abort.
				if file.UncompressedSize64 > 500*1024*1024 {
					subStatus = StatusUnknown
					subDesc = fmt.Sprintf("embedded jar file %q is too large (> 500 MB)", file.Name)
				} else {
					err := func() error {
						// Open the jar inside the jar.
						subRd, err := file.Open()
						if err != nil {
							return err
						}

						defer subRd.Close()

						// Extract the jar from the jar.
						buf := bytes.NewBuffer(make([]byte, 0, file.UncompressedSize64))
						_, err = buf.ReadFrom(subRd)
						if err != nil {
							return err
						}

						// And check the jar in the jar recursively.
						subStatus, subDesc = checkJar(pathToFile, bytes.NewReader(buf.Bytes()), int64(buf.Len()), depth+1)
						return nil
					}()
					if err != nil {
						// If an error was encountered, mark the jar's patch status as unknown.
						subStatus = StatusUnknown
						subDesc = fmt.Sprintf("error while checking embedded jar file %q: %v", file.Name, err)
					}
				}

				// We want the worst status of all the jars inside the jars
				// propagated up to the jar file on the filesystem.
				// That way if there are 2 Log4j instances inside the jar, one
				// vulnerable and another one not, we will always mark the jar
				// as vulnerable.
				if subStatus > worstSubStatus {
					worstSubStatus = subStatus
					worstDesc = subDesc
				}
			}
		}

		// Map the results of the scan to a status and description.
		if !vulnClassFound {
			if maybeClassFound != "" {
				status = StatusMaybe
				desc = maybeClassFound
			} else {
				status = StatusOK
				desc = ""
			}
		} else if thirdPatchFound {
			status = StatusThirdOld
			desc = ""
		} else if secondPatchFound && !oldPatchFound {
			status = StatusPatched
			desc = ""
		} else if secondPatchFound {
			status = StatusSecondOld
			desc = ""
		} else if oldPatchFound {
			status = StatusOld
			desc = ""
		} else {
			status = StatusVulnerable
			desc = ""
		}

		if worstSubStatus > status {
			status = worstSubStatus
			desc = worstDesc
		}

		return nil
	}()
	if err != nil {
		status = StatusUnknown
		desc = err.Error()
	}

	return
}

type Status int

const (
	StatusOK = iota
	StatusPatched
	StatusUnknown
	StatusSecondOld
	StatusThirdOld
	StatusOld
	StatusMaybe
	StatusVulnerable
)

// printStatus takes in the path to the file, status and description, and
// prints the result out to stdout.
func printStatus(fileName string, status Status, desc string) {
	printMutex.Lock()
	defer printMutex.Unlock()

	// If we're running in -mode list, we only print likely vulnerable files.
	if *mode == "list" {
		if status == StatusVulnerable || status == StatusOld ||
			status == StatusMaybe || status == StatusSecondOld ||
			status == StatusThirdOld {
			fmt.Println(fileName)
		}

		return
	}

	// Otherwise, pretty print all jars.
	var c *color.Color
	switch status {
	case StatusOK:
		c = color.New(color.FgGreen)
		c.Print("OK      ")
	case StatusPatched:
		c = color.New(color.FgGreen)
		c.Print("PATCHED ")
	case StatusOld:
		c = color.New(color.FgRed)
		c.Print("OLD2.15 ")
	case StatusSecondOld:
		c = color.New(color.FgRed)
		c.Print("OLD2.16 ")
	case StatusThirdOld:
		c = color.New(color.FgRed)
		c.Print("OLD2.17 ")
	case StatusVulnerable:
		c = color.New(color.FgRed)
		c.Print("VULNRBL ")
	case StatusMaybe:
		c = color.New(color.FgRed)
		c.Print("MAYBE   ")
	case StatusUnknown:
		c = color.New(color.FgYellow)
		c.Print("UNKNOWN ")
	}

	fmt.Print(fileName)

	if desc != "" {
		fmt.Print(": " + desc)
	}

	fmt.Println("")
}
