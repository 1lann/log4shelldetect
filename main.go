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
	"path/filepath"
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/karrick/godirwalk"
)

var printMutex = new(sync.Mutex)

var mode = flag.String("mode", "report", "the output mode, either \"report\" (every jar pretty printed) or \"list\" (list of potentially vulnerable files)")

func main() {
	flag.Parse()

	if flag.Arg(0) == "" {
		fmt.Println("Usage: log4shelldetect [options] <path>")
		fmt.Println("Scans a file or folder recursively for jar files that may be")
		fmt.Println("vulnerable to Log4Shell (CVE-2021-44228) by inspecting")
		fmt.Println("the class paths inside the Jar")
		fmt.Println("")
		fmt.Println("Options:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	target := flag.Arg(0)

	f, err := os.Stat(target)
	if err != nil {
		panic(err)
	}

	if !f.IsDir() {
		checkJar(target, nil, 0, 0)
		return
	}

	pool := make(chan struct{}, 8)

	err = godirwalk.Walk(target, &godirwalk.Options{
		Callback: func(osPathname string, de *godirwalk.Dirent) error {
			if filepath.Ext(osPathname) == ".jar" {
				pool <- struct{}{}
				go func() {
					status, desc := checkJar(osPathname, nil, 0, 0)
					printStatus(osPathname, status, desc)
					<-pool
				}()
			}

			return nil
		},
		ErrorCallback: func(osPathname string, err error) godirwalk.ErrorAction {
			log.Printf("skipping %q: %v", osPathname, err)
			return godirwalk.SkipNode
		},
		Unsorted: true, // (optional) set true for faster yet non-deterministic enumeration (see godoc)
	})
	if err != nil {
		panic(err)
	}

	for i := 0; i < cap(pool); i++ {
		pool <- struct{}{}
	}
}

func checkJar(pathToFile string, rd io.ReaderAt, size int64, depth int) (status Status, desc string) {
	if depth > 100 {
		status = StatusUnknown
		desc = "reached recursion limit of 100 (why do you have so many jars in jars???)"
		return
	}

	err := func() error {
		if rd == nil {
			f, err := os.Open(pathToFile)
			if err != nil {
				return err
			}
			defer f.Close()

			stat, err := f.Stat()
			if err != nil {
				return err
			}

			size = stat.Size()
			rd = f
		}

		zipRd, err := zip.NewReader(rd, size)
		if err != nil {
			return err
		}

		var vulnClassFound = false
		var patchedClassFound = false
		var maybeClassFound = ""
		var worstSubStatus Status = StatusOK
		var worstDesc string

		for _, file := range zipRd.File {
			if strings.HasSuffix(file.Name, "log4j/core/lookup/JndiLookup.class") {
				vulnClassFound = true
			}

			if strings.HasSuffix(file.Name, "lookup/JndiLookup.class") {
				maybeClassFound = file.Name
			}

			if strings.HasSuffix(file.Name, "log4j/core/appender/mom/JmsAppender$Builder.class") {
				err := func() error {
					if file.UncompressedSize64 > 1024*1024 {
						return errors.New("JmsAppender is too big??")
					}

					subRd, err := file.Open()
					if err != nil {
						return err
					}
					defer subRd.Close()

					data, err := io.ReadAll(subRd)
					if err != nil {
						return err
					}

					if bytes.Contains(data, []byte("allowedLdapHosts")) {
						patchedClassFound = true
					}

					return nil
				}()
				if err != nil {
					log.Printf("error reading %q: %v", file.Name, err)
				}
			}

			if path.Ext(file.Name) == ".jar" {
				var subStatus Status
				var subDesc string
				if file.UncompressedSize64 > 500*1024*1024 {
					subStatus = StatusUnknown
					subDesc = fmt.Sprintf("embedded jar file %q is too large (> 500 MB)", file.Name)
				} else {
					err := func() error {
						subRd, err := file.Open()
						if err != nil {
							return err
						}

						defer subRd.Close()

						buf := bytes.NewBuffer(make([]byte, 0, file.UncompressedSize64))
						_, err = buf.ReadFrom(subRd)
						if err != nil {
							return err
						}

						subStatus, subDesc = checkJar(pathToFile, bytes.NewReader(buf.Bytes()), int64(buf.Len()), depth+1)
						return nil
					}()
					if err != nil {
						subStatus = StatusUnknown
						subDesc = fmt.Sprintf("error while checking embedded jar file %q: %v", file.Name, err)
					}
				}

				if subStatus > worstSubStatus {
					worstSubStatus = subStatus
					worstDesc = subDesc
				}
			}
		}

		if !vulnClassFound {
			if maybeClassFound != "" {
				status = StatusMaybe
				desc = maybeClassFound
			} else {
				status = StatusOK
				desc = ""
			}
		} else if patchedClassFound {
			status = StatusPatched
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
	StatusMaybe
	StatusVulnerable
)

func printStatus(fileName string, status Status, desc string) {
	printMutex.Lock()
	defer printMutex.Unlock()

	if *mode == "list" {
		if status == StatusVulnerable || status == StatusMaybe {
			fmt.Println(fileName)
		}

		return
	}

	var c *color.Color
	switch status {
	case StatusOK:
		c = color.New(color.FgGreen)
		c.Print("OK      ")
	case StatusPatched:
		c = color.New(color.FgGreen)
		c.Print("PATCHED ")
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
