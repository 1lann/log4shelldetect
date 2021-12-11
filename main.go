package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"log"
	"os"
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
		checkJar(target)
		return
	}

	pool := make(chan struct{}, 8)

	err = godirwalk.Walk(target, &godirwalk.Options{
		Callback: func(osPathname string, de *godirwalk.Dirent) error {
			if filepath.Ext(osPathname) == ".jar" {
				pool <- struct{}{}
				go func() {
					checkJar(osPathname)
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

func checkJar(pathToFile string) {
	err := func() error {
		rd, err := zip.OpenReader(pathToFile)
		if err != nil {
			return err
		}

		var vulnClassFound = false
		var patchedClassFound = false
		var maybeClassFound = ""

		for _, file := range rd.File {
			if strings.HasSuffix(file.Name, "log4j/core/lookup/JndiLookup.class") {
				vulnClassFound = true
			}

			if strings.HasSuffix(file.Name, "lookup/JndiLookup.class") {
				maybeClassFound = file.Name
			}

			if strings.HasSuffix(file.Name, "log4j/core/lookup/JndiRestrictedLookup.class") {
				patchedClassFound = true
			}
		}

		if !vulnClassFound {
			if maybeClassFound != "" {
				printStatus(pathToFile, StatusMaybe, maybeClassFound)
			} else {
				printStatus(pathToFile, StatusOK, "")
			}
		} else if patchedClassFound {
			printStatus(pathToFile, StatusPatched, "")
		} else {
			printStatus(pathToFile, StatusVulnerable, "")
		}

		return nil
	}()
	if err != nil {
		printStatus(pathToFile, StatusUnknown, err.Error())
		return
	}
}

type Status int

const (
	StatusOK = iota
	StatusVulnerable
	StatusPatched
	StatusMaybe
	StatusUnknown
)

func printStatus(fileName string, status int, desc string) {
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
