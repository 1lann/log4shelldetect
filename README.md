# log4shelldetect

Scans a file or folder recursively for Java programs that may be vulnerable to Log4Shell (CVE-2021-44228) by inspecting the class paths inside files.

If you only want possibly vulnerable files to be printed rather than all files, run with `-mode list`.

## Usage

```
Usage: log4shelldetect [options] <path>

Options:
  -include-zip
        include zip files in the scan
  -mode string
        the output mode, either "report" (every jar pretty printed) or "list" (list of potentially vulnerable files) (default "report")
```

## License

Code here is released to the public domain under [unlicense](/LICENSE).

With the exception of `velocity-1.1.9.jar` which is an example vulnerable `.jar` file part of [Velocity](https://github.com/PaperMC/Velocity) which is licensed under GPLv3.
