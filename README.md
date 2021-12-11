# log4shelldetect

Scans a file or folder recursively for jar files that may be vulnerable to Log4Shell (CVE-2021-44228) by inspecting the class paths inside the jar.

If you only want possibly vulnerable jars to be printed rather than all jars, run with `-mode list`.

## License

Code here is released to the public domain under [unlicense](/LICENSE).

With the exception of `velocity-1.1.9.jar` which is an example vulnerable `.jar` file part of [Velocity](https://github.com/PaperMC/Velocity) which is licensed under GPLv3.
