# MS Office DLL Checker

## Status
It currently scans only for the "MSOSVG.dll" in all known paths and reports any found DLL file with a Message Box. It is written in AutoHotkey script. If more dll files should be scanned, one could change the script to "FileAppend", build a report and add the checksums and files to the arrays on top. The respective line is commented out for now. The script can also be altered to build a list checksums. 

## Background
The script has been created as part of a security research on SVG files in MS Office and is meant as a response to may be maliciously altered "MSOSVG.dll" files.
