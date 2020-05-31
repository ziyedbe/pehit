# Pehit
This project is part of the forensics class from EURECOM.
[B1] Write a (preferably python) Linux command-line tools to parse, extract, and visualize PE resources.

# Features & help
Pehit is able to extract and parse the PE resources using pefile library.
Those are the supported features :
```
-a : Display all headers (File Header and Optional Header)
-s <header> : Display a specific header
-x <minimal length>: Display strings
-l : List imported DLLs
-f <ddl> : List imported functions in a specific DLL
-c : List sections
-d <section number> : Dump the full content of a section
-e : List exported symbols
-p : Check the packer used
```
# Installation
Pehit uses:
```
- Python3
- pefile
```
