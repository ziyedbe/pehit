import sys, getopt
import pefile


def usage():
	print ('test.py -i <inputfile> [-a] [-s Header]')

def help():
	print("-i : Input File")
	print("-a : Display all headers")
	print("-s header : Display a specific header")
	print("------------------------------------")
	print("[File Headers]")
	print(" Machine\n","NumberOfSections\n", "PointerToSymbolTable\n"
		,"NumberOfSymbols\n","SizeOfOptionalHeader\n","Characteristics\n")
	print("------------------------------------")
	print("[Optional Headers]")
	print(" Magic\n","MajorLinkerVersion\n","MinorLinkerVersion\n","SizeOfCode\n","SizeOfInitializedData\n"    
		,"SizeOfUninitializedData\n","AddressOfEntryPoint\n","BaseOfCode\n","BaseOfData\n","ImageBase\n"                 
		,"SectionAlignment\n","FileAlignment\n","MajorOperatingSystemVersion\n","MinorOperatingSystemVersion\n"
		,"MajorImageVersion\n","MinorImageVersion\n","MajorSubsystemVersion\n","MinorSubsystemVersion\n"     
		,"Reserved1\n","SizeOfImage\n","SizeOfHeaders\n","CheckSum\n","Subsystem\n","DllCharacteristics\n"        
		,"SizeOfStackReserve\n","SizeOfStackCommit\n","SizeOfHeapReserve\n","SizeOfHeapCommit\n"          
		,"LoaderFlags\n","NumberOfRvaAndSizes\n")

def display(pe,arg):
	if arg=="TimeDateStamp":
		print("TimeDateStamp : " + str(pe.FILE_HEADER.dump_dict()[arg]['Value'].split('[')[1][:-1]))
	elif arg in ("Machine","NumberOfSections", "PointerToSymbolTable"
		,"NumberOfSymbols","SizeOfOptionalHeader","Characteristics"):
		print(arg+" : 0x%0X" % pe.FILE_HEADER.dump_dict()[arg]['Value'])
	elif arg in ("Magic","MajorLinkerVersion","MinorLinkerVersion","SizeOfCode","SizeOfInitializedData"    
		,"SizeOfUninitializedData","AddressOfEntryPoint","BaseOfCode","BaseOfData","ImageBase"                 
		,"SectionAlignment","FileAlignment","MajorOperatingSystemVersion","MinorOperatingSystemVersion"
		,"MajorImageVersion","MinorImageVersion","MajorSubsystemVersion","MinorSubsystemVersion"     
		,"Reserved1","SizeOfImage","SizeOfHeaders","CheckSum","Subsystem","DllCharacteristics"        
		,"SizeOfStackReserve","SizeOfStackCommit","SizeOfHeapReserve","SizeOfHeapCommit"          
		,"LoaderFlags","NumberOfRvaAndSizes"):
		print(arg+" : 0x%0X" % pe.OPTIONAL_HEADER.dump_dict()[arg]['Value'])
	else:
		print("Please enter a valid argument")
		print("-----------------------------")
		help()

def fstrings(pe,min=4):
	print(pe)

	########TODO########
#	with open(path, errors="ignore") as f:
#		for c in f.read():
#			print(c)
#			if c in string.printable:
#				result += c
#				continue
#			if len(result) >= min:
#				yield result
#			result = ""
#			if len(result) >= min:  # catch result at EOF
#				yield result
#	return result

def flibraries(pe):
	########TODO########
	print(pe.dump_info())

def main(argv):
	found_i = False
	found_args = False
	try:
		opts, args = getopt.getopt(argv,"hi:o:as:lx")
	except getopt.GetoptError:
		usage()
		sys.exit(2)
	for opt, arg in opts:

   	  #-h used for help 
		if opt == '-h':
			found_args = True
			usage()
			help()
			sys.exit()

      #-i for the input file
		elif opt in ("-i"):
			found_i = True
			pe = pefile.PE(arg)
			path= arg

		elif opt in ("-a"):
			found_args=True
			print(pe.FILE_HEADER)
			print(pe.OPTIONAL_HEADER)

		elif opt in ("-l"):
			found_args=True
			flibraries(pe)

		elif opt in ("-x"):
			found_args=True
			fstrings(pe)

		elif opt in ("-s"):
			found_args = True
			display(pe,arg)



	if not found_i:
		print ("-i Please specify an input file")
		usage()
		sys.exit()

	if not found_args:
		usage()
		sys.exit()


if __name__ == "__main__":
   main(sys.argv[1:])