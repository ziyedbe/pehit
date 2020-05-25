import sys, getopt
import pefile


def usage():
	print ('test.py -i <inputfile> [-a] [-s Header]')


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
		print("refter to ...") #TODO

def main(argv):
	found_i = False
	found_args = False
	try:
		opts, args = getopt.getopt(argv,"hi:o:as:")
	except getopt.GetoptError:
		usage()
		sys.exit(2)
	for opt, arg in opts:

   	  #-h used for help 
		if opt == '-h':
			found_args = True
			usage()
			sys.exit()

      #-i for the input file
		elif opt in ("-i"):
			found_i = True
			pe = pefile.PE(arg)

		elif opt in ("-a"):
			found_args=True
			print(pe.FILE_HEADER)
			print(pe.OPTIONAL_HEADER)

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