import sys, getopt
import pefile
import peutils

def usage():
	print ('test.py -i <inputfile> [-a] [-s Header]')
	print ('Use -h for help')

def help():
	print("-i <inputfile> : Input File")
	print("-a : Display all headers")
	print("-s <header> : Display a specific header")
	print("-x : Display strings")
	print("-l : Listing imported DLLs")
	print("-f <ddl> : List imported functions in a specific DLL ")
	print("-c : List sections")
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


#Refers to the userdb.txt file to check the packer used by the pe file
def fpacker(pe):

	with open('userdb.txt', 'rt',encoding = "ISO-8859-1") as f: 
		sig_data = f.read()
		signatures = peutils.SignatureDatabase(data=sig_data)
	matches = signatures.match(pe, ep_only = True)
	print(matches)

#Listing imported DLLs
def flibraries(pe):
	print("[*] Listing imported DLLs...")
	for entry in pe.DIRECTORY_ENTRY_IMPORT:
		print('\t' + entry.dll.decode('utf-8'))

#list each imported function in a specific DLL 
def ffunction(pe,arg):
	for entry in pe.DIRECTORY_ENTRY_IMPORT:
		dll_name = entry.dll.decode('utf-8')
		if dll_name == arg:
			print("[*]"+ arg+ " imports:")
			for func in entry.imports:
				print("\t%s at 0x%08x" % (func.name.decode('utf-8'), func.address))


#Listing sections
def fsections(pe):
	for section in pe.sections:
		print(section.Name.decode('utf-8'))
		print("\tVirtual Address: " + hex(section.VirtualAddress))
		print("\tVirtual Size: " + hex(section.Misc_VirtualSize))
		print("\tRaw Size: " + hex(section.SizeOfRawData))

def fexports(pe):
	try:
		for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
			print(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name.decode('utf-8'))
	except AttributeError as err:
		print(format(err))

def main(argv):
	found_i = False
	found_args = False
	try:
		opts, args = getopt.getopt(argv,"hi:o:as:lxf:cep")
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

		elif opt in ("-f"):
			found_args = True
			ffunction(pe,arg)

		elif opt in ("-c"):
			found_args = True
			fsections(pe)
		elif opt in ("-e"):
			found_args = True
			fexports(pe)


		elif opt in ("-p"):
			found_args = True
			fpacker(pe)


	if not found_i:
		print ("-i Please specify an input file")
		usage()
		sys.exit()

	if not found_args:
		usage()
		sys.exit()


if __name__ == "__main__":
   main(sys.argv[1:])