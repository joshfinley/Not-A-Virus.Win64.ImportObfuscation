AS=uasm64                                   # assembler
ASFLAGS=-q -win64 -W1                        # assembler flags
LD=link.exe                                 # linker
LDFLAGS=/ERRORREPORT:PROMPT /INCREMENTAL:NO $\
    /SUBSYSTEM:CONSOLE /NODEFAULTLIB /OPT:NOREF $\
    /OPT:NOICF /ENTRY:start /DYNAMICBASE $\
    /NXCOMPAT /MACHINE:X64 /SAFESEH:NO /NOLOGO     # linker flags
SOURCES=$(wildcard ./*.asm)                 # sources
OBJECTS=$(SOURCES:%.asm=%.obj)              # object files
EXECUTABLE=poc.exe                          # program name

# check version
all: $(SOURCES) $(EXECUTABLE)
    
# assemble program
$(OBJECTS): $(SOURCES)
	@$(AS) $(ASFLAGS) $(SOURCES) 
	@echo asm $<

# create executable
$(EXECUTABLE): $(OBJECTS)
	@$(LD) $(LDFLAGS) $(OBJECTS) 
	@echo link $<
	@rm main.obj

# clean folder
clean:
	rm main.err main.exe
