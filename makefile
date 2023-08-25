CC = gcc
CFLAGS = -W -Wall -g 
LDFLAGS = -lpcap 
SRC = $(wildcard src/*.c)
OBJ = $(patsubst src/%.c,obj/%.o,$(SRC)) 
OBJDIR = ./obj
AOUT = my_tcpdump
INCLUDES = include/*.h

all : $(AOUT)

my_tcpdump : $(OBJ)
	$(CC) $(CFLAGS) -o $(AOUT) $(OBJ) $(LDFLAGS)

$(OBJ): | $(OBJDIR)

$(OBJDIR)/%.o : src/%.c
	@echo $<
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	@rm ./obj/*.o
	@rm $(AOUT)

archive: 
	tar zcvf DIVRIOTIS_Constantin.tar.gz include/* src/* test/* obj/ makefile projet.pdf README.md
