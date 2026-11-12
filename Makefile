CC      = cc
CFLAGS  = -Wall -Wextra -O2 -std=gnu11
LDFLAGS =

SRC = src/main.c src/elf_parser.c src/scanner.c src/report.c
OBJ = $(SRC:.c=.o)

bldd: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) bldd bldd_report.*

.PHONY: clean
