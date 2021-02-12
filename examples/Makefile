include ../vars.mk
INC+=-I../inc
LIB+=
LINK+=

EXAMPLES=$(patsubst %.c,bin/%,$(wildcard *.c))

bin:
	mkdir -p bin

bin/%: %.c bin
	$(CC) $(CFLAGS) $(LIB) $(INC) $(LIBS) $< -o $@ $(LINK)

.PHONY: examples clean 
examples: $(EXAMPLES)
	@echo "Built examples"

clean:
	rm -rf bin/


