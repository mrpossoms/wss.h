include ../vars.mk
INC+=-I../inc
LIB+=
LINK+=

TESTS=$(patsubst %.c,bin/%,$(wildcard *.c))

bin:
	mkdir -p bin

bin/%: %.c bin
	$(CC) -DWSS_H_TEST=1 $(CFLAGS) $(LIB) $(INC) $(LIBS) $< -o $@ $(LINK)

.PHONY: test clean 
test: $(TESTS)
	@./.test-runner.py

clean:
	rm -rf bin/


