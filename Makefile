include vars.mk


TESTS+=$(wildcard tests/*.c*)
SRCS+=$(wildcard src/*.c*)
HDRS+=$(wildcard inc/*.h)


#    ___  _             _     ___              
#   |   \(_)_ _ ___   _| |_  |   \ ___ _ __ ___
#   | |) | | '_(_-<  |_   _| | |) / -_) '_ (_-<
#   |___/|_|_| /__/    |_|   |___/\___| .__/__/
#                                     |_|      
lib/$(TARGET):
	mkdir -p $@

obj/$(TARGET): lib/$(TARGET)
	mkdir -p $@

gitman_sources:
	pip install gitman
	gitman install
	# install the pre-commit hook
	cp .pre-commit .git/hooks

#     ___  _     _        _     ___      _        
#    / _ \| |__ (_)___ __| |_  | _ \_  _| |___ ___
#   | (_) | '_ \| / -_) _|  _| |   / || | / -_|_-<
#    \___/|_.__// \___\__|\__| |_|_\\_,_|_\___/__/
#             |__/                                
obj/$(TARGET)/%.o: src/% obj/$(TARGET) gitman_sources
	$(CC) $(CFLAGS) $(INC) $(LIB) -c $< -o $@ $(LINK)

#    _    _ _                        ___      _
#   | |  (_) |__ _ _ __ _ _ _ _  _  | _ \_  _| |___ ___
#   | |__| | '_ \ '_/ _` | '_| || | |   / || | / -_|_-<
#   |____|_|_.__/_| \__,_|_|  \_, | |_|_\\_,_|_\___/__/
#                             |__/
lib/$(TARGET)/lib$(PROJECT).a: $(SRC_OBJS)
	ar -crs $@ $^

lib/$(TARGET)/lib$(PROJECT).so: $(SRC_OBJS)
	$(CC) -shared -o $@ $^

#    ___ _             _        
#   | _ \ |_  ___ _ _ (_)___ ___
#   |  _/ ' \/ _ \ ' \| / -_|_-<
#   |_| |_||_\___/_||_|_\___/__/
#                               
.PHONEY: docs deps clean libdyn test static format

static: lib/$(TARGET)/lib$(PROJECT).a
	@echo "Built static library"

shared: lib/$(TARGET)/lib$(PROJECT).so
	@echo "Built shared library"

test:
	make -C tests test

format:
	clang-format -i $(SRCS)
	clang-format -i $(HDRS)
	clang-format -i $(TESTS)

docs:
	mkdir -p $@
	doxygen

deps:
	edit .gitman.yaml

deps-update:
	gitman update

clean:
	rm -rf obj lib docs
