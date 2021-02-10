# wss.h
![C/C++ CI](https://github.com/mrpossoms/clbp/workflows/C/C++%20CI/badge.svg)

wss.h is an unopinionated, single headerfile websocket server library intended to make life easier when incorporating websocket connections into an existing socket server implementation. wss.h provides only helper functions that facilitate the basics such as handshaking, encoding and decoding frames. 

## Requirements

To run tests and generate documentation please ensure you have installed the following
* Python3+
* Pip
* C/C++ toolchain
* GNU make
* doxygen
* clang-format

## Dependencies

Instead of managing dependencies as git submodules. A seperate python program
called [gitman](https://github.com/jacebrowning/gitman) which does an excellent
job managing, updating and even building dependencies. If you have a proper
python3 and pip environment setup then gitman will be installed automatically.


## Useage

The Makefile included at the repository root can be used to do almost
everything you could want to do. This includes fetching, installing and
building dependencies, building documentation and of course the software
itself. Helpful make rules include the following.

* `test` - Build and run the test suite
* `format` - Run clang-format explicitly (normally executed as a pre-commit
  hook).
* `docs` - Run Doxygen and build documentation.
* `deps` - Edit depenedency config file
* `deps-update` - Pull the latest versions of all dependencies.
* `clean` - Delete all build artifacts.
