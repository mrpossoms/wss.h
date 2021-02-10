# clbp
![C/C++ CI](https://github.com/mrpossoms/clbp/workflows/C/C++%20CI/badge.svg)

C Library Boilerplate is a starting point for C/C++ library projects and includes a functionally minimal makefile, dependency management tooling config, directory structures, automatic code formatting, and unit testing infrastructure.

## Requirements

To best utilize this boilerplate please ensure you have installed the following
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

* `static` - Build project as a static library.
* `shared` - Build project as a shared library .
* `test` - Build and run the test suite
* `format` - Run clang-format explicitly (normally executed as a pre-commit
  hook).
* `docs` - Run Doxygen and build documentation.
* `deps` - Edit depenedency config file
* `deps-update` - Pull the latest versions of all dependencies.
* `clean` - Delete all build artifacts.
