# CkptFS

## Prerequisites
- g++-11
```
sudo add-apt-repository ppa:ubuntu-toolchain-r/test
sudo apt update
sudo apt install g++-11
```

- [syscall_intercept](https://github.com/pmem/syscall_intercept)

## Build
```
mkdir -p build
pushd build
cmake -DCMAKE_CXX_COMPILER=/usr/bin/g++-11 .. && make -j
popd
```

## Run
```
./run.sh <command>
```
