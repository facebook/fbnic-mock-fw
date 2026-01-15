# Quick Start

### How to run

1. Navigate to this directory with cd and start the mock firmware

```
$ ./mock_fw.py /tmp/fbnic-ctrl-skt
```

2. Launch the host QEMU
3. Open another terminal and SSH into host QEMU

```
$ ssh root@127.0.0.1 -p 5555
root@127.0.0.1's password:
```
4. In the terminal from step 3, load the fbnic driver

```
$ cd ~/local/fbnic

$ make LLVM=1 -j

$ insmod ~/local/fbnic/src/fbnic.ko
```
Use ifconfig and ethtool -i enp1s0 to verify that the driver is loaded

## License

This project is licensed under the Apache 2.0 License - see the LICENSE file for details.
