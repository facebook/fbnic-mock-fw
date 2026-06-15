# Quick Start

This mock firmware is designed to be used together with the FBNIC driver QEMU. Visit its [Github repo](https://github.com/facebook/fbnic_qemu) to get started.

### How to run

1. Navigate to this directory with cd and start the mock firmware

```
$ ./mock_fw.py /tmp/fbnic-ctrl-skt
```

2. Continue your steps in the FBNIC driver QEMU repo

### Injecting sensor readings

The mock firmware listens on a Unix socket at `/tmp/fbnic-fw-ctl` for injection
commands. This lets you push firmware-originated events to the driver on demand
while the mock firmware is running and a driver is connected.

Currently the only supported injection is sensor readings. Use
`inject_sensor_value` to set the mock firmware's current temperature (in
milli-degrees Celsius) and/or voltage (in millivolts):

```
$ echo "inject_sensor_value temp 81234 volt 912" | nc -U /tmp/fbnic-fw-ctl
```

The injected readings become the mock firmware's current sensor values. If a
reading is outside the mock firmware's healthy range, a
`SENSOR_THRESHOLD_EXCEEDED` event is also sent to the driver for that sensor.

## License

This project is licensed under the Apache 2.0 License - see the LICENSE file for details.
