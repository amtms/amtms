# AMTMS

This is the anonymous public code repository of AMTMS probing modules.

AMTMS is an Adaptive Multipath Topology Measurement System, integrating cross-network adaptation module, multipath probing module and topology restoration module, for adaptive, extensive and efficient network topology measurement.

## Enviroment requirements

The probe system is successfully deployed and generally runs under Ubuntu 22.04 and CentOS7.

Before the official deployment, you need to install the relevant dependencies, such as Ubuntu 22.04.

```shell
sudo ufw disable
sudo apt update && sudo apt install cmake g++-11 gcc-11 libpcap-dev traceroute unzip zip gcc g++ net-tools -y
```

Some operating environments may require the firewall and connection tracing to be disabled.

```shell
sudo ufw disable
sudo ip6tables -t raw -A PREROUTING -j NOTRACK
sudo ip6tables -t raw -A OUTPUT -j NOTRACK
sudo iptables -t raw -A PREROUTING -j NOTRACK
sudo iptables -t raw -A OUTPUT -j NOTRACK
```

## Usage

After the dependency is installed, it is compiled in the directory.

```shell
cmake .
make
```

You can run the "sudo ./amtms --help" command to view all operating parameters. (sudo permission required)

```shell
--version          ipv4 or ipv6, default is ipv4
--default          use default method, true or false, default is false
--ip-file          input file path
--prefix-file      input prefix file path
--upper-path       path upperbound, default is 100
--lower-path       path lowerbound, default is 20
--pre-round        preprobe round, default is 3
--pcap-store       store pcap, ture or false, default is true
--band-limit       band limit, a limit for max speed of sending, default is 1500
--process-thread   the number of packet process thread, default is 1
--max-ttl          the number of ttl or hop limit, default is 32
--interface        the name of interface, default is eth0
--block-send       use block model, true or false, default is false
--group-size       group size, default is 2500
--pool-size        pool size for pruning, default is 10
```

Parameters for special interpretation:

- default: If this field is true, the system does not perform the pre-probe phase and only TCP probes are used in the official probe.
- ip-file and prefix-file: If only the ip-file parameter is used, all IP addresses are probed. If both fields are provided, only one active IP is detected under each prefix. The ip-file parameter cannot be nullable, but the prefix-file parameter can be null.
- upper-path: The maximum single-target path for a single probe manually specified.
- pre-round: The number of validation rounds during the pre-probing phase.
- block-send: Whether the local network protocol stack uses blocking mode for packet sending. Blocking probes can cause errors in the calculation of the delay time.
- group-size: The number of targets detected per round.
- pool-size: The size of the pool in which the gain is calculated in the path pruning algorithm.

An example of probing:

```shell
sudo ./amtms --version ipv4 --ip-file ipv4s.txt --prefix-file ipv4-24.txt --upper-path 200 --block-send true
```

