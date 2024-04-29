## Introduction
This is a project for the paper "Efficient Two-server ORAM with Logarithmic Bandwidth and Constant Storage Cost". This project also implements the state-of-the-art [LO13](https://eprint.iacr.org/2011/384.pdf), [GKW18](https://eprint.iacr.org/2018/005.pdf), and [KM19](https://arxiv.org/pdf/1802.05145.pdf).
## Prerequisites
1. Ubuntu 20.04.6 operating system.
2. Python version 3.9.13 installed on your local and server machines.
3. Install the necessary libraries:

    `pip install numpy==1.21.5`

    `pip install pycryptodome==3.19.0`
    
    `pip install pycryptodomex==3.19.0`
## Files
* ``*ORAMClient*.py``: The ORAM core code deployed on the client, which allows the client to adjust the database size, block size, and number of accesses.
* ``*ORAMServer*.py/ORAMServer2*.py``: The ORAM core code deployed on two servers.
* ``client.py``: The TCP protocol deployed on the client, which allows the client to modify the addresses and ports of the two servers they need to connect to.
* ``server.py``: The TCP protocol deployed on the two servers.
* ``*utils.py``: The implementation of some auxiliary functions kept on both the servers and the client, including DPF, read-only PIR, write-only PIR, PRF, etc.
* ``SimOBuildClient.py/SimOBuildServer.py``: Since KM19 requires the oblivious sort to implement its rebuild operations, which consumes massive time, users can first pre-test the cost of rebuild by deploying these two files on the client and a server so that accelerating the experiment.
## Deployments
Users need to deploy two servers and copy the corresponding two files ``*ORAMServer.py`` and ``*ORAMServer2.py`` on each server. The file ``server.py`` and other ``*utils`` files are also needed to be copied in two servers. The files ``*ORAMClient.py``、``client.py``、and ``*utils.py`` need to be preserved locally.
## Test
Before starting the client-side code, ensure that the server-side is already running. For experimental comparisons, users can modify the database size and block size in ``*ORAMClient.py`` to test the results under different databases and block sizes.

