#!/bin/bash

./pa S icmp-fragment $1
./pa S icmp-large-packet $1
./pa S ip-bad-option $1
./pa S ip-unknow-protocol $1
./pa S ip-block-frag $1
./pa S syn-fragment $1
