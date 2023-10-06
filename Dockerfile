FROM ubuntu:22.04

RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install golang-go -y && \
    apt-get clean -y

WORKDIR /go/src