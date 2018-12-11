FROM ubuntu:latest
RUN apt-get update
RUN apt-get install -y python3 python3-pip
RUN pip3 install kubernetes
RUN pip3 install PTable
RUN echo "alias kubiscan='python3 /KubiScan/KubiScan.py'" > /root/.bash_aliases
RUN . /root/.bash_aliases
RUN apt-get remove -y python3-pip
COPY . /KubiScan