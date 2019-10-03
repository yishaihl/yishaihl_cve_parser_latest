# Start from the latest golang base image
FROM google/cloud-sdk:latest
ENV GOROOT /usr/local/go
ENV GOPATH $HOME/app
ENV PATH $GOPATH/bin:$GOROOT/bin:$PATH
# Set the Current Working Directory inside the container
WORKDIR /app

# Build the Go app
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get install -y python-pip && \
    apt-get install -y software-properties-common && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements.txt

RUN pip install -r requirements.txt

RUN wget https://dl.google.com/go/go1.12.7.linux-amd64.tar.gz && \
    tar -xvf go1.12.7.linux-amd64.tar.gz && \
    rm -rf go1.12.7.linux-amd64.tar.gz

COPY . . 
RUN mv go /usr/local

RUN go get -u cloud.google.com/go/storage

WORKDIR /app/app/CVE


# Command to run the executable
CMD ["/bin/bash"]
