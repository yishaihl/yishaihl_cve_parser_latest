# Start from the latest golang base image
FROM google/cloud-sdk:latest
#ENV GOLANG_SAMPLES_BUCKET dwbi878_yishaihl 
#ENV GOLANG_SAMPLES_PROJECT_ID yishaihl32-gke 
#ENV GOOGLE_APPLICATION_CREDENTIALS /cred/GKE-Cluster-b3f95e8d875b.json
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

RUN go run download_cve.go
RUN go run unzip_file.go
RUN python cve.py jenkins 

# Command to run the executable
CMD ["/bin/bash"]
