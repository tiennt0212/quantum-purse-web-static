FROM --platform=linux/x86_64 ubuntu:latest

WORKDIR /ckb

# Install required packages
RUN apt-get update && \
  apt-get -y install sudo curl git libc6 && \
  apt-get upgrade -y

# Download and extract CKB binary
RUN curl -O -L https://github.com/nervosnetwork/ckb/releases/download/v0.121.0/ckb_v0.121.0_x86_64-unknown-linux-gnu-portable.tar.gz && \
  tar -xzf ckb_v0.121.0_x86_64-unknown-linux-gnu-portable.tar.gz && \
  mv ckb_v0.121.0_x86_64-unknown-linux-gnu-portable/ckb ckb_v0.121.0_x86_64-unknown-linux-gnu-portable/ckb-cli /usr/local/bin/ && \
  rm -rf ckb_v0.121.0_x86_64-unknown-linux-gnu-portable.tar.gz ckb_v0.121.0_x86_64-unknown-linux-gnu-portable

# Clone the test chain repo and correct port info
RUN git clone https://github.com/tea2x/ckb-dev-chain.git && \
sed -i 's/listen_address = "127.0.0.1:8114"/listen_address = "0.0.0.0:8114"/' /ckb/ckb-dev-chain/ckb.toml

# Change working directory
WORKDIR /ckb/ckb-dev-chain

# Ensure start.sh is executable
RUN chmod +x /ckb/ckb-dev-chain/start.sh

# Expose ports
EXPOSE 8114 8115

# Start the node in the foreground
ENTRYPOINT [ "./start.sh" ]
