FROM node:22-bullseye

RUN apt-get update && apt-get install -y \
  tmux \
  telnet \
  inetutils-ping \
  net-tools \
  coreutils \
  ncurses-term \
  vim \
  default-jre \
  protobuf-compiler

# Set terminal color support
ENV TERM=xterm-256color
ENV CLICOLOR=1
RUN dircolors -b >> ~/.bashrc
RUN echo "alias l='ls --color=auto'" >> ~/.bashrc
RUN echo "PS1='\\[\\e[1;32m\\]\\u@\\h:\\w\\$ \\[\\e[0m\\]'" >> ~/.bashrc

# install pnpm
RUN npm install --global corepack@latest

# RUN wget -qO- https://get.pnpm.io/install.sh | ENV="$HOME/.bashrc" SHELL="$(which bash)" bash -

# Install Golang
ENV GO_VERSION=1.25.0
RUN wget https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz

ENV GOPATH=/home/node/go
ENV PATH="/usr/local/go/bin:${GOPATH}/bin:${PATH}"

USER node

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
RUN go install golang.org/x/tools/gopls@latest
RUN go install golang.org/x/tools/cmd/goimports@latest
RUN go install github.com/go-delve/delve/cmd/dlv@latest

WORKDIR /workdir

EXPOSE 8080 3000

CMD ["sh", "-c", "trap 'exit 0' INT TERM; while true; do sleep 1; done"]
