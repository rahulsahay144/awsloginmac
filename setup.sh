#!/bin/bash

echo Login to AWS...
./awsloginmac 

touch $HOME/.gitconfig.restore
cat ~/.gitconfig > ~/.gitconfig.restore

HOST=proxy
PORT=8080
USER=$(whoami)

echo -n "Password: "
stty -echo
read password
stty echo

git config --global credential.helper '!aws codecommit credential-helper --profile saml $@'
git config --global credential.UseHttpPath true

git config --global http.proxy http://${USER}:${password}@${HOST}:${PORT}
git config --global http.proxyAuthMethod 'basic'

if security delete-internet-password -l git-codecommit.us-east-1.amazonaws.com &> /dev/null; then
    echo "git-codecommit.us-east-1.amazonaws.com password reset"
fi

export HTTP_PROXY=http://${USER}:${password}@${HOST}:${PORT}
export HTTPS_PROXY=http://${USER}:${password}@${HOST}:${PORT}
export http_proxy=http://${USER}:${password}@${HOST}:${PORT}
export https_proxy=http://${USER}:${password}@${HOST}:${PORT}

