#!/bin/bash
if [ -f "$HOME/.gitconfig.restore" ]; then
    cat $HOME/.gitconfig.restore > $HOME/.gitconfig
    rm $HOME/.gitconfig.restore
fi

HTTP_PROXY=
HTTPS_PROXY=
http_proxy=
https_proxy=
