#!/bin/bash


export ALL_PROXY="http://127.0.0.1:3129"

export HTTP_PROXY="$ALL_PROXY"
export HTTPS_PROXY="$ALL_PROXY"
export FTP_PROXY="$ALL_PROXY"

export http_proxy="$ALL_PROXY"
export https_proxy="$ALL_PROXY"
export ftp_proxy="$ALL_PROXY"



#curl "https://web.whatsapp.com/"
curl -k "https://jsonplaceholder.typicode.com/posts/1"


