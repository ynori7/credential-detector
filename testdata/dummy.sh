#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: k8s-switch-context context-name environment"
    echo "You must supply the desired context name (e.g. platform) and the environment"
    echo "For example: k8s-switch-context platform dev"
    exit 1
fi

ROLE=arn:aws:iam::1234:role/stuff-$1-Developers

if [[ -z "${AWS_PASSWORD}" ]]; then
    PASSWORD="123blahblah"
else
    PASSWORD=$AWS_PASSWORD
fi

saml2aws login --force --password="$PASSWORD" --role=$ROLE --skip-prompt

kubectl config use-context $1-$2