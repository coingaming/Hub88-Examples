#!/bin/bash

PRIVATE_KEY='../../priv/private.pem'
PUBLIC_KEY='../../priv/public.pem'
TMP_SIGNATURE='/tmp/request_body_signature'

REQUEST_BODY=`cat`
echo "\nRequest body:\n$REQUEST_BODY"

SIGNATURE=`echo -n "$REQUEST_BODY" | openssl dgst -binary -sha256 -keyform PEM -sign $PRIVATE_KEY | base64`
echo "\nSignature:\n$SIGNATURE"

echo "$SIGNATURE" | base64 --decode > $TMP_SIGNATURE

echo "\nStatus: "
echo -n "$REQUEST_BODY" | openssl dgst -sha256 -keyform PEM -verify $PUBLIC_KEY -signature $TMP_SIGNATURE
