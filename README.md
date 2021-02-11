 # Start vault
 vault server -dev

 # enable kv
 vault secrets enable -path=myapp kv

 # create keystore
 keytool -genseckey -keystore aes-keystore.jck -storetype jceks -storepass mystorepass -keyalg AES -keysize 256 -alias jceksaes -keypass mykeypass

 # encode using base64
 cat aes-keystore.jck | base64 > aes-keystore.jck.base64

 # write encoded base64
 vault write myapp/key64  keyfile=@aes-keystore.jck.base64

 # get base64 encoded file
 vault kv get myapp/key64
