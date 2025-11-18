echo off
FOR /L %%i IN (1001,1,1020) DO (
echo "创建%%i用户证书"
openssl ecparam -name secp384r1 -genkey -noout -out %%i.key
openssl req -new -key %%i.key -sha256 -out %%i.csr -subj "/C=CN/ST=Sichuan/L=Chengdu/O=CCS/OU=Unit 1/CN=%%i"
openssl x509 -req -in %%i.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out %%i.crt -days 3650 -sha256
)
echo "用户证书创建完成"
pause