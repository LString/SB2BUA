echo off
echo "是否真的创建CA证书?前期产生的会被覆盖,用户证书无效??"
pause
echo "是否真的创建CA证书?前期产生的会被覆盖,用户证书无效??"
pause
echo "是否真的创建CA证书?前期产生的会被覆盖,用户证书无效??"
pause
echo "是否真的创建CA证书?前期产生的会被覆盖,用户证书无效??"
pause
echo "是否真的创建CA证书?前期产生的会被覆盖,用户证书无效??"
pause
openssl ecparam -name secp384r1 -genkey -noout -out rootCA.key
openssl req -new -x509 -days 7300 -sha256 -key rootCA.key -out rootCA.crt -subj "/C=CN/ST=Sichuan/L=Chengdu/O=CCS/OU=CCS CA/CN=CCS CA"
pause