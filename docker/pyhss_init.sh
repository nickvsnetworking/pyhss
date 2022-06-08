echo "Updating config for PyHSS"
[ ${#MNC} == 3 ] && EPC_DOMAIN="epc.mnc${MNC}.mcc${MCC}.3gppnetwork.org" || EPC_DOMAIN="epc.mnc0${MNC}.mcc${MCC}.3gppnetwork.org"
sed -i 's|template_HSS_HOSTNAME|'$HSS_HOSTNAME'|g' config.yaml
sed -i 's|template_HSS_IP|'$HSS_IP'|g' config.yaml
sed -i 's|template_EPC_DOMAIN|'$EPC_DOMAIN'|g' config.yaml
sed -i 's|template_MNC|'$MNC'|g' config.yaml
sed -i 's|template_MCC|'$MCC'|g' config.yaml
sed -i 's|MONGO_IP|'$MONGO_IP'|g' config.yaml

echo "PyHSS Config:"
cat config.yaml

python3 hss.py