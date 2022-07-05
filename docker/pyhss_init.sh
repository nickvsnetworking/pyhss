echo "Updating config for PyHSS"
[ ${#MNC} == 3 ] && EPC_DOMAIN="epc.mnc${MNC}.mcc${MCC}.3gppnetwork.org" || EPC_DOMAIN="epc.mnc0${MNC}.mcc${MCC}.3gppnetwork.org"
sed -i 's|template_HSS_HOSTNAME|'$HSS_HOSTNAME'|g' config.yaml
sed -i 's|template_HSS_IP|'$HSS_IP'|g' config.yaml
sed -i 's|template_EPC_DOMAIN|'$EPC_DOMAIN'|g' config.yaml
sed -i 's|template_MNC|'$MNC'|g' config.yaml
sed -i 's|template_MCC|'$MCC'|g' config.yaml
sed -i 's|HSS_DB_TYPE|'$HSS_DB_TYPE'|g' config.yaml
sed -i 's|HSS_DB_SERVER|'$HSS_DB_SERVER'|g' config.yaml
sed -i 's|HSS_DB_USERNAME|'$HSS_DB_USERNAME'|g' config.yaml
sed -i 's|HSS_DB_PASSWORD|'$HSS_DB_PASSWORD'|g' config.yaml
sed -i 's|HSS_DB_DB|'$HSS_DB_DB'|g' config.yaml
sed -i 's|HSS_DB_PORT|'$HSS_DB_PORT'|g' config.yaml
sed -i 's|Test_Subscriber_IMSI|'$Test_Subscriber_IMSI'|g' config.yaml


echo "PyHSS Config:"
cat config.yaml

python3 hss.py