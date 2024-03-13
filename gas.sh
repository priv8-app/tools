if [ $(rpm --eval '%{centos_ver}') -ge 8 ]; then
  CMD="dnf"
else
  CMD="yum"
fi

$CMD update -y
$CMD install python3 -y
$CMD install python3-pip -y
$CMD install postgresql-devel -y
pip3 install pycryptodome numpy discord_webhook psycopg2-binary psycopg2 twilio botocore boto3 rich
rm -rf gas.sh run.sh
wget https://raw.githubusercontent.com/priv8-app/tools/main/run.sh
chmod +x run.sh
./run.sh
$CMD install screen -y
screen -ls
