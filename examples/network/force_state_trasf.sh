#!/usr/bin/env bash

KEY_COUNTER=1

# e.g. deploy a 101 b 201
# returns deployment id
deploy() {
  depid=$(CORE_PEER_ADDRESS="172.17.0.$REPLICA_MASTER:7051" peer chaincode deploy -n mycc -p github.com/hyperledger/fabric/examples/chaincode/go/chaincode_example02 -c '{"Function": "init", "args": ["'$1'", "'$2'", "'$3'", "'$4'"]}' 2>&1 | grep -E -o 'name[^ ]*' | awk  -F \" '{ print $2 }')
  sleep 2
  echo "$depid"
}

# e.g. invoke $name a b 100
invoke() {
  CORE_PEER_ADDRESS="172.17.0.$REPLICA_MASTER:7051" peer chaincode invoke -n "$1" -c '{"Function": "invoke", "args": ["'$2'", "'$3'", "'$4'"]}' &> /dev/null
  sleep 2
}

# e.g. newset path
newset() {
  txsetid=$(CORE_PEER_ADDRESS="172.17.0.$REPLICA_MASTER:7051" peer muchain newset -s "$1" -o "key$KEY_COUNTER" 2>&1 | grep -E -o 'txSetID: [^ ]*' | awk  -F " " '{ print $2 }')
  ((KEY_COUNTER++))
  local blocknr=""
  while [[ -z $blocknr ]]
  do
    blocknr=$(CORE_PEER_ADDRESS="172.17.0.$REPLICA_MASTER:7051" peer muchain query-state "$txsetid" 2>&1 | grep Introduced | awk  -F : '{ print $2 }')
    blocknr="$(echo -e "${blocknr}" | sed -e 's/^[[:space:]]*//')"
    sleep 2
  done
  echo "$txsetid|$blocknr"
}

# e.g. query txid var
query() {
  res=$(CORE_PEER_ADDRESS="172.17.0.$REPLICA_MASTER:7051" peer chaincode query -n $1 -c '{"Function": "query", "args": ["'$2'"]}' 2> /dev/null | awk  -F : '{ print $2 }')
  sleep 1
  echo $res
}

# e.g. wait_for_val txid var expected_val
wait_for_val() {
  echo "Waiting for $2 to be $3..."
  aval=""
  while [ "$aval" != "$3" ]
  do
    aval=$(query $1 $2)
  done
  echo "done!"
}

# e.g. mutate txsetid block index
mutate() {
  CORE_PEER_ADDRESS="172.17.0.$REPLICA_MASTER:7051" peer muchain mutate -n "$1" -i "$2" &> /dev/null
  sleep 2
}

firstArg() {
  echo "$1" | awk -F "|" '{print $1}'
}

secondArg() {
  echo "$1" | awk -F "|" '{print $2}'
}

# Actual script
# Address at which all requests will be addressed
REPLICA_MASTER=2
depid=$(deploy a 101 b 201)
echo "Deployed transaction with id:" $depid
wait_for_val $depid a 101
invoke $depid a b 1
wait_for_val $depid a 100
setres=$(newset $1)
txsetid=$(firstArg $setres)
blocknr=$(secondArg $setres)
echo "Issued tx set with id:" $txsetid
echo "At block nr:" $blocknr
wait_for_val $depid a 70
mutate $txsetid 0
wait_for_val $depid a 80
mutate $txsetid 2
wait_for_val $depid a 60
invoke $depid b a 1
wait_for_val $depid a 61
mutate $txsetid 0
wait_for_val $depid a 81
setres=$(newset $2)
depsetid=$(firstArg $setres)
depblocknr=$(secondArg $setres)
echo "Issued tx set with id:" $depsetid
echo "At block nr:" $depblocknr
wait_for_val $depsetid a 1000
invoke $depsetid a b 1100
wait_for_val $depsetid a -100
invoke $depsetid a b 250
wait_for_val $depsetid a -350
mutate $depsetid 1
wait_for_val $depsetid a 750
invoke $depsetid a b 50
wait_for_val $depsetid a 700
docker-compose pause vp2
echo "Start vp3 and then press any key here to continue."
read -n 1 -s
REPLICA_MASTER=5
invoke $depsetid a b 50
echo "Crashed, press any key to stop the execution"
read -n 1 -s
docker-compose unpause vp2
docker-compose stop
