#! /bin/sh


APP_VERSION=$1 #passed from analysis template at verification time. 
PASS_OR_FAIL=${2:-pass}
echo "Running very comprehensive test suite"
echo "App Version: $APP_VERSION"
for i in $(seq 1 5); do 
  echo "Verification Step $i of 6"
  sleep 1; echo -e "\tPASS"
done
echo "Verification Step 6 of 6"
sleep 1
[[ "$PASS_OR_FAIL" == "pass" ]] && echo -e "\tPASS" || { echo -e "\tFAIL";exit 1; }
#only runs if not exited
echo "All Tests Passed Successfully!"