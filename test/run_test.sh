#!/bin/bash

# If you have privcount installed in a venv, activate it before running
# this script

# Show how long it took
date
STARTSEC="`date +%s`"

# Find the privcount directory based on the name of the script
TESTDIR="`dirname $0`"
PRIVDIR="`dirname $TESTDIR`"
if [ ! -f "$PRIVDIR/setup.py" ]; then
  # or the current directory
  if [ -f "setup.py" ]; then
    PRIVDIR="."
  elif [ -f "../setup.py" ]; then
    PRIVDIR=".."
  else
    unset PRIVDIR
    echo "Couldn't find privcount directory."
    exit 1
  fi
fi

# Install the latest privcount version
echo "Installing latest version of privcount from '$PRIVDIR' ..."
pip install -I "$PRIVDIR"

cd "$PRIVDIR/test"

# Move aside the old result files
echo "Moving old results files to '$PRIVDIR/test/old' ..."
mkdir -p old
mv privcount.* old/

# Then run the injector, ts, sk, and dc
echo "Launching injector, tally server, share keeper, and data collector..."
privcount inject --port 20003 --log events.txt --simulate &
privcount ts config.yaml &
privcount sk config.yaml &
privcount dc config.yaml &

# Then wait until they produce a results file
echo "Waiting for results..."
while [ ! -f privcount.outcome.*.json ]; do
  sleep 1
done

# Plot the tallies file
echo "Plotting results..."
privcount plot -d privcount.tallies.*.json test

# And terminate all the privcount processes
echo "Terminating privcount..."
pkill -P $$

# Show how long it took
date
ENDSEC="`date +%s`"
ELAPSEDSEC=$[ $ENDSEC - $STARTSEC ]
echo "Seconds Elapsed: $ELAPSEDSEC"
