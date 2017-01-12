#!/bin/bash

set -e
set -u

PRIVCOUNT_ROUNDS=2

# Process arguments
if [ $# -lt 1 -o $# -gt 2 ]; then
  echo "usage: $0 [-I] <privcount-directory>"
  echo "       -I: run 'pip install -I <privcount-directory>' before testing"
  exit 1
elif [ $# -eq 1 ]; then
  PRIVCOUNT_INSTALL=0
  PRIVCOUNT_DIRECTORY="$1"
elif [ $# -eq 2 ]; then
  PRIVCOUNT_INSTALL=1
  PRIVCOUNT_DIRECTORY="$2"
fi

# source the venv if it exists
if [ -f "$PRIVCOUNT_DIRECTORY/venv/bin/activate" ]; then
    echo "Using virtualenv in venv..."
    set +u
    . "$PRIVCOUNT_DIRECTORY/venv/bin/activate"
    set -u
fi

if [ "$PRIVCOUNT_INSTALL" -eq 1 ]; then
  # Install the latest requirements
  # Unfortunately, this doesn't work on my OS X install without sudo
  #echo "Installing requirements from '$PRIVCOUNT_DIRECTORY' ..."
  #pip install -r "$PRIVCOUNT_DIRECTORY/requirements.txt"

  # Install the latest privcount version
  echo "Installing latest version of privcount from '$PRIVCOUNT_DIRECTORY' ..."
  pip install -I "$PRIVCOUNT_DIRECTORY"
fi

cd "$PRIVCOUNT_DIRECTORY/test"

# Run the python-based unit tests
echo "Testing time formatting:"
python test_format_time.py
echo ""

echo "Testing encryption:"
python test_encryption.py
echo ""

echo "Testing random numbers:"
python test_random.py
echo ""

echo "Testing counters:"
python test_counter.py
echo ""

echo "Testing noise:"
# The noise script contains its own main function, which we use as a test
python ../privcount/statistics_noise.py

# Requires a local privcount-patched Tor instance
#python test_tor_ctl_event.py

# Execute this command to produce a numeric unix timestamp in seconds
TIMESTAMP_COMMAND="date +%s"
DATE_COMMAND="date"
# Record how long the tests take to run
"$DATE_COMMAND"
STARTSEC="`$TIMESTAMP_COMMAND`"

# Move aside the old result files
echo "Moving old results files to '$PRIVCOUNT_DIRECTORY/test/old' ..."
mkdir -p old
# Save the commands for re-use during multiple round tests
MOVE_JSON_COMMAND="mv privcount.*.json old/"
MOVE_PDF_COMMAND="mv privcount.*.pdf old/"
MOVE_LOG_COMMAND="mv privcount.*.log old/"
# Clean up before running the test
$MOVE_JSON_COMMAND || true
# If the plot libraries are not installed, this will always fail
$MOVE_PDF_COMMAND 2> /dev/null || true
$MOVE_LOG_COMMAND || true

# Injector commands for re-use
# We can either test --simulate, and get partial data, or get full data
# It's better to get full data
INJECTOR_BASE_CMD="privcount inject --log events.txt"
INJECTOR_PORT_CMD="$INJECTOR_BASE_CMD --port 20003"
INJECTOR_UNIX_CMD="$INJECTOR_BASE_CMD --unix /tmp/privcount-inject"

# Then run the ts, sk, dc, and injector
echo "Launching injector (IP), tally server, share keeper, and data collector..."
privcount ts config.yaml &
privcount sk config.yaml &
privcount dc config.yaml &
$INJECTOR_PORT_CMD &

# Then wait for each job, terminating if any job produces an error
# Ideally, we'd want to use wait, or wait $job, but that only checks one job
# at a time, so continuing processes can cause the script to run forever
echo "Waiting for PrivCount to finish..."
ROUNDS=0
JOB_STATUS=`jobs`
echo "$JOB_STATUS"
while echo "$JOB_STATUS" | grep -q "Running"; do
  # fail if any job has failed
  if echo "$JOB_STATUS" | grep -q "Exit"; then
    # and kill everything
    echo "Error: Privcount process exited with an error..."
    pkill -P $$
    exit 1
  fi
  # succeed if an outcome file is produced
  if [ -f privcount.outcome.*.json ]; then
    if [ $[$ROUNDS+1] -lt $PRIVCOUNT_ROUNDS ]; then
      echo "Moving round $ROUNDS results files to '$PRIVCOUNT_DIRECTORY/test/old' ..."
      $MOVE_JSON_COMMAND || true
      # If the plot libraries are not installed, this will always fail
      $MOVE_PDF_COMMAND 2> /dev/null || true
      ROUNDS=$[$ROUNDS+1]
      echo "Restarting injector (unix path) for round $ROUNDS..."
      $INJECTOR_UNIX_CMD &
    else
      ROUNDS=$[$ROUNDS+1]
      break
    fi
  fi
  sleep 2
  JOB_STATUS=`jobs`
  echo "$JOB_STATUS"
done

# Measure how long the actual tests took
ENDDATE="`$DATE_COMMAND`"
ENDSEC="`$TIMESTAMP_COMMAND`"

# And terminate all the privcount processes
echo "Terminating privcount after $ROUNDS round(s)..."
pkill -P $$

# If an outcome file was produced, keep a link to the latest file
if [ -f privcount.outcome.*.json ]; then
  ln -s privcount.outcome.*.json privcount.outcome.latest.json
else
  echo "Error: No outcome file produced."
  exit 1
fi

# If a tallies file was produced, keep a link to the latest file, and plot it
if [ -f privcount.tallies.*.json ]; then
  ln -s privcount.tallies.*.json privcount.tallies.latest.json
  echo "Plotting results..."
  # plot will fail if the optional dependencies are not installed
  # tolerate this failure, and shut down the privcount processes
  privcount plot -d privcount.tallies.latest.json data || true
else
  echo "Error: No tallies file produced."
  exit 1
fi

# Show the differences between the latest and old latest outcome files
if [ -e privcount.outcome.latest.json -a \
     -e old/privcount.outcome.latest.json ]; then
  # there's no point in comparing the tallies JSON or results PDF
  echo "Comparing latest outcomes file with previous outcomes file..."
  # skip expected differences due to time or network jitter
  # some minor numeric differences are expected due to noise, and due to
  # events falling before or after data collection stops in short runs
  diff --minimal \
      -I "time" -I "[Cc]lock" -I "alive" -I "rtt" -I "Start" -I "Stop" \
      -I "[Dd]elay" -I "Collect" -I "End" -I "peer" \
      old/privcount.outcome.latest.json privcount.outcome.latest.json || true
else
  # Since we need old/latest and latest, it takes two runs to generate the
  # first outcome file comparison
  echo "Warning: Outcomes files could not be compared."
  echo "$0 must be run twice to produce the first comparison."
fi

# Show how long it took
echo "$ENDDATE"
ELAPSEDSEC=$[ $ENDSEC - $STARTSEC ]
echo "Seconds Elapsed: $ELAPSEDSEC for $ROUNDS round(s)"
