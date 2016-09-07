# PrivCount - Local Deployment Test

This directory contains the necessary components to run a local deployment of PrivCount and to test
its ability to correctly gather statistics using safe test data.

## Prerequisites

You should have followed the main README to setup and install PrivCount. You should have your
PYTHONPATH setup properly so that you can call `privcount` without providing a full paths to it.

## Running the test

### Automated testing

The automated test script runs all the testing steps listed below, terminating all the privcount processes after the tally server produces a results file:

    ./run_test.sh ..

The first argument is the privcount source directory, which is '..' if you're in privcount/test.

It can optionally install the latest version of privcount using 'pip install', and then run the tests:

    ./run_test.sh -I <privcount-directory>

### Manual testing

Start the event server that will supply events to the data collector:

    privcount inject --simulate --port 20003 --log events.txt

Start the PrivCount components:

    privcount ts config.yaml
    privcount sk config.yaml
    privcount dc config.yaml

Now wait until the end of the epoch and check the tally results json file published by the
tally server. The results for the 'SanityCheck' counter should indicate a zero count for the
bin representing counts in the range [0, Infinity).

If you have matplotlib installed, you can then visualize the results:

    privcount plot -d privcount.tallies.*.json test

and open the PDF file that was created.
