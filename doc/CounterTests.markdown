# Testing PrivCount Counters

Each PrivCount counter can be tested by sending data through a test tor
network.

You will need:
* the PrivCount python code,
* a PrivCount-patched Tor binary,
* Chutney, and
* a JSON parser (I like jq, but any JSON parser will do).

The terms used to name each counter are documented in
CounterDefinitions.markdown.

Each line in this file that names a counter starts with '- '. This helps us
check that we have tested all the counters.

## Test Setup

Each set of counter variants has a test with expected results for the least
specific variant. More specific variants can be tested by changing the chutney
bytes, connections, ports, or flavour.

To run a test, use:
    test/run_test.sh -I . -x -s chutney

You can pass the following arguments to run_test.sh:
    -n chutney-flavour
    -o chutney-connections (streams)
    -b chutney-bytes (per stream)
For more advanced options, use the environmental variables in the chutney
README.

To display all the bins for a counter, use:
    jq .Tally.CounterName.bins test/privcount.outcome.latest.json
Where "CounterName" can be replaced by any PrivCount counter name.

More specific jq expressions are used in some tests to retrieve particular
values. Expressions that need shell quoting are in double quotes.

Any specific values listed in the tests are from the chutney basic-min network,
unless otherwise indicated.

### Useful jq Expressions

Extract the lower bound and count out of a histogram:
    jq ".Tally.CounterName.bins|map([.[0,2]])"

## Counter Tests

Every PrvivCount counter has at least one test in this section.
(Checked by test/test_counter_match.sh)

### Validity Check

- ZeroCount: ".Tally.ZeroCount.bins[0][2] == 0"
    The ZeroCount is 0 in all valid outcome files.

### Exit Circuits

- ExitCircuitCount:
    ".Tally.ExitActiveCircuitCount.bins[0][2] +
     .Tally.ExitInactiveCircuitCount.bins[0][2] ==
     .Tally.ExitCircuitCount.bins[0][2]"
    This is the sum of ExitActiveCircuitCount and ExitInactiveCircuitCount.

    There are approximately 3 exit circuits per chutney tor (including
    authorities, relays, and clients). These circuits are created
    pre-emptively, and are only used (made active) if needed. Once a circuit is
    used, there is a short delay before another pre-emptive circuit is created
    to replace it.

- ExitActiveCircuitCount: ".Tally.ExitActiveCircuitCount.bins[0][2] == 1"
    There is 1 active circuit per chutney Tor client. To add more active
    circuits, use a chutney flavour with more clients, or add more clients to
    chutney's basic-min. (chutney can also be modified to create a new
    circuit for each data source connection, by modifying the circuit isolation
    options and user/password sent to the SOCKSPort.)
    For example:
        run_test.sh ... -n basic -p `seq 8000 8007`
    Produces 2 active circuits.
    (Sometimes larger chutney networks don't work with PrivCount due to
    timing issues, see bug #272 for details.)

- ExitInactiveCircuitCount: .Tally.ExitInactiveCircuitCount.bins[0][2] is ~10
    See the note under ExitCircuitCount.

- ExitInteractiveCircuitCount
- ExitOtherPortCircuitCount
- ExitP2PCircuitCount
- ExitWebCircuitCount
    The sum of the port variants is equal to ExitActiveCircuitCount. (Inactive
    circuits are not counted, as they have no Stream and therefore no port.)
    Chutney uses port 4747 by default, which is in the OtherPort range.

- ExitCircuitLifeTime:
    "(.Tally.ExitCircuitLifeTime.bins|map(.[2])|add) ==
      .Tally.ExitCircuitCount.bins[0][2]"
    The sum of all the bins is equal to ExitCircuitCount. Typically, chutney
    runs for less than 2 minutes, so all circuit lifetimes are in the [0, 120)
    bin. To extend circuit lifetimes, change the PrivCount collect_period to
    240 seconds, and run:
        CHUTNEY_STOP_TIME=120 test/run_test.sh ...

- ExitActiveCircuitLifeTime
- ExitInactiveCircuitLifeTime
    The counts for the ExitActiveCircuitCount and ExitInactiveCircuitCount
    variants also match, just like ExitCircuitLifeTime.

### Exit Streams

- ExitStreamCount: ".Tally.ExitStreamCount.bins[0][2] == 1"
    There is 1 stream per chutney Tor client.
    To add more streams, use:
        run_test.sh ... -o 10
    to ask clients to make multiple data source connections, or add more
    clients. (See the notes under ExitActiveCircuitCount.)

- ExitInteractiveStreamCount
- ExitOtherPortStreamCount
- ExitP2PStreamCount
- ExitWebStreamCount
    See the port variant notes under ExitInteractiveCircuitCount.

- ExitStreamLifeTime
    Typically, chutney exit streams take less than a second to complete.
    The counts for ExitStreamLifeTime match ExitStreamCount, just like
    ExitCircuitLifeTime.
    To increase stream lifetime, send more bytes:
        run_test.sh ... -b 100000000
    On my machine, sending 100MB takes about 3 seconds.

- ExitInteractiveStreamLifeTime
- ExitOtherPortStreamLifeTime
- ExitP2PStreamLifeTime
- ExitWebStreamLifeTime
    See the port variant notes under ExitInteractiveCircuitCount.

- ExitCircuitStreamCount
    The counts for ExitCircuitStreamCount match ExitStreamCount, but since
    ExitCircuitStreamCount is a per-circuit stream count histogram, there may
    be some inaccuracy due to bucket sizes.
    Increasing ExitStreamCount also increases ExitCircuitStreamCount.

- ExitCircuitInteractiveStreamCount
- ExitCircuitOtherPortStreamCount
- ExitCircuitP2PStreamCount
- ExitCircuitWebStreamCount
    See the port variant notes under ExitInteractiveCircuitCount.

- ExitCircuitInterStreamCreationTime
    The time in seconds between stream creation requests on the same circuit.
    This is zero when there are zero or one streams on a circuit.
    (There is one fewer InterStreamCreationTime than the number of streams.)
    Chutney creates streams for each exit connection simultaneously, so
    multiple connections will result in 0 InterStreamCreationTimes, even if
    they transmit a large number of bytes.

    To see non-zero InterStreamCreationTimes, add multiple chutney verification
    rounds, and send more data:
        run_test.sh ... -u 3 -b 70000000
    On my machine, sending 3 x 70 MB streams results in an [0,3) second time
    and a [3, 30) second time.
    (See ExitStreamLifeTime for more info about increasing stream times.)

- ExitCircuitInteractiveInterStreamCreationTime
- ExitCircuitOtherPortInterStreamCreationTime
- ExitCircuitP2PInterStreamCreationTime
- ExitCircuitWebInterStreamCreationTime
    The InterStreamCreationTimes are calculated separately using a list of
    stream creation times for each port variant. So the variants will not match
    a subset of the ExitCircuitInterStreamCreationTimes.
    See the port variant notes under ExitInteractiveCircuitCount for more
    details.

### Exit Bytes

- ExitStreamByteCount

- ExitInteractiveStreamByteCount
- ExitOtherPortStreamByteCount
- ExitP2PStreamByteCount
- ExitWebStreamByteCount
    See the port variant notes under ExitInteractiveCircuitCount.

- ExitStreamByteRatio

- ExitInteractiveStreamByteRatio
- ExitOtherPortStreamByteRatio
- ExitP2PStreamByteRatio
- ExitWebStreamByteRatio
    See the port variant notes under ExitInteractiveCircuitCount.

- ExitStreamInboundByteCount

- ExitInteractiveStreamInboundByteCount
- ExitOtherPortStreamInboundByteCount
- ExitP2PStreamInboundByteCount
- ExitWebStreamInboundByteCount
    See the port variant notes under ExitInteractiveCircuitCount.

- ExitStreamOutboundByteCount

- ExitInteractiveStreamOutboundByteCount
- ExitOtherPortStreamOutboundByteCount
- ExitP2PStreamOutboundByteCount
- ExitWebStreamOutboundByteCount
    See the port variant notes under ExitInteractiveCircuitCount.

### Exit Traffic Model

- ExitStreamTrafficModelEmissionCount

- ExitStreamTrafficModelTransitionCount

- ExitStreamTrafficModelLogDelayTime
- ExitStreamTrafficModelSquaredLogDelayTime

### Entry Connections

- EntryConnectionCount

- EntryConnectionLifeTime

### Entry Circuits

- EntryCircuitCount
- EntryActiveCircuitCount
- EntryInactiveCircuitCount

- EntryCircuitCellRatio

- EntryCircuitInboundCellCount

- EntryCircuitOutboundCellCount

### Entry Client IPs

- EntryClientIPCount
- EntryActiveClientIPCount
- EntryClientIPActiveCircuitCount
- EntryInactiveClientIPCount
- EntryClientIPInactiveCircuitCount
