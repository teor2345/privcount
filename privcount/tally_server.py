'''
Created on Dec 12, 2015

@author: rob
'''
import os
import json
import logging
import cPickle as pickle

from time import time
from base64 import b64encode

from twisted.internet import reactor, task, ssl
from twisted.internet.protocol import ServerFactory

from protocol import PrivCountServerProtocol
from util import log_error, SecureCounters, generate_keypair, generate_cert

import yaml

# for warning about logging function and format # pylint: disable=W1202
# for calling methods on reactor # pylint: disable=E1101

def log_tally_server_status(status):
    minutes = int((time() - status['time'])/ 60.0)
    logging.info("--server status: PrivCount is {} for {} minutes (since {})".format(status['state'], minutes, status['time']))
    t, r = status['dcs_total'], status['dcs_required']
    a, i = status['dcs_active'], status['dcs_idle']
    logging.info("--server status: DataCollectors: have {}, need {}, {}/{} active, {}/{} idle".format(t, r, a, t, i, t))
    t, r = status['sks_total'], status['sks_required']
    a, i = status['sks_active'], status['sks_idle']
    logging.info("--server status: ShareKeepers: have {}, need {}, {}/{} active, {}/{} idle".format(t, r, a, t, i, t))

class TallyServer(ServerFactory):
    '''
    receive blinded counts from the DCs
    receive key shares from the SKs
    sum shares and counts at end of epoch
    publish the final results to a file
    '''

    def __init__(self, config_filepath):
        self.config_filepath = config_filepath
        self.config = None
        self.clients = {}
        self.collection_phase = None
        self.idle_time = time()
        self.num_completed_collection_phases = 0

    def buildProtocol(self, addr):
        return PrivCountServerProtocol(self)

    def startFactory(self):
        # TODO
        return
        # load any state we may have from a previous run
        state_filepath = self.config['state']
        if os.path.exists(state_filepath):
            with open(state_filepath, 'r') as fin:
                state = pickle.load(fin)
                self.clients = state['clients']
                self.collection_phase = state['collection_phase']
                self.idle_time = state['idle_time']

    def stopFactory(self):
        # TODO
        return
        state_filepath = self.config['state']
        if self.collection_phase is not None or len(self.clients) > 0:
            # export everything that would be needed to survive an app restart
            state = {'clients': self.clients, 'collection_phase': self.collection_phase, 'idle_time': self.idle_time}
            with open(state_filepath, 'w') as fout:
                pickle.dump(state, fout)

    def run(self):
        # load initial config
        self.refresh_config()
        if self.config is None:
            return

        # refresh and check status every minute
        task.LoopingCall(self.refresh_loop).start(60, now=False)

        # setup server for receiving blinded counts from the DC nodes and key shares from the SK nodes
        listen_port = self.config['listen_port']
        key_path = self.config['key']
        cert_path = self.config['cert']
        ssl_context = ssl.DefaultOpenSSLContextFactory(key_path, cert_path)

        logging.info("Tally Server listening on port {}".format(listen_port))
        reactor.listenSSL(listen_port, self, ssl_context)
        reactor.run()

    def refresh_loop(self):
        # make sure we have the latest config and counters
        self.refresh_config()

        # check if any clients have not checked in recently
        self.clear_dead_clients()

        # check if we should start the next collection phase
        if self.collection_phase is None:
            num_phases = self.num_completed_collection_phases
            if num_phases == 0 or self.config['continue']:
                dcs, sks = self.get_idle_dcs(), self.get_idle_sks()
                if len(dcs) >= self.config['dc_threshold'] and len(sks) >= self.config['sk_threshold']:
                    logging.info("starting collection phase {} with {} DataCollectors and {} ShareKeepers".format((num_phases+1), len(dcs), len(sks)))
                    self.start_new_collection_phase(dcs, sks)

        # check if we should stop a running collection phase
        else:
            if self.collection_phase.is_error():
                logging.info("stopping collection phase due to error")
                self.stop_collection_phase()

            elif self.collection_phase.is_expired():
                logging.info("stopping collection phase due to valid expiration")
                self.stop_collection_phase()

        # log the latest status
        log_tally_server_status(self.get_status())
        if self.collection_phase is not None:
            self.collection_phase.log_status()

    def refresh_config(self):
        # re-read config and process any changes
        try:
            logging.debug("reading config file from '%s'", self.config_filepath)

            # read in the config from the given path
            with open(self.config_filepath, 'r') as fin:
                conf = yaml.load(fin)
            ts_conf = conf['tally_server']

            if 'counters' in ts_conf:
                # TODO: refactor to avoid duplicate code
                expanded_path = os.path.expanduser(ts_conf['counters'])
                ts_conf['counters'] = os.path.abspath(expanded_path)
                assert os.path.exists(os.path.dirname(ts_conf['counters']))
                with open(ts_conf['counters'], 'r') as fin:
                    counters_conf = yaml.load(fin)
                ts_conf['counters'] = counters_conf['counters']
            else:
                ts_conf['counters'] = conf['counters']

            # Load the sigma values from the data collector configuration
            # this is a cut-down version of the DC loading script
            dc_conf = conf['data_collector']

            if 'counters' in dc_conf:
                # TODO: refactor to avoid duplicate code
                expanded_path = os.path.expanduser(dc_conf['counters'])
                dc_conf['counters'] = os.path.abspath(expanded_path)
                assert os.path.exists(os.path.dirname(dc_conf['counters']))
                with open(dc_conf['counters'], 'r') as fin:
                    dc_counters_conf = yaml.load(fin)
                ts_conf['sigma'] = dc_counters_conf['counters']

            # Also load the tally server's IP and port
            if 'tally_server_info' in dc_conf:
                ts_conf['tally_server_info'] = dc_conf['tally_server_info']
            else:
                my_info = {}
                # I think it's better to just leave this out
                #my_info['ip'] = 'unknown'
                my_info['port'] = ts_conf['listen_port']
                ts_conf['tally_server_info'] = my_info

            # if key path is not specified, look at default path, or generate a new key
            if 'key' in ts_conf and 'cert' in ts_conf:
                expanded_path = os.path.expanduser(ts_conf['key'])
                ts_conf['key'] = os.path.abspath(expanded_path)
                assert os.path.exists(ts_conf['key'])

                expanded_path = os.path.expanduser(ts_conf['cert'])
                ts_conf['cert'] = os.path.abspath(expanded_path)
                assert os.path.exists(ts_conf['cert'])
            else:
                ts_conf['key'] = 'privcount.rsa_key.pem'
                ts_conf['cert'] = 'privcount.rsa_key.cert'
                if not os.path.exists(ts_conf['key']) or not os.path.exists(ts_conf['cert']):
                    generate_keypair(ts_conf['key'])
                    generate_cert(ts_conf['key'], ts_conf['cert'])

            if 'results' in ts_conf:
                expanded_path = os.path.expanduser(ts_conf['results'])
                ts_conf['results'] = os.path.abspath(expanded_path)
                assert os.path.exists(os.path.dirname(ts_conf['results']))

            expanded_path = os.path.expanduser(ts_conf['state'])
            ts_conf['state'] = os.path.abspath(expanded_path)
            assert os.path.exists(os.path.dirname(ts_conf['state']))

            assert ts_conf['listen_port'] > 0
            assert ts_conf['sk_threshold'] > 0
            assert ts_conf['dc_threshold'] > 0
            assert ts_conf['checkin_period'] > 0
            assert ts_conf['collect_period'] > 0
            assert ts_conf['continue'] == True or ts_conf['continue'] == False
            assert ts_conf['q'] > 0
            # Do we need to sanity check this, or just dump it out?
            # We shouldn't duplicate the sanity check code both here and in the DC
            assert ts_conf['sigma'] is not None

            for key in ts_conf['counters']:
                if 'Histogram' in key:
                    assert 'bins' in ts_conf['counters'][key] and ts_conf['counters'][key]['bins'] is not None

            if self.config == None:
                self.config = ts_conf
                logging.info("using config = %s", str(self.config))
            else:
                changed = False
                for k in ts_conf:
                    if k not in self.config or ts_conf[k] != self.config[k]:
                        logging.info("updated config for key {} from {} to {}".format(k, self.config[k], ts_conf[k]))
                        self.config[k] = ts_conf[k]
                        changed = True
                if not changed:
                    logging.debug('no config changes found')

        except AssertionError:
            logging.warning("problem reading config file: invalid data")
            log_error()
        except KeyError:
            logging.warning("problem reading config file: missing required keys")
            log_error()

    def clear_dead_clients(self):
        now = time()

        for uid in self.clients.keys():
            c_status = self.clients[uid]
            time_since_checkin = now - c_status['alive']

            if time_since_checkin > 2 * self.get_checkin_period():
                logging.warning("last checkin was {} minutes ago for client {}".format(time_since_checkin/60.0, c_status))

            if time_since_checkin > 6 * self.get_checkin_period():
                logging.warning("marking dead client {}".format(c_status))
                c_status['state'] = 'dead'

                if self.collection_phase is not None and self.collection_phase.is_participating(uid):
                    self.collection_phase.lost_client(uid)

                self.clients.pop(uid, None)

    def _get_matching_clients(self, c_type, c_state):
        matching_clients = []
        for uid in self.clients:
            if self.clients[uid]['type'] == c_type and self.clients[uid]['state'] == c_state:
                matching_clients.append(uid)
        return matching_clients

    def get_idle_dcs(self):
        return self._get_matching_clients('DataCollector', 'idle')

    def get_active_dcs(self):
        return self._get_matching_clients('DataCollector', 'active')

    def get_idle_sks(self):
        return self._get_matching_clients('ShareKeeper', 'idle')

    def get_active_sks(self):
        return self._get_matching_clients('ShareKeeper', 'active')

    def count_client_states(self):
        dc_idle = len(self.get_idle_dcs())
        dc_active = len(self.get_active_dcs())
        sk_idle = len(self.get_idle_sks())
        sk_active = len(self.get_active_sks())
        return dc_idle, dc_active, sk_idle, sk_active

    def get_checkin_period(self): # called by protocol
        return self.config['checkin_period']

    def get_status(self): # called by protocol
        dc_idle, dc_active, sk_idle, sk_active = self.count_client_states()

        status = {
            'state' : 'idle' if self.collection_phase is None else 'active',
            'time' : self.idle_time if self.collection_phase is None else self.collection_phase.get_start_ts(),
            'dcs_idle' : dc_idle,
            'dcs_active' : dc_active,
            'dcs_total' : dc_idle+dc_active,
            'dcs_required' : self.config['dc_threshold'],
            'sks_idle' : sk_idle,
            'sks_active' : sk_active,
            'sks_total' : sk_idle+sk_active,
            'sks_required' : self.config['sk_threshold']
        }

        return status

    def set_client_status(self, uid, status): # called by protocol
        for k in status.keys():
            logging.debug("{} sent status: {}: {}".format(uid, k, status[k]))
        if uid in self.clients:
            for k in self.clients[uid].keys():
                logging.debug("{} has stored state: {}: {}".format(uid, k, self.clients[uid][k]))

        oldstate = self.clients[uid]['state'] if uid in self.clients else status['state']
        oldtime = self.clients[uid]['time'] if uid in self.clients else status['alive']

        # only data collectors have a fingerprint
        # oldfingerprint is either:
        #  - the previous fingerprint we had recorded for this client, or
        #  - None
        # fingerprint is either:
        #  - the current fingerprint we've just received in the status, or
        #  - the previous fingerprint we had recorded for this client, or
        #  - None
        # in that order.
        oldfingerprint = self.clients.get(uid, {}).get('fingerprint')
        fingerprint = status.get('fingerprint', oldfingerprint)

        # uidfp includes the fingerprint for data collectors
        if fingerprint is not None:
            uidfp = uid + ' ' + fingerprint
        else:
            uidfp = uid

        # complain if fingerprint changes
        if (fingerprint is not None and oldfingerprint is not None and
            fingerprint != oldfingerprint):
            logging.warning("fingerprint of {} {} state {} changed from {} to {}".format(status['type'], uid, status['state'], oldfingerprint, fingerprint))

        if uid not in self.clients:
            logging.info("new {} {} joined and is {}".format(status['type'], uidfp, status['state']))

        self.clients[uid] = status
        if oldstate == self.clients[uid]['state']:
            self.clients[uid]['time'] = oldtime
        else:
            self.clients[uid]['time'] = status['alive']

        # remember the latest fingerprint for next time, in case the client forgets
        if oldfingerprint is None and fingerprint is not None:
            self.clients[uid]['fingerprint'] = fingerprint

        minutes = int((time() - status['time'])/ 60.0)
        logging.info("----client status: {} {} is alive and {} for {} minutes (since {})".format(status['type'], uidfp, status['state'], minutes, status['time']))

    def get_clock_padding(self, client_uids):
        max_delay = max([self.clients[uid]['rtt']+self.clients[uid]['clock_skew'] for uid in client_uids])
        return max_delay + self.get_checkin_period()

    def start_new_collection_phase(self, dc_uids, sk_uids):
        assert self.collection_phase is None

        clock_padding = self.get_clock_padding(dc_uids + sk_uids)

        sk_public_keys = {}
        for uid in sk_uids:
            sk_public_keys[uid] = self.clients[uid]['public_key']

        # clients don't provide some context until the end of the phase
        # so we'll wait and pass the client context to collection_phase just
        # before stopping it

        self.collection_phase = CollectionPhase(self.config['collect_period'], self.config['counters'], sk_uids, sk_public_keys, dc_uids, self.config['q'], clock_padding, self.config['sigma'], self.config['tally_server_info'])
        self.collection_phase.start()

    def stop_collection_phase(self):
        assert self.collection_phase is not None
        self.collection_phase.set_client_context(self.clients)
        self.collection_phase.stop()
        if self.collection_phase.is_stopped():
            self.num_completed_collection_phases += 1
            dir_path = './' if 'results' not in self.config else self.config['results']
            self.collection_phase.write_results(dir_path)
            self.collection_phase = None
            self.idle_time = time()

    def get_start_config(self, client_uid): # called by protocol
        # return None to indicate we shouldnt start the client yet
        if self.collection_phase is not None:
            return self.collection_phase.get_start_config(client_uid)
        else:
            return None

    def set_start_result(self, client_uid, result_data): # called by protocol
        if self.collection_phase is not None:
            self.collection_phase.store_data(client_uid, result_data)

    def get_stop_config(self, client_uid): # called by protocol
        # returns None to indicate we shouldnt stop the client yet
        if self.collection_phase is not None:
            return self.collection_phase.get_stop_config(client_uid)
        elif client_uid in self.clients and self.clients[client_uid]['state'] == 'active':
            # client is active even though we have no collection phase (could be stale client)
            return {'send_counters' : False}
        else:
            return None

    def set_stop_result(self, client_uid, result_data): # called by protocol
        if self.collection_phase is not None:
            self.collection_phase.store_data(client_uid, result_data)

class CollectionPhase(object):

    def __init__(self, period, counters_config, sk_uids, sk_public_keys, dc_uids, param_q, clock_padding, sigma_config, tally_server_info):
        # store configs
        self.period = period
        self.counters_config = counters_config
        self.sk_uids = sk_uids
        self.sk_public_keys = sk_public_keys
        self.dc_uids = dc_uids
        self.param_q = param_q
        self.clock_padding = clock_padding
        self.sigma_config = sigma_config
        self.tally_server_info = tally_server_info
        self.client_context = None

        # setup some state
        self.state = 'new' # states: new -> starting_dcs -> starting_sks -> started -> stopping -> stopped
        self.starting_ts = None
        self.stopping_ts = None
        self.encrypted_shares = {} # uids of SKs to which we send shares {sk_uid : share_data}
        self.need_shares = set() # uids of DCs from which we still need encrypted shares
        self.final_counts = {} # uids of clients and their final reported counts
        self.need_counts = set() # uids of clients from which we still need final counts
        self.error_flag = False

    def _change_state(self, new_state):
        old_state = self.state
        self.state = new_state
        if old_state != new_state:
            logging.info("collection phase state changed from '{}' to '{}'".format(old_state, new_state))

    def start(self):
        if self.state != "new":
            return

        # we are now starting up
        self.starting_ts = time()

        # we first need to get all encrypted shares from the DCs before we
        # forward them to the SKs
        for uid in self.dc_uids:
            self.need_shares.add(uid)
        self._change_state('starting_dcs')

    def stop(self):
        if self.stopping_ts is None:
            self.stopping_ts = time()

        # main state switch to decide how to stop the phase
        if self.state == 'new':
            self._change_state('stopped')

        elif self.state == 'starting_dcs' or self.state == 'starting_sks':
            self.need_shares.clear()
            self.encrypted_shares.clear()

            # need to tell all clients to stop and reset
            self._change_state('stopping')
            for uid in self.dc_uids+self.sk_uids:
                self.need_counts.add(uid)
            self.error_flag = True # when sending STOP, indicate error so we dont get tallies

        elif self.state == 'started':
            # our noise covers activity independent of the length of the period
            # so we can keep results even if we are ending early
            if self.stopping_ts - self.starting_ts >= self.period:
                logging.info("graceful end to collection phase")
            else:
                logging.info("premature end to collection phase, results may be less accurate than expected due to the noise that was added (if a client is missing, results may be nonsense)")

            for uid in self.dc_uids+self.sk_uids:
                self.need_counts.add(uid)

            # when sending STOP, indicate that we need tallies
            self.error_flag = False
            self._change_state('stopping')

        elif self.state == 'stopping':
            if len(self.need_counts) == 0:
                self._change_state('stopped')

    def lost_client(self, client_uid):
        # this is called when client_uid isnt responding
        # we could mark error_flag as true and abort, or keep counting anyway
        # and hope we can recover from the error by adding the local state
        # files later... TODO
        pass

    def store_data(self, client_uid, data):
        if data == None:
            logging.warning("received error response from {} while in state {}".format(client_uid, self.state))
            return

        if self.state == 'starting_dcs':
            # we expect these to be the encrpyted and blinded counts
            # from the DCs that we should forward to the SKs during SK startup
            assert client_uid in self.dc_uids

            # dont add a share from the same DC twice
            if client_uid in self.need_shares:
                # collect all shares for each SK together
                shares = data # dict of {sk_uid : share}
                for sk_uid in shares:
                    self.encrypted_shares.setdefault(sk_uid, []).append(shares[sk_uid])
                logging.info("received {} shares from data collector {}".format(len(shares), client_uid))

                # mark that we got another one
                self.need_shares.remove(client_uid)
                logging.info("need shares from {} more data collectors".format(len(self.need_shares)))
                if len(self.need_shares) == 0:
                    # ok, we got all of the shares for all SKs, now start the SKs
                    for sk_uid in self.sk_uids:
                        self.need_shares.add(sk_uid)
                    self._change_state('starting_sks')

        elif self.state == 'starting_sks':
            # the sk got our encrypted share successfully
            logging.info("share keeper {} started and received its shares".format(client_uid))
            self.need_shares.remove(client_uid)
            if len(self.need_shares) == 0:
                self._change_state('started')

        elif self.state == 'stopping':
            if client_uid in self.need_counts:
                # the client got our stop command
                counts = data
                logging.info("received {} counts from stopped client {}".format(len(counts), client_uid))

                if not self.is_error() and len(counts) == 0:
                    logging.warning("received empty counts from {}, final results will not be available".format(client_uid))
                    self.error_flag = True
                if not self.is_error():
                    # add up the tallies from the client
                    self.final_counts[client_uid] = data
                self.need_counts.remove(client_uid)

    def is_participating(self, client_uid):
        return True if client_uid in self.sk_uids or client_uid in self.dc_uids else False

    def is_expired(self):
        if self.starting_ts is None:
            return False
        return True if (time() - self.starting_ts) >= self.period else False

    def is_error(self):
        return self.error_flag

    def is_stopped(self):
        return True if self.state == 'stopped' else False

    def get_start_ts(self):
        return self.starting_ts

    def get_start_config(self, client_uid):
        if not self.is_participating(client_uid) or client_uid not in self.need_shares:
            return None

        assert self.state == 'starting_dcs' or self.state == 'starting_sks'
        config = {'q':self.param_q}

        if self.state == 'starting_dcs' and client_uid in self.dc_uids:
            config['sharekeepers'] = {}
            for sk_uid in self.sk_public_keys:
                config['sharekeepers'][sk_uid] = b64encode(self.sk_public_keys[sk_uid])
            config['counters'] = self.counters_config
            config['defer_time'] = self.clock_padding
            logging.info("sending start comand with {} counters and requesting {} shares to data collector {}".format(len(config['counters']), len(config['sharekeepers']), client_uid))

        elif self.state == 'starting_sks' and client_uid in self.sk_uids:
            config['shares'] = self.encrypted_shares[client_uid]
            config['counters'] = self.counters_config
            logging.info("sending start command with {} counters and {} shares to share keeper {}".format(len(config['counters']), len(config['shares']), client_uid))

        return config

    def get_stop_config(self, client_uid):
        if not self.is_participating(client_uid) or client_uid not in self.need_counts:
            return None

        assert self.state == 'stopping'
        config = {'send_counters' : not self.is_error()}
        msg = "without" if self.is_error() else "with"
        logging.info("sending stop command to {} {} request for counters".format(client_uid, msg))
        return config

    # context is a dictionary of dictionaries, indexed by UID, and then by the
    # attribute: name, fingerprint, ...
    def set_client_context(self, context):
        self.client_context = context

    # returns a list of unique types of clients in self.client_context
    def get_client_types(self):
        types = []
        if self.client_context is None:
            return types
        for uid in self.client_context:
            for k in self.client_context[uid].keys():
                if k == 'type' and not self.client_context[uid]['type'] in types:
                    types.append(self.client_context[uid]['type'])
        return types

    # returns a context for each client by UID, grouped by client type
    def get_client_context_by_type(self):
        contexts = {}
        if self.client_context is None:
            return contexts
        for type in self.get_client_types():
            for uid in self.client_context:
                if self.client_context[uid].get('type', 'NoType') == type:
                    # make a copy, so we can delete unnecesary keys
                    contexts.setdefault(type, {})[uid] = self.client_context[uid].copy()
                    # remove the (inner) types, because they're redundant now
                    del contexts[type][uid]['type']
        return contexts

    # the context is written out with the tally results
    def get_result_context(self):
        result_context = {}

        # log the times used for the round
        result_time = {}
        # Do we want to round these times?
        # (That is, use begin and end instead?)
        result_time['Start'] = self.starting_ts
        result_time['Stop'] = self.stopping_ts
        result_time['Period'] = self.period
        result_time['ClockPadding'] = self.clock_padding
        result_context['Time'] = result_time

        # add the values used while counting
        result_count_context = {}
        # the bins are listed in each Tally, so we don't duplicate them here
        #result_count_context['CounterBins'] = self.counters_config
        result_count_context['Q'] = self.param_q
        # The TS reads the data collector config to load the sigma values
        result_count_context['Sigma'] = self.sigma_config
        result_context['Count'] = result_count_context

        # add the context for the clients that participated in the count
        # this includes all status information by default
        # clients are grouped by type, rather than listing them all by UID at
        # the top level of the context
        if self.client_context is not None:
            result_context.update(self.get_client_context_by_type())

        # now remove any context we are sure we don't want
        # currently, that's the share keepers' public keys: they're too long
        for uid in result_context.get('ShareKeeper', {}):
            del result_context['ShareKeeper'][uid]['public_key']

        # add the context for the tally server itself
        result_context['TallyServer'] = self.tally_server_info

        return result_context

    def write_results(self, path_prefix):
        if not self.is_stopped():
            logging.warning("trying to write results before collection phase is stopped")
            return
        if len(self.final_counts) <= 0:
            logging.warning("no tally results to write!")
            return

        tallied_counter = SecureCounters(self.counters_config, self.param_q)
        tally_was_successful = tallied_counter.tally_counters(self.final_counts.values())

        if not tally_was_successful:
            logging.warning("problem tallying counters, did all counters and bins match!?")
            return

        tallied_counts = tallied_counter.detach_counts()

        # For backwards compatibility, write out a "tallies" file
        # This file only has the counts
        begin, end = int(round(self.starting_ts)), int(round(self.stopping_ts))
        filepath = "{}/privcount.tallies.{}-{}.json".format(path_prefix, begin, end)
        with open(filepath, 'a') as fout:
            json.dump(tallied_counts, fout, sort_keys=True, indent=4)

        #logging.info("tally was successful, counts for phase from %d to %d were written to file '%s'", begin, end, filepath)

        # Write out an "outcome" file that adds context to the counts
        # This makes it easier to interpret results later on
        result_info = {}

        # add the existing list of counts as its own item
        result_info['Tally'] = tallied_counts

        # add the context of the outcome as another item
        result_info['Context'] = self.get_result_context()

        filepath = "{}/privcount.outcome.{}-{}.json".format(path_prefix, begin, end)
        with open(filepath, 'a') as fout:
            json.dump(result_info, fout, sort_keys=True, indent=4)

        logging.info("tally was successful, outcome of phase from %d to %d were written to file '%s'", begin, end, filepath)
        self.final_counts = {}

    def log_status(self):
        message = "collection phase is in '{}' state".format(self.state)

        if self.state == 'starting_dcs':
            message += ", waiting to receive shares from {} DCs: {}".format(len(self.need_shares), ','.join([ uid for uid in self.need_shares]))
        elif self.state == 'starting_sks':
            message += ", waiting to send shares to {} SKs: {}".format(len(self.need_shares), ','.join([ uid for uid in self.need_shares]))
        elif self.state == 'started':
            minutes = (time() - self.starting_ts) / 60.0
            message += ", running for {} minutes (since {})".format(minutes, self.starting_ts)
        elif self.state == 'stopping':
            minutes = (time() - self.stopping_ts) / 60.0
            message += ", trying to stop for {} minutes (since {})".format(minutes, self.stopping_ts)
            message += ", waiting to receive counts from {} DCs/SKs: {}".format(len(self.need_counts), ','.join([ uid for uid in self.need_counts]))

        logging.info(message)
