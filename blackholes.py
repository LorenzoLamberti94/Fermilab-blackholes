#!/usr/bin/env python

# LIBRARIES
from elasticsearch import Elasticsearch
from operator import itemgetter
import datetime
import logging
import pprint

logger = logging.getLogger(__name__)


class Blackholes(object):
    def __init__(self, client, weights={}, window=30, scale=0.5):
        self.client = client
        self.weights=weights
        self.window=window
        self.scale=scale

    def get_blackholes(self, end, term_to_search="MachineAttrMachine0", query=None):
        """
        it returns a list with (node,score) and add the scores to the suspicious_nodes_dictionary
        """
        self.start_time_analysis = end - datetime.timedelta(minutes=self.window)
        self.end_time_analysis = end

        # TIME FOR AVERAGE
        self.end_time_average = self.start_time_analysis
        self.start_time_average = self.end_time_average - datetime.timedelta(minutes=self.window / self.scale)
        analysis_dictionary, average_dictionary, global_average = self.get_elasticsearch_data(term_to_search, query)

        # Get suspicious nodes
        suspicious_nodes_dictionary = self.save_suspicious_nodes_global_average(analysis_dictionary, global_average)

        # Calculate Scores and Sort the List
        suspicious_nodes_dictionary = self.calculate_score_suspicious_nodes(suspicious_nodes_dictionary,global_average)

        return suspicious_nodes_dictionary

    def get_elasticsearch_data(self, term_to_search, query):

        # 1: analysis_dictionary is the dictionary of nodes under analysis
        analysis_dictionary = self.get_fifebatch_events(self.start_time_analysis, self.end_time_analysis, 'fifebatch-events-*', term_to_search, query=None)

        # 2: average_dictionary is the dictionary of average features of each node in a previous time interval
        average_dictionary = self.get_fifebatch_events(self.start_time_average, self.end_time_average, 'fifebatch-events-*', term_to_search, query=None)
        # Normalization: multiplies by scaling factor (to compensate the fact that the time window is bigger = much more informations)
        for node, stats in average_dictionary.items():
            stats.update((k, v * self.scale) for k, v in
                         average_dictionary[node].items())  # Scaling factor is for normalization over time
        # Compute global average of nodes values
        global_average = self.calculate_global_average(average_dictionary)

        return analysis_dictionary, average_dictionary, global_average

    def get_fifebatch_events(self,start, end, fife_index, term_to_search, query=None):  ##initialization between brackets
        numebr_of_nodes_analyzed = 1000


        query_events = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "match_all": {}
                        },
                    ],
                    'filter': [{'range': {'@timestamp': {"gte": start, "lte": end}}}],
                    "must_not": []
                }
            },
            "_source": {
                "excludes": []
            },
            "aggs": {
                "node": {
                    "terms": {
                        "field": term_to_search,
                        "size": numebr_of_nodes_analyzed,
                        "order": {
                            "_count": "desc"
                        }
                    },
                    "aggs": {
                        "status": {
                            "filters": {
                                "filters": {

                                    "hold": {
                                        "query_string": {
                                            "query": "MyType:JobHeldEvent",
                                            "analyze_wildcard": True
                                        }
                                    },
                                    "fail": {
                                        "query_string": {
                                            "query": "MyType:JobTerminatedEvent AND NOT ReturnValue:0",
                                            "analyze_wildcard": True
                                        }
                                    },
                                    "success": {
                                        "query_string": {
                                            "query": "MyType:JobTerminatedEvent AND ReturnValue:0",
                                            "analyze_wildcard": True
                                        }
                                    },
                                    "disconnections": {
                                        "query_string": {
                                            "query": "MyType: JobReconnectFailedEvent",
                                            "analyze_wildcard": True
                                        }
                                    },
                                    "manual": {
                                        "query_string": {
                                            "query": "HoldReasonCode: 1",
                                            "analyze_wildcard": True
                                        }
                                    },
                                    "resources": {
                                        "query_string": {
                                            "query": "HoldReasonCode: (34 26)",
                                            "analyze_wildcard": True
                                        }
                                    },
                                    "starter": {
                                        "query_string": {
                                            "query": "HoldReasonCode: 6",
                                            "analyze_wildcard": True
                                        }
                                    },
                                    "others": {
                                        "query_string": {
                                            "query": "MyType:JobHeldEvent AND (NOT HoldReasonCode: (1 6 26 34) )",
                                            "analyze_wildcard": True
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if query is not None:
            query_events['query']['bool']['must'] = {'query_string': {'query': query}}
        r = self.client.search(fife_index, body=query_events)
        #     print (r , '\n\n')
        complete = {}
        for node in r['aggregations']['node']['buckets']:
            # print vo
            complete[node['key']] = {}
            for status, stats in node['status']['buckets'].items():
                complete[node['key']][status] = stats['doc_count']
        # print(complete)
        return complete

    def calculate_global_average(self,dictionary):
        lenght = len(dictionary)
        complete = {}
        for node, status in dictionary.items():
            for bucket, value in status.items():
                complete.setdefault(bucket, 0)  # Adds the new key with default value=0 (if not present)
                complete[bucket] += value

        for bucket, stats in complete.items():
            complete[bucket] = stats/lenght

        return complete

    def save_suspicious_nodes_global_average(self, analysis, average):
        """
        We calculate the average for every single node. use the Global Average just to set a threshold
        """
        result ={}
        for node, stats_analysis in analysis.items():
            for aggr, value_analysis in stats_analysis.items():
                # if (value_analysis > average[aggr]):    # THRESHOLD
                if node not in result:
                    result[node] = {}
                    result[node]['criteria'] = {}
                    result[node]['criteria']['no_successful_jobs'] = float(0)
                    result[node]['score'] = float(0)
                if aggr != 'success' and aggr != 'hold':    ################################ EXCLUDES SUCCESS and HOLD aggregation
                    result[node]['criteria'][aggr] = value_analysis

            if analysis[node]['success']==0:
                result[node]['criteria']['no_successful_jobs'] = float(analysis[node]['hold']+analysis[node]['fail'])

        return result

    def calculate_score_suspicious_nodes(self, suspicious_dict,average):
        for node, stats_analysis in suspicious_dict.items():
            for aggr, value_analysis in stats_analysis['criteria'].items():

                if aggr=='disconnections':
                    # suspicious_dict[node]['criteria'][aggr]=value_analysis/(average[aggr]+1) ############################################################## I INSERTED AN 1 because the average is often Zero
                    suspicious_dict[node]['score'] += self.weights[aggr] * (suspicious_dict[node]['criteria'][aggr]) # Just INCREMENT the score

                if aggr=='fail':
                    suspicious_dict[node]['criteria'][aggr] = value_analysis / (average[aggr] + 1)
                    suspicious_dict[node]['score'] += self.weights[aggr] * suspicious_dict[node]['criteria'][aggr]  # Just INCREMENT the score

                if aggr == 'hold_manual':
                    suspicious_dict[node]['criteria'][aggr] = value_analysis / (average[aggr] + 1)
                    suspicious_dict[node]['score'] += self.weights[aggr] * suspicious_dict[node]['criteria'][aggr]  # Just INCREMENT the score

                if aggr == 'hold_others':
                    suspicious_dict[node]['criteria'][aggr] = value_analysis / (average[aggr] + 1)
                    suspicious_dict[node]['score'] += self.weights[aggr] * suspicious_dict[node]['criteria'][aggr]  # Just INCREMENT the score

                if aggr == 'hold_resources':
                    suspicious_dict[node]['criteria'][aggr] = value_analysis / (average[aggr] + 1)
                    suspicious_dict[node]['score'] += self.weights[aggr] * suspicious_dict[node]['criteria'][aggr]  # Just INCREMENT the score

                if aggr == 'hold_starter':
                    # suspicious_dict[node]['criteria'][aggr] = value_analysis / (average[aggr] + 1)
                    suspicious_dict[node]['score'] += self.weights[aggr] * suspicious_dict[node]['criteria'][aggr]  # Just INCREMENT the score

                if aggr == 'no_successful_jobs':
                    suspicious_dict[node]['score'] += self.weights[aggr] * suspicious_dict[node]['criteria'][aggr]  # Just INCREMENT the score

        return suspicious_dict

def print_suspicious(suspicious_dict, score_threshold=1.0):

    # Creating a list (node,score) just to sort by scores
    suspicious_list = list()
    for node, stats_analysis in suspicious_dict.items():
        if suspicious_dict[node]['score'] > 0:      # If we have a score > 0 we put the node on a separate list
            suspicious_list.append([node, suspicious_dict[node]['score']])

    # Sorting the list by scores
    suspicious_list = sorted(suspicious_list,key=itemgetter(1), reverse=True)  # sorting elements of the list


    # Printing the elements of the dict sorted by scores
    print('\nTop Suspicious Nodes Scores:\n')
    print("%37s\t%10s\t%15s\t%10s\t %10s\t%10s\t%10s\t%10s\t%15s " % ("node:", "score:", "fail", "manual", "resources", "others","starter", "disconn.", "no succ. jobs"))
    for elem in suspicious_list:
        if elem[1]>score_threshold:
            print("%37s\t%10.2f\t%15.2f\t%10.1f\t %10.2f\t%10.2f\t%10.2f\t%10.2f\t%15.2f " %
                  (elem[0],
                   elem[1],
                   suspicious_dict[elem[0]]['criteria']['fail'],
                   suspicious_dict[elem[0]]['criteria']['manual'],
                   suspicious_dict[elem[0]]['criteria']['resources'],
                   suspicious_dict[elem[0]]['criteria']['others'],
                   suspicious_dict[elem[0]]['criteria']['starter'],
                   suspicious_dict[elem[0]]['criteria']['disconnections'],
                   suspicious_dict[elem[0]]['criteria']['no_successful_jobs'])
                  )



def get_options():
    from optparse import OptionParser
    import configparser


    parser = OptionParser(usage="usage: %prog [options] [config file(s)]")
    parser.add_option('-t','--test',action="store_true",
                      help="output data to stdout, don't publish (implies --once)")
    parser.add_option('-1','--once',action="store_true",
                      help="run once and exit")
    parser.add_option('-e','--end',default="now",
                      help="end time for analysis (\"now\" or ISO8601 timestamp)")
    (cmd_opts,args) = parser.parse_args()

    config = configparser.ConfigParser()
    config.read(args)

    opts = {
        'elasticsearch_url': config.get('elasticsearch','url',fallback="localhost:9200"),
        'elasticsearch_timeout_s': config.getint('elasticsearch','timeout',fallback=60),
        'elasticsearch_events_index': config.get('elasticsearch','events_index',fallback='fifebatch-events-*'),
        'weights': {},
        'end': cmd_opts.end,
        'window_m': config.getint('analysis','window_m',fallback=30),
        'scale': config.getfloat('analysis','scale',fallback=0.5),
        'threshold': config.getfloat('analysis','threshold',fallback=1.0),
        'test':              cmd_opts.test or config.getboolean("analysis", "test",fallback=False),
        'once':              cmd_opts.once or config.getboolean("analysis", "once",fallback=False),
    }
    for w in config.items('weights'):
        opts['weights'][w[0]]=float(w[1])

    return opts

def main():
    opts = get_options()

    if opts['test']:
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO
    logging.basicConfig(level=loglevel,
            format="[%(asctime)s] %(levelname)s (%(name)s):  %(message)s")

    logger.info('configuraion: \n'+pprint.pformat(opts))

    es = Elasticsearch(opts['elasticsearch_url'], timeout=opts['elasticsearch_timeout_s'])
    b = Blackholes(client=es, weights=opts['weights'], window=opts['window_m'], scale=opts['scale'])

    if opts['end'] == "now":
        end = datetime.datetime.utcnow()
    else:
        try:
            end = datetime.datetime.fromiso(opts['end'])
        except Exception as e:
            log.fatal(f'error while parsing end time, should conform to ISO8601: {e}')

    print('\n\n ############################################################# BLACKHOLE NODES #############################################################')
    print_suspicious(b.get_blackholes(end), opts['threshold'])

    print('\n\n\n\n\n\n\n ############################################################# BLACKHOLE SITES #############################################################')
    print_suspicious(b.get_blackholes(end, term_to_search="MachineAttrGLIDEIN_Site0", query="NOT MachineAttrGLIDEIN_Site0: FermiGrid"), opts['threshold'])


if __name__=="__main__":
    main()
