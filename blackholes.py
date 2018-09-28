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
        '''
        :param client   : elasticsearch_url
        :param weights  : dictionary that contains the weights used for the weighted average of the scores
        :param window   : it's the interval of time that it's analyzed (in minutes)
        :param scale    : the "score" parameter sets the interval of time on which we calculate the average of the features. average_time = analysis_time / scale
            example     : if we set a scale of 0.25, the average time will be four times longer than the analysis time
        '''

        self.client = client
        self.weights=weights
        self.window=window
        self.scale=scale

    def get_elasticsearch_data(self, term_to_search, query):
        """
        This function creates the "global average" and two dictionaries:
        - The "analysis_dictionary" collects the data for the analysis
        - The "average_dictionary" collects the data in order to create a reference point

        the average_dictionary needs to be normalized because it takes in account a time interval much bigger compared to the analysis time (look at the "scale" variable)

        :param term_to_search   : The data will be aggregated according to this term. Type "MachineAttrMachine0" to aggregate by nodes, type "MachineAttrGLIDEIN_Site0" to aggregate by Sites
        :param query            : you can pass here a specific query, for example with "MachineAttrMachine0: fnpc17146.fnal.gov" you will get only informations about that specific node

        :var analysis_dictionary : is the dictionary of nodes under analysis. it takes the time interval between (start_time_analysis ; end_time_analysis)
        :var average_dictionary  : is the dictionary of average features of each node. it takes the time interval between (start_time_average ; end_time_average)
        :var global_average      : is a dictionary in which we save the average value for every feature. every average value considers the data from all the nodes

        :return             : the function returns these three dictionaries: analysis_dictionary,average_dictionary, global_average

        """

        # Creation of analysis and average dictionaries
        analysis_dictionary = self.get_fifebatch_events(self.start_time_analysis, self.end_time_analysis, 'fifebatch-events-*', term_to_search, query=None)
        average_dictionary = self.get_fifebatch_events(self.start_time_average, self.end_time_average, 'fifebatch-events-*', term_to_search, query=None)

        # Normalization
        ''' Normalization: it is a for loop that it's needed for the normalization of the data inside the average_dictionary. It uses the "scale" value for normalization
        example:
        if we set a scale of 0.25, the average time will be four times longer than the analysis time and we need to multiply every value of the average dictionary by the scale factor 0.25 '''
        for node, stats in average_dictionary.items():
            stats.update((k, v * self.scale) for k, v in    # Scaling factor is for normalization over time
                         average_dictionary[node].items())
        # Compute global average of nodes values
        global_average = self.calculate_global_average(average_dictionary)

        return analysis_dictionary, average_dictionary, global_average

    def get_fifebatch_events(self,start, end, fife_index, term_to_search, query=None):  #initialization between brackets
        '''
        This function makes a query to elasticsearch server

        :param start          : start time for the query to elasticsearch
        :param end            : end time for the query to elasticsearch
        :param fife_index     : string that provides the index name in which i'm searching the data
        :param term_to_search : The data will be aggregated according to this term. Type "MachineAttrMachine0" to aggregate by nodes, type "MachineAttrGLIDEIN_Site0" to aggregate by Sites
        :param query          : you can pass here a specific query, for example with "MachineAttrMachine0: fnpc17146.fnal.gov" you will get only informations about that specific node

        :var number_of_nodes_analyzed : it's the number of nodes that will be analyzed
        :var query_events : JSON query to the elasticsearch server

        :return complete : returns a dictionary with the full list of nodes and their features
        '''

        number_of_nodes_analyzed = 1000


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
                        "size": number_of_nodes_analyzed,
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

        # Add the query (only if it's specified) to the JSON format
        if query is not None:
            query_events['query']['bool']['must'] = {'query_string': {'query': query}}

        # Get data from the server
        r = self.client.search(fife_index, body=query_events)

        # then save only the informations needed: count of held, failed, successful jobs and disconnetions
        complete = {}
        for node in r['aggregations']['node']['buckets']:
            complete[node['key']] = {}
            for status, stats in node['status']['buckets'].items():
                complete[node['key']][status] = stats['doc_count']

        return complete

    def calculate_global_average(self,dictionary):
        '''
        This function computes the global average.
        We get a dictionary from the input and then:
        - we sum up the values of every node for every feature
        - we divide the sum obtained by the number of the nodes (:var lenght)

        :param dictionary : it's the dictionary over which we calculate the global average
        :return           : we obtain a dictionary that stores the average of every feature computed considering the values from all the nodes. This variable obtained is useful as a pint of reference for the analysis
        '''

        lenght = len(dictionary)
        complete = {}
        for node, status in dictionary.items():
            for bucket, value in status.items():
                complete.setdefault(bucket, 0)  # Adds the new key with default value=0 (if not present)
                complete[bucket] += value

        for bucket, stats in complete.items():
            complete[bucket] = stats/lenght

        return complete

    def create_suspicious_nodes_dictionary(analysis):  # We calculate the average for every single node. use thethreshold just to set a threshold
        '''
        This function takes the dictionary "analysis" of the analysis interval of time and creates a new dictionary that includes some new entries:
        "score" and "no_successful_jobs". it also moves all the features inside the "criteria" entry.
        We still need to compute the scores, so it is still 0.

        :param analysis: it's the dictionary on which we want to work
        :return: a dictionary with all the nodes, scores and criteria for the scores. We still need to compute the scores, so it is still 0
        '''

        result ={}
        for node, stats_analysis in analysis.items():
            for aggr, value_analysis in stats_analysis.items():
                if node not in result:
                    result[node] = {}
                    result[node]['criteria'] = {}
                    result[node]['criteria']['no_successful_jobs'] = float(0)
                    result[node]['score'] = float(0)

                if aggr != 'success' and aggr != 'hold':    # EXCLUDES SUCCESS and HOLD aggregation, thay are not useful for now
                    result[node]['criteria'][aggr] = value_analysis

            if analysis[node]['success']==0:
                result[node]['criteria']['no_successful_jobs'] = float(analysis[node]['hold']+analysis[node]['fail'])

        return result

    def calculate_score_suspicious_nodes(self, suspicious_dict,average):
        '''
        This function computes the score for each node.
        The score is a weighted average and it takes in consideration the average value of the features in a precedent interval of time (global_average)

        score = (count(feature)/global average(feature)) * weight
        NOTE: we don't take in account global_average when we compute the score for "starter" hold reason and for the number of "no_successful_jobs"

        :param suspicious_dict: this is the initialized dictionary of the suspicious nodes, in wich the scores are still 0
        :param average: it's the global_average, it's a reference point of a precedent interval of time (longer than the analysis time, look at the "scale" variable)
        :return: it returns the same dictionary in wich the scores and the reasons of the scores (criteria:features) are updated (features are divided by the global average, the score is computed as a weighted average)
        '''

        for node, stats_analysis in suspicious_dict.items():
            for aggr, value_analysis in stats_analysis['criteria'].items():

                if aggr=='disconnections':
                    # suspicious_dict[node]['criteria'][aggr]=value_analysis/(average[aggr]+1) ############################################################## I INSERTED AN 1 because the average is often Zero
                    suspicious_dict[node]['score'] += self.weights[aggr] * (suspicious_dict[node]['criteria'][aggr]) # Just INCREMENTS the score

                if aggr=='fail':
                    suspicious_dict[node]['criteria'][aggr] = value_analysis / (average[aggr] + 1)
                    suspicious_dict[node]['score'] += self.weights[aggr] * suspicious_dict[node]['criteria'][aggr]  # Just INCREMENTS the score

                if aggr == 'hold_manual':
                    suspicious_dict[node]['criteria'][aggr] = value_analysis / (average[aggr] + 1)
                    suspicious_dict[node]['score'] += self.weights[aggr] * suspicious_dict[node]['criteria'][aggr]  # Just INCREMENTS the score

                if aggr == 'hold_others':
                    suspicious_dict[node]['criteria'][aggr] = value_analysis / (average[aggr] + 1)
                    suspicious_dict[node]['score'] += self.weights[aggr] * suspicious_dict[node]['criteria'][aggr]  # Just INCREMENTS the score

                if aggr == 'hold_resources':
                    suspicious_dict[node]['criteria'][aggr] = value_analysis / (average[aggr] + 1)
                    suspicious_dict[node]['score'] += self.weights[aggr] * suspicious_dict[node]['criteria'][aggr]  # Just INCREMENTS the score

                if aggr == 'hold_starter':
                    # suspicious_dict[node]['criteria'][aggr] = value_analysis / (average[aggr] + 1)    # WE DONT TAKE IN CONSIDERATION THE GLOBAL AVERAGE FOR THIS FEATURE
                    suspicious_dict[node]['score'] += self.weights[aggr] * suspicious_dict[node]['criteria'][aggr]  # Just INCREMENTS the score

                if aggr == 'no_successful_jobs':                                                        # WE DONT TAKE IN CONSIDERATION THE GLOBAL AVERAGE FOR THIS FEATURE
                    suspicious_dict[node]['score'] += self.weights[aggr] * suspicious_dict[node]['criteria'][aggr]  # Just INCREMENTS the score

        return suspicious_dict

    def get_blackholes(self, end, term_to_search="MachineAttrMachine0", query=None):

        '''
        This function sets the interval of time for the analysis and for the average
        Then it gets data from elasticsearch and creates a dictionary with the suspicious nodes
        It returns a dictionary of the suspicious nodes with their scores

        NOTE: Here we set the average_time interval through the "scale" variable (=analysis_time/scale)
        example: if we set a scale of 0.25, the average time will be four times longer than the analysis time

        :param end              : end time for the analysis
        :param term_to_search   : The data will be aggregated according to this term. Type "MachineAttrMachine0" to aggregate by nodes, type "MachineAttrGLIDEIN_Site0" to aggregate by Sites
        :param query            : you can pass here a specific query, for example with "MachineAttrMachine0: fnpc17146.fnal.gov" you will get only informations about that specific node
        :return                 : dictionary of the suspicious nodes with their scores
        '''

        # Set the interval of time for analysis
        self.end_time_analysis = end
        self.start_time_analysis = end - datetime.timedelta(minutes=self.window)

        # Set the interval of time for average
        self.end_time_average = self.start_time_analysis
        self.start_time_average = self.end_time_average - datetime.timedelta(minutes=self.window / self.scale)

        # Get data from elasticsearch
        analysis_dictionary, average_dictionary, global_average = self.get_elasticsearch_data(term_to_search, query)

        # Get suspicious nodes
        suspicious_nodes_dictionary = self.create_suspicious_nodes_dictionary(analysis_dictionary, global_average)

        # Calculate Scores and Sort the List
        suspicious_nodes_dictionary = self.calculate_score_suspicious_nodes(suspicious_nodes_dictionary,global_average)

        return suspicious_nodes_dictionary



def print_suspicious(suspicious_dict, score_threshold=1.0):
    '''
    This function prints the list of suspicious nodes sorted by the score

    :param suspicious_dict: dicionary to print of the suspicious nodes
    :param score_threshold: threshold for the score. default value is 1.0
    '''

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
    import sys

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
            end = datetime.datetime.fromisoformat(opts['end'])
        except Exception as e:
            logger.error(f'error while parsing end time, should conform to ISO8601: {e}')
            sys.exit(1)

    print('\n\n')
    print('############################################################# BLACKHOLE NODES #############################################################')
    print_suspicious(b.get_blackholes(end), opts['threshold'])

    print('\n\n\n\n\n\n\n')
    print('############################################################# BLACKHOLE SITES #############################################################')
    print_suspicious(b.get_blackholes(end, term_to_search="MachineAttrGLIDEIN_Site0", query="NOT MachineAttrGLIDEIN_Site0: FermiGrid"), opts['threshold'])


if __name__=="__main__":
    main()
