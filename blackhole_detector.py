import sys
import logging
import datetime
import json

from elasticsearch import Elasticsearch
import faust

from blackholes import Blackholes

logger = logging.getLogger(__name__)

opts = {
    'elasticsearch_url':  'https://fifemon-es.fnal.gov',
    'elasticsearch_timeout_s': 120,
    'elasticsearch_events_index': 'fifebatch-events-*',
    'weights': {
        'disconnections': 5,
        'fail': 0.1,
        'hold_manual': 0,
        'hold_resources': 5,
        'hold_starter': 100,
        'hold_other': 5,
        'no_successful_jobs': 5,
    },
    'window_m': 30,
    'scale': 0.5,
    'threshold': 100,
}

es = Elasticsearch(opts['elasticsearch_url'], timeout=opts['elasticsearch_timeout_s'])
bh = Blackholes(client=es, weights=opts['weights'], window=opts['window_m'], scale=opts['scale'])


class BlackholeEvent(faust.Record):
    type: str
    name: str
    score: float
    reason: str


app = faust.App('blackholes', broker='kafka://lssrv03,lssrv04,lssrv05')
channel = app.channel(value_type=BlackholeEvent)
#self.topic = app.topic('detected_blackholes'), value_type=BlackholeEvent)


@app.agent(channel)
async def process(stream):
    async for event in stream:
        print(f'Received: {event!r}')


#@app.timer(60)
@app.task
async def detect():
    holes = bh.get_blackholes(datetime.datetime.utcnow())
    for node,stats in holes.items():
        if stats['score']>opts['threshold']:
            m = BlackholeEvent(type='node',
                               name=node,
                               score=stats['score'],
                               reason=json.dumps(stats['criteria']),
            )
            await channel.send(value=m)
        elif stats['score']>1:
            logger.info(f'near blackhole node={node} score={stats["score"]} criteria={stats["criteria"]!r}')


if __name__=="__main__":
    app.main()
