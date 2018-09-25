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
    'threshold': 1,
}

es = Elasticsearch(opts['elasticsearch_url'], timeout=opts['elasticsearch_timeout_s'])
bh = Blackholes(client=es, weights=opts['weights'], window=opts['window_m'], scale=opts['scale'])


class BlackholeEvent(faust.Record):
    type: str
    name: str
    detected_at: str
    score: float
    reason: str


app = faust.App('blackholes', broker='kafka://lssrv03,lssrv04,lssrv05')
detected_blackholes = app.topic('blackholes_detected', value_type=BlackholeEvent)
known_blackholes = app.Table('known_blackholes', value_type=BlackholeEvent)


@app.agent(detected_blackholes)
async def process(stream):
    async for event in stream:
        known_blackholes[event.name]=event
        #print(f'Received: {event!r}')


@app.timer(300)
async def detect():
    when = datetime.datetime.utcnow()
    holes = bh.get_blackholes(when)
    for node,stats in holes.items():
        if stats['score']>opts['threshold']:
            if node in known_blackholes:
                logger.info(f'existing blackhole node={node} score={stats["score"]:.1f}')
            else:
                logger.info(f'blackhole node={node} score={stats["score"]:.1f} criteria={stats["criteria"]!r}')
                m = BlackholeEvent(type='node',
                                   name=node,
                                   detected_at=when.isoformat(),
                                   score=stats['score'],
                                   reason=json.dumps(stats['criteria']),
                )
                await detected_blackholes.send(value=m)
        elif stats['score']>1:
            logger.info(f'near-blackhole node={node} score={stats["score"]:.1f} criteria={stats["criteria"]!r}')


@app.page('/list/')
async def list_blackholes(web, request):
    return web.text(known_blackholes.as_ansitable())

if __name__=="__main__":
    app.main()
