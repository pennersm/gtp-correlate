#! /usr/bin/python3
#
# General window construct over ES
#
# version: 0.2-15Nov2021
import logging
import sys
import os
import time
import eland as ed
import elasticsearch as es
import pandas as pd
import datetime as dt
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
#import pdb; pdb.set_trace()
#-----------------------------------------------------------------------------------------------
elk_ip_address = '127.0.0.1'
elk_port = '9200'
elk_query_timeout = 30
#es.search = Elasticsearch( timeout= elk_query_timeout )
es = Elasticsearch( request_timeout=30, max_retries=3,retry_on_timeout=True )
#
index_threat="pan-fwlog-threat-*"
index_traffic="pan-fwlog-traffic-*"
index_gtp="pan-fwlog-gtp-*"
index_gtp_x_threat="pan-x-gtp-threat-"
#
#
# now here we set the WINDOW in which we process data:
# first we will check the NEWEST timestamp in the current threat index further down
# then we will set the startpoint of the WINDOW to NEWEST - timebackset
# then we will set the endpoint of the WINDOW to starpoint + timewindow
# then we will read all threats in the window but must limit it to maxthreatstep
# adjust those timers along your threat-per-second rate vs query time
# be smart and avoid rims: make timebackset just a seond longer !
maxthreatstep     = 10000
timestamp         = 'fw_log_time'
timewindow        = 3600
timebackset       = 3601
time2wait         = 5
timezone          = 'None'
elastictimeformat = 'strict_date_optional_time_nanos'
# https://stackoverflow.com/questions/13866926/is-there-a-list-of-pytz-timezones
# https://discuss.elastic.co/t/kibana-timezone/29270/5
timestart         = str(dt.datetime.today().strftime('%Y-%m-%dT%H:%M:%S.%f%z'))
#-----------------------------------------------------------------------------------------------
# NOTE: We need to be able to match different ON/OFF conditions
# not always start AND stop will be logged
# it is also independent for traffic and GTP logs
rcv_gtp_start      = True
rcv_gtp_stop       = True
rcv_gtp_drt        = True
rcv_traffic_start  = False
rcv_traffic_stop   = False

#-----------------------------------------------------------------------------------------------
myname = os.path.basename(__file__)
logfile= myname.rsplit('.',1)[0]+"_"+timestart+'.log'
# debug info warning error critical
#
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logging.captureWarnings(True)
formatter=logging.Formatter('%(asctime)s [%(levelname)s] [%(process)d] [%(name)s] :: %(message)s')
#-
stdout_handler=logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
stdout_handler.setFormatter(formatter)
#
file_handler=logging.FileHandler(logfile)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
#
logger.addHandler(file_handler)
logger.addHandler(stdout_handler)
#
es_logger=logging.getLogger('elasticsearch')
es_logger.setLevel(logging.INFO)
urll_logger=logging.getLogger('urllib3')
urll_logger.setLevel(logging.ERROR)
#
logger=logging.getLogger('main')
#
#if not sys.warnoptions:
#    import warnings
#    warnings.simplefilter("ignore")
#
#-----------------------------------------------------------------------------------------------
logline="starting with internal timestamp "+timestart
logger.info(logline)
#
# 1: set a defined startpoint and initial window in which index entries are selected
# ============================================================================
#
imsis = False
while imsis == False:
    try:
        ed_df_gtpidx = ed.DataFrame(elk_ip_address, index_gtp)
        imsis=True
    except:
        logline="can not access index "+index_gtp+" on IP "+elk_ip_address+"... will wait for Index"
        logger.error(logline)
        sleep(3*time2wait)
    continue

window_start    = ed_df_gtpidx[ timestamp ].max() - dt.timedelta( seconds = timebackset )
window_end      = window_start + dt.timedelta( seconds = timewindow )

# 2: start loop to move window over target index and do something useful inside each window instance
# ===================================================================================================
# daemon section: -----------------------------------------------------------------------------------------------------------------------------
while True:
    logline="searching for imsi-imei pairs from "+window_start.strftime("%Y-%m-%d %H:%M:%S.%s")+" until "+window_end.strftime("%Y-%m-%d %H:%M:%S.%s")
    logger.debug(logline)


#a) start processing here
    try:
        imsi_window = ed_df_gtpidx.es_query(
            { "query":
                { "bool":
                    {"must":
                    [{"range":
                        { timestamp: {"gte": window_start, "format": elastictimeformat,"lte": window_end ,"format": elastictimeformat}}
                     },{"match":
                        {"session_stat": "ON"}}
                    ]}
                }
             }
        )
        imsi_imei_groups = imsi_window.groupby(['imsi','imei']).count()
    except:
        logline="can not run query against index "+index_gtp
        logger.error(logline)
        threats_in_win=0

    import pdb; pdb.set_trace()




#---------------------------------------------------------------------------------------------------------
#e) move the window forward or initiate controlled waiting if we dont have entries right now
    window_start    = window_end
    window_end      = window_start + dt.timedelta( seconds = timewindow )
    now             = dt.datetime.today()
    windowdrift     = str(now - pd.Timestamp(window_start).to_pydatetime())
    logline = "end loop with drift "+windowdrift
    logger.debug(logline)
    if now < window_start:
        logline = "negative drift! waiting for new threats during "+str(12*time2wait)+" seconds"
        logger.info(logline)
        time.sleep(12*time2wait)
        window_start   = now - dt.timedelta( seconds = timebackset )
        window_end     = window_start + dt.timedelta( seconds = timewindow )
        logline = "new window created from:"+window_start.strftime("%Y-%m-%d %H:%M:%S.%s")+" until "+window_end.strftime("%Y-%m-%d %H:%M:%S.%s")

    continue
