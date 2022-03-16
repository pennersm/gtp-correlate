#! /usr/bin/python3
#
# fetches threats from index and tries to match them to GTP session start logs in other index
# matching to stop logs could be alternative option (e.g. to match GTP and traffic_stop)
# but GTP-log always sends both session start & stop
#
# LEFTTODO
# elastic index is not rotating because it has series properties enabled
# OS tuning, more filesystem cache, faster networking port
# @timestamp has the timestamp from fw not from elastic
# es.search correctly complaining that no authentication to access the ES cluster is used - either fix that or disable warning
# version: 0.3-28Oct2021
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
#-----------------------------------------------------------------------------------------------
elk_ip_address = '127.0.0.1'
elk_port = '9200'
elk_query_timeout = 30
#es.search = Elasticsearch( timeout= elk_query_timeout )
es = Elasticsearch( request_timeout=30, max_retries=3,retry_on_timeout=True )
#
indexpattern="pan-*"
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
# 1: set a defined startpoint and initial window in which threats are selected
# ============================================================================
# NOTE There is still a major fuckup here: ES puts the timestamp back to UTC and hence we need to do some conversion
# to local time well have to find out how to use timezone configued for that
# NOTE also that I have no idea why the @timestamp shows the time FW and not when the log was received by elastic
threats = False
while threats == False:
    try:
        ed_df_threatidx = ed.DataFrame(elk_ip_address, index_threat)
        threats=True
    except:
        logline="can not access index "+index_threat+" on IP "+elk_ip_address+"... will wait for Index"
        logger.error(logline)
        sleep(3*time2wait)
    continue

window_start    = ed_df_threatidx[ timestamp ].max() - dt.timedelta( seconds = timebackset )
window_end      = window_start + dt.timedelta( seconds = timewindow )

# 2: start loop to move window over threat index as it flows and match all threats
# ================================================================================
# daemon section:
while True:
    logline="searching for threats from "+window_start.strftime("%Y-%m-%d %H:%M:%S.%s")+" until "+window_end.strftime("%Y-%m-%d %H:%M:%S.%s")
    logger.debug(logline)
#a) fetch threats in window
    try:
        threat_window   = es.search(index=index_threat,
                body    ={
                    "size": maxthreatstep,
                    "query": { "range":{ timestamp: { "gte": window_start , "lte": window_end, "format": elastictimeformat } }  },
                    "track_total_hits": 'true'
                    }
        )
        threats_in_win=threat_window['hits']['total']['value']
        logline="found "+str(threats_in_win)+" threats in window"
        logger.debug(logline)
    except:
        logline="can not run query against index "+index_threat
        logger.error(logline)
        threats_in_win=0

#b) if any threats in current window then make a pandas frame from it
    if threats_in_win > 0:
        try:
            pdf_threat=pd.DataFrame.from_records( pd.DataFrame.from_dict(threat_window["hits"]["hits"])._source  )
            pdf_threat.rename(columns={'fw_log_time': 'threat_fw_log_time'}, inplace=True)
            threat_window.clear()
        except:
            logline="can not convert eland threat_window into pandas dataframe"
            logger.error(logline)

#c) iterating through threats found above, find here matching keys in the GTP sessions Always look for
#   - closest "ON" before the threat or
#   - closest "OFF" after the threat  (NOT IMPLEMENTED HERE!!! you need session-start-logs)
#   => distance feature querying
# LIMITATIONS OF THIS CODE:
# IF    the same IMSI shoots several threats with the same UE source IP and at the same exact time (ms)
# THEN  the assigning of the APN to the particular threatid will be random among possible entries
# IF    the same IMSI would show up in 2 different FWs at the same time and use the same UE-IP
# THEN  we would not see that this is happening in 2 FWs as below correlation is not FW centric
#       resolve: juyst add a FW serial to the gtpkey but I wonder how you want to dashboard that result
#
# iterate we must - shit:
        dirtygtp = []
        for index, row in pdf_threat.iterrows():
            logline  = "iteration pdf_threat::q!
             "+row["seskey"]+" - "+row["threat_fw_log_time"]
            logger.debug(logline)
            dict_dirtygtp = {}
            one_dirtygtp = es.search(index=index_gtp,
                body ={
                    "size": 1,
                    "query": {
                        "bool": {
                            "filter": [
                                {
                                    "term": { "session_stat": "ON" }
                                    },
                                    {
                                    "terms": { "gtpkey_ue": [ row["gtpkey_src"], row["gtpkey_dst"] ] }
                                    },
                                    {
                                    "range": {
                                        "fw_log_time": {
                                            "lte": row["threat_fw_log_time"], "format": elastictimeformat
                                        }
                                    }
                                }
                            ],
                            "should": {
                                "distance_feature": {
                                    "field": "fw_log_time",
                                    "pivot": "1s",
                                    "origin": row["threat_fw_log_time"]
                                }
                            }
                        }
                    }
                }
            )
            if one_dirtygtp['hits']['total']['value'] == 1:
                dict_dirtygtp.update(one_dirtygtp["hits"]["hits"][0]["_source"])
                dirtygtp.append(dict_dirtygtp)
            elif one_dirtygtp['hits']['total']['value'] == 0:
                logline  = "can not match this to GTP session: threat "+row["seskey"]+" - "+row["threat_fw_log_time"]
                logger.debug(logline)
            else:
                logline = "ambiguous query result - same threat "+row["seskey"]+" - "+row["threat_fw_log_time"]+"is matching multiple ("+str(one_dirtygtp['hits']['total']['value'])+"GTP entries"
                logger.error(logline)
        #---- next -----one_dirtygtp['hits']['total']['value']

        # it can be that no GTP sessions match any one of the threats in the window
        # this situation (dirtygtp==NULL) would create errors in below commands
        if len(dirtygtp) > 0:
            pdf_dirtygtp=pd.DataFrame(dirtygtp)
            pdf_threat.drop(columns=['@timestamp','@version','tags','session_stat'], inplace=True)
            pdf_threat.assign(logtype='DRT_x_GTPON')
            pdf_dirtygtp.drop(columns=['@timestamp','@version','tags','logtype','imsi','imei','vsys','device_name','subkey','serial','devkey'], inplace=True)
            pdf_dirtygtp.rename(columns={'seskey': 'gtp_seskey' }, inplace=True)
            pdf_gtp_x_threat=pd.concat([pdf_threat, pdf_dirtygtp], axis=1)
            pdf_gtp_x_threat.fillna("NULL",inplace=True)
        else:
            logline  = "no GTP sessions at all found for threat window:"+window_start.strftime("%Y-%m-%d %H:%M:%S.%s")+" until "+window_end.strftime("%Y-%m-%d %H:%M:%S.%s")
        # fertig !

#d) write the correlated threats to an own index
        try:
            gtp_x_threat=pdf_gtp_x_threat.to_dict(orient='records')
            current_index_gtp_x_threat=index_gtp_x_threat+dt.datetime.today().strftime("%Y.%m.%d")
            bulk( es, gtp_x_threat, index=current_index_gtp_x_threat, doc_type='_doc', raise_on_error=True)
        except:
            logline  = "Error using bulk for writing to Index "+index_gtp_x_threat
            logger.error(logline)

    else:
            time.sleep(time2wait)

#e) move the window forward or initiate controlled waiting if we dont have threats right now
    window_start    = window_end
    window_end      = window_start + dt.timedelta( seconds = timewindow )
    now             = dt.datetime.today()
    windowdrift     = str(now - pd.Timestamp(window_start).to_pydatetime())
    logline = "end correlation loop with drift "+windowdrift
    logger.debug(logline)
    if now < window_start:
        logline = "negative drift! waiting for new threats during "+str(12*time2wait)+" seconds"
        logger.info(logline)
        time.sleep(12*time2wait)
        window_start   = now - dt.timedelta( seconds = timebackset )
        window_end     = window_start + dt.timedelta( seconds = timewindow )
        logline = "new window created from:"+window_start.strftime("%Y-%m-%d %H:%M:%S.%s")+" until "+window_end.strftime("%Y-%m-%d %H:%M:%S.%s")

    continue
