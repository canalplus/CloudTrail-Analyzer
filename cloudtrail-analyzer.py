#!/usr/bin/env python
# -*- coding: utf-8 -*-


import logging.config
import os, time, hashlib
import json, sqlite3, gzip


logging.config.fileConfig(os.path.join(os.path.dirname(__file__), 'logging.conf'))
logger = logging.getLogger('logger_app_debug')


# Global var
max_relaunch_in_hour = 4 # the max relaunch of a subprocess before stop with error
# the correspondance DB Columns and CloudTrail elements
dict_val = {
    'eventid': 'eventID',
    'time': 'eventTime',
    'region': 'awsRegion',
    'name': 'eventName',
    'type': 'eventType',
    'sourceip': 'sourceIPAddress',
    'event_source': 'eventSource',
    'invocker': 'userIdentity',
    'user_agent': 'userAgent',
    'accountid_dest': 'recipientAccountId'
}

###########    DB FUNCTIONS    ###########

def creat_db(db_logfiles_name = "logfiles_list.db"):
    '''
    Create the database for analyse CloudTraillog Files

    :param db_logfiles_name: the name of the SQLite DB file
    :type db_logfiles_name: basestring
    :return:
    '''

    connect = sqlite3.connect(db_logfiles_name)
    curs = connect.cursor()

    #### creation of the table if not exist ###
    # Sqlite connection and cursor
    # If not exist, create Volumes table
    curs.execute("CREATE TABLE IF NOT EXISTS AWS_EVENTS "
                 "(eventid TEXT PRIMARY KEY,"
                 "time TEXT,"
                 "region TEXT,"
                 "name TEXT,"
                 "type TEXT,"
                 "sourceip TEXT,"
                 "event_source TEXT,"
                 "invocker TEXT,"
                 "user_agent TEXT,"
                 "accountid_dest TEXT"
                 ");")
    connect.close()


def parsejson_logs(file_content, db_logfiles_name = "logfiles_list.db"):
    '''
    Parse the CloudTrail log file and record data in a sqlite file

    :param file_content: the contetn of a CloudTrail log file
    :type file_content: basestring
    :param db_logfiles_name: the name of the SQLite DB file
    :type db_logfiles_name: basestring
    :return:
    '''

    logger.debug("Connection to the SQLite DB")
    connect = sqlite3.connect(db_logfiles_name)
    curs = connect.cursor()


    logger.info("Let's save events infos of in the SQLite DB")
    # if ifs a new event
    begin_sql_insert_event = "INSERT INTO AWS_EVENTS (eventid"
    # if it's a previous event (normally not, but if an event appears twice or it we read the same file several times)
    begin_sql_update_event = "UPDATE AWS_EVENTS SET "

    json_data = json.loads(file_content)
    # logger.debug(json_data)
    for anevent in json_data['Records']:
        col_sql_insert_event = begin_sql_insert_event
        val_sql_insert_event = "("
        val_sql_insert_event += "'" + anevent['eventID'] + "'"

        end_sql_update_event = " WHERE eventid = '%s';" % anevent['eventID']
        query_sql_update_event = ""

        logger.debug("Read the event %s" % anevent['eventID'])
        logger.debug("Raw the event %s" % anevent)
        for row, jskey in dict_val.items():

            if row == 'invocker' and jskey in anevent:

                if anevent['userIdentity']['type'] == 'AWSService':
                    theinvocker = anevent['userIdentity']['invokedBy']
                elif anevent['userIdentity']['type'] == 'IAMUser' or anevent['userIdentity']['type'] == 'AssumedRole':
                    theinvocker = anevent['userIdentity']['arn']
                elif  anevent['userIdentity']['type'] == 'AWSAccount':
                    theinvocker = anevent['userIdentity']['accountId']
                else:
                    raise Exception()


                col_sql_insert_event += ", " + row
                val_sql_insert_event += ", '" + theinvocker + "'"
                query_sql_update_event += row + " = " + "'" + theinvocker + "',"
                # if 'accessKeyId' in anevent['userIdentity']:
                #     col_sql_insert_event += ", " + row
                #     val_sql_insert_event += ", '" + anevent['userIdentity']['accessKeyId'] + "'"
                #     query_sql_update_event += row + " = " + "'" + anevent['userIdentity']['accessKeyId'] + "',"
                # elif 'invokedBy' in anevent['userIdentity']:
                #     col_sql_insert_event += ", " + row
                #     val_sql_insert_event += ", '" + anevent['userIdentity']['invokedBy'] + "'"
                #     query_sql_update_event += row + " = " + "'" + anevent['userIdentity']['invokedBy'] + "',"
                # else:
                #     logger.error("%s not in %s" % (jskey, anevent['eventID']))
                #     col_sql_insert_event += ", " + row
                #     val_sql_insert_event += ", 'none'"
                #     query_sql_update_event += row + " = " + "'none',"
            elif jskey in anevent and row != 'eventid':
                col_sql_insert_event += ", " + row
                val_sql_insert_event += ", '" + anevent[jskey] + "'"
                query_sql_update_event += row + " = '" + anevent[jskey] + "',"
            elif jskey not in anevent:
                logger.error("%s not in %s" % (jskey, anevent['eventID']))
                col_sql_insert_event += ", " + row
                val_sql_insert_event += ", 'none'"
                query_sql_update_event += row + " = " + "'none',"
            elif row == 'eventid':
                pass #already set
            else: # just in case
                logger.error("unexpected test fail at %s:%s" % (row, jskey))
        #remove the last , of the update request
        query_sql_update_event = query_sql_update_event[:-1]
        #close the list of columns of insert request
        col_sql_insert_event += ") values "
        #close the list of values of insert request
        val_sql_insert_event += ");"
        logger.debug("The Insert request for %s : %s" % (anevent['eventID'], col_sql_insert_event+val_sql_insert_event))
        logger.debug("The Update request for %s : %s" % (anevent['eventID'], begin_sql_update_event+query_sql_update_event+end_sql_update_event))
        try:
            curs.execute(col_sql_insert_event+val_sql_insert_event)
            connect.commit()
        except sqlite3.IntegrityError as e: # Insert into fail
            curs.execute(begin_sql_update_event+query_sql_update_event+end_sql_update_event)
            connect.commit()

    connect.close()


def process_acloudtrailfile(filename, db_logfiles_name = "logfiles_list.db"):
    '''
    Process a CloudTrail file

    :param filename: the filename
    :type filename: basestring
    :param db_logfiles_name: the name of the SQLite DB file
    :type db_logfiles_name: basestring
    :return:
    '''
    # 0/ clean the name of the file
    short_name = filename.split('/')[len(filename.split('/'))-1]
    logger.info("Process file %s" % short_name)

    # 1/ unzip it
    if short_name.split('.')[len(filename.split('.'))-1] == 'gz':
        logger.debug("Ungzip %s" % short_name)

        f = gzip.open(filename, 'rb')
        parsejson_logs(file_content=f.read(),db_logfiles_name=db_logfiles_name)
        f.close()

        logger.info("Process done for %s" % short_name)

    else:
        logger.error("Unsupported file format of %s" % short_name)
        raise RuntimeError("Unsupported file format of %s. Only support gz files" % short_name)


###########    MAIN    ###########

if __name__ == "__main__":


    #### Creation of the Databases ###
    creat_db()
    process_acloudtrailfile(filename="899267438132_CloudTrail_eu-west-1_20181012T0755Z_vAFxRvMPnWhVxQGv.json.gz")

    ## test with a file ##




