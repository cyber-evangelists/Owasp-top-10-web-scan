# from app.models.db_models.WebAnalyser import WebAnalyserModel
# from app.services.redis import add_dict_to_redis
# from beanie.odm.operators.update.general import Set

from dotenv import load_dotenv
from zapv2 import ZAPv2
from logs import logger
import os
import json



load_dotenv()
os.makedirs("scan-reports", exist_ok=True)
apikey = os.getenv('ZAPURL')
zap = ZAPv2(proxies={'http': apikey, 'https': apikey})


def web_scan(url,id=None):
    try:
        logger.info('Accessing target {}'.format(url))
        zap.urlopen(url)
        logger.info(''.format(url))
        scanid = zap.spider.scan(url)
        passive_scan = []
        while (int(zap.pscan.records_to_scan) > 0):
            logger.info('Records to passive scan : {}'.format(zap.pscan.records_to_scan))
            passive_scan.append(zap.pscan.records_to_scan)

        logger.info('Passive Scan completed')

        logger.info('Active Scanning target {}'.format(url))
        scanid = zap.ascan.scan(url)
        while (int(zap.ascan.status(scanid)) < 100):
            logger.info('Scan progress %: {}'.format(zap.ascan.status(scanid)))

        logger.info('Active Scan completed')
        logger.info('Hosts: {}'.format(', '.join(zap.core.hosts)))
        alerts = zap.core.alerts()
        filename = str(zap.core.hosts[0]) + "-scan-report.json"
        file_path = "scan-reports"+"/"+filename
        save_file = open(file_path, "w")  
        json.dump(alerts, save_file, indent = 6)  
        save_file.close()  
        logger.info(f'Report saved: {file_path}')
    except Exception as Error:
        logger.info(f'Error while performing web scan is: {Error}')


if __name__ == '__main__':
    url = input("please enter URL [https://example.com]: ")
    web_scan(url)