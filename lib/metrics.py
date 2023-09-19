class Metrics:

    def __init__(self, redisMessaging):
        self.redisMessaging = redisMessaging

    def initializeMetrics(self) -> bool:
        """
        Preloads all metrics, and sets their initial value to 0.
        """

        print("Initializing Metrics")

        metricList = [
            {'serviceName':'api', 'metricName':'prom_flask_http_geored_endpoints', 'metricType':'counter', 'metricHelp':'Number of Geored Pushes Received'},
            {'serviceName':'diameter', 'metricName':'prom_diam_inbound_count', 'metricType':'counter', 'metricHelp':'Number of Diameter Inbounds'},
            {'serviceName':'geored', 'metricName':'prom_http_geored', 'metricType':'counter', 'metricHelp':'Number of Geored Pushes'},
            {'serviceName':'webhook', 'metricName':'prom_http_webhook', 'metricType':'counter', 'metricHelp':'Number of Webhook Pushes'},
            {'serviceName':'database', 'metricName':'prom_eir_devices', 'metricType':'counter', 'metricHelp':'Profile of attached devices'},
            {'serviceName':'diameter', 'metricName':'prom_ims_subs', 'metricType':'gauge', 'metricHelp':'Number of attached IMS Subscribers'},
            {'serviceName':'diameter', 'metricName':'prom_mme_subs', 'metricType':'gauge', 'metricHelp':'Number of attached MME Subscribers'},
            {'serviceName':'diameter', 'metricName':'prom_pcrf_subs', 'metricType':'gauge', 'metricHelp':'Number of attached PCRF Subscribers'},
            {'serviceName':'diameter', 'metricName':'prom_diam_auth_event_count', 'metricType':'counter', 'metricHelp':'Diameter Authentication related Counters'},
            {'serviceName':'diameter', 'metricName':'prom_diam_response_count_successful', 'metricType':'counter', 'metricHelp':'Number of Successful Diameter Responses'},
            {'serviceName':'diameter', 'metricName':'prom_diam_response_count_fail', 'metricType':'counter', 'metricHelp':'Number of Failed Diameter Responses'}
        ]

        for metric in metricList:
            try:
                self.redisMessaging.sendMetric(serviceName=metric['serviceName'],
                                                metricName=metric['metricName'],
                                                metricType=metric['metricType'], 
                                                metricAction='inc', 
                                                metricValue=0.0, 
                                                metricHelp=metric['metricHelp'],
                                                metricLabels=metric['metricLabels'],
                                                metricExpiry=60)
            except Exception as e:
                print(e)
                pass
        
        return True