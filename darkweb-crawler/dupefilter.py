from scrapy_redis.dupefilter import RFPDupeFilter
from scrapy_splash.dupefilter import splash_request_fingerprint


class CustomRFPDupeFilter(RFPDupeFilter):
    def request_fingerprint(self, request):
        return splash_request_fingerprint(request)
