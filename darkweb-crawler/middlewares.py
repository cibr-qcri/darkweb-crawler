import json
import os
from operator import attrgetter

import scrapy
from scrapy import signals
from scrapy.downloadermiddlewares.retry import RetryMiddleware
from scrapy.utils.project import get_project_settings
from twisted.web.client import ResponseFailed

from .support import TorHelper

http_proxy = "http://" + os.getenv("TOR_PROXY_SERVICE_HOST") + ":8118"
ignore_type = (".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".rar", ".deb", ".wav", ".mp4", ".zip", ".mp3",
               ".gz", ".rar", ".sig", ".epub", ".xz")
request_count = {}


class ASpiderMiddleware(object):
    # Not all methods need to be defined. If a method is not defined,
    # scrapy acts as if the spider middleware does not modify the
    # passed objects.

    @classmethod
    def from_crawler(cls, crawler):
        # This method is used by Scrapy to create your spiders.
        s = cls()
        crawler.signals.connect(s.spider_opened, signal=signals.spider_opened)
        return s

    def process_spider_input(self, response, spider):
        # Called for each response that goes through the spider
        # middleware and into the spider.

        # Should return None or raise an exception.
        return None

    def process_spider_output(self, response, result, spider):
        # Called with the results returned from the Spider, after
        # it has processed the response.

        # Must return an iterable of Request, dict or Item objects.
        for i in result:
            yield i

    def process_spider_exception(self, response, exception, spider):
        # Called when a spider or process_spider_input() method
        # (from other spider middleware) raises an exception.

        # Should return either None or an iterable of Response, dict
        # or Item objects.
        pass

    def process_start_requests(self, start_requests, spider):
        # Called with the start requests of the spider, and works
        # similarly to the process_spider_output() method, except
        # that it doesn’t have a response associated.

        # Must return only requests (not items).
        for r in start_requests:
            yield r

    def spider_opened(self, spider):
        spider.logger.info('Spider opened: %s' % spider.name)


class TorspiderDownloaderMiddleware(object):
    # Not all methods need to be defined. If a method is not defined,
    # scrapy acts as if the downloader middleware does not modify the
    # passed objects.

    def __init__(self, user_agent):
        settings = get_project_settings()
        self.user_agent = user_agent
        self.helper = TorHelper()
        self.retry = RetryMiddleware(settings)

    @classmethod
    def from_crawler(cls, crawler):
        # This method is used by Scrapy to create your spiders.
        s = cls(user_agent=crawler.settings.get('USER_AGENT'))
        crawler.signals.connect(s.spider_opened, signal=signals.spider_opened)
        return s

    def process_request(self, request, spider):
        # Called for each request that goes through the downloader
        # middleware.

        # Must either:
        # - return None: continue processing this request
        # - or return a Response object
        # - or return a Request object
        # - or raise IgnoreRequest: process_exception() methods of
        #   installed downloader middleware will be called

        return None

    def process_response(self, request, response, spider):
        # Called with the response returned from the downloader.

        # Must either;
        # - return a Response object
        # - return a Request object
        # - or raise IgnoreRequest
        # if b"Content-Type" not in response.headers or b"text/html" not in response.headers[b"Content-Type"] :
        #     self.time_log.pop(request.url)
        #     raise scrapy.exceptions.IgnoreRequest

        if "dataloss" in response.flags:
            u = json.loads(attrgetter("_body")(request))["url"]
            msg = "request url:{0} failed due to data loss".format(u)
            spider.logger.error(msg)
            return self.retry.process_exception(request, ResponseFailed(msg), spider)

        s = attrgetter("_body")(response)
        body = json.loads(s)

        if "history" not in body or len(body["history"]) == 0:
            raise scrapy.exceptions.IgnoreRequest

        history = body["history"]
        last_response = history[-1]["response"]

        if "content" not in last_response or "text" not in last_response["content"]:
            raise scrapy.exceptions.IgnoreRequest

        if last_response["status"] >= 400:
            raise scrapy.exceptions.IgnoreRequest

        return response

    def process_exception(self, request, exception, spider):
        # Called when a download handler or a process_request()
        # (from other downloader middleware) raises an exception.

        # Must either:
        # - return None: continue processing this exception
        # - return a Response object: stops process_exception() chain
        # - return a Request object: stops process_exception() chain

        return None

    def spider_opened(self, spider):
        spider.logger.info('Spider opened: %s' % spider.name)
