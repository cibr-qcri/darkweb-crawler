import base64
import hashlib
import os
import re
from datetime import datetime

from bs4 import BeautifulSoup
from scrapy_redis.spiders import RedisSpider

from ..items import TorspiderItem
from ..support import TorHelper

ONION_PAT = re.compile(r"(?:https?://)?(([^/.]*)\.)*(\w{56}|\w{16})\.onion")


class TorSpider(RedisSpider):
    name = "darkweb-crawler"

    def __init__(self):
        RedisSpider.__init__(self)
        self.helper = TorHelper()
        self.site_info = {}
        self.seq_number = 0
        self.dirname = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.domain_count = dict()

    def make_requests_from_url(self, url):
        return TorHelper.build_splash_request(url, callback=self.parse)

    def parse(self, response):
        history = response.data['history']
        last_response = history[-1]["response"]

        requested_url = response.url.strip("/")
        requested_url = requested_url.replace("///", "//")
        url = last_response["url"].strip("/")
        scheme = self.helper.get_scheme(url)
        domain = self.helper.get_domain(url)

        http_redirect, _ = self.helper \
            .build_redirect_paths(history, response.data["http_redirects"], requested_url, url)
        self.helper.persist_http_redirects(http_redirect)

        js_files = response.data["js"]
        css_files = response.data["css"]

        rendered_page = response.data["rendered"]
        raw_page = str(base64.b64decode(last_response["content"]["text"]))

        headers = [{"key": entry["name"], "value": entry["value"]} for entry in last_response["headers"]]

        soup_rendered = BeautifulSoup(rendered_page, "lxml")
        urls = self.helper.extract_all_urls(url, domain, scheme, soup_rendered)

        if ONION_PAT.match(url):
            domain_key = domain.replace('.onion', '.ox')
            self.server.sadd(domain_key, url)

            item = TorspiderItem()
            item["date"] = datetime.today()
            item["url"] = url
            item['domain'] = domain
            item["scheme"] = self.helper.get_scheme(url)
            item['title'] = soup_rendered.title.string.strip() \
                if soup_rendered.title and soup_rendered.title.string else ""
            item['scheme'] = scheme

            base_url = scheme + "://" + domain
            item["homepage"] = base_url == requested_url
            self.logger.info("######################################")
            self.logger.info(requested_url)
            self.logger.info(item["homepage"])

            item['urls'] = urls
            item["version"] = 3 if len(domain.replace(".onion", "")) > 16 else 2
            item["response_header"] = headers
            item["btc"] = self.helper.get_btc(soup_rendered)
            item["rendered_page"] = rendered_page
            item["raw_page"] = raw_page
            item["raw_md5"] = hashlib.md5(raw_page.encode('utf-8')).hexdigest(),
            item["js"] = len(soup_rendered.find_all('script')) > 0
            item["css"] = len(soup_rendered.find_all('style')) > 0
            item["screenshot"] = base64.b64decode(response.data['jpeg'])
            item["js_files"] = js_files
            item["css_files"] = css_files

            if len(urls["external"]["meta"]["tor"]) > 0:
                item["redirect"] = {
                    "url": urls["external"]["meta"]["tor"][0],
                    "type": "meta"
                }

            yield item

            for u in sorted(urls["internal"]["anchor"]):
                domain_count = self.server.scard(domain_key)
                if domain_count >= 100:
                    break
                if ONION_PAT.match(u) and u != url:
                    self.server.sadd(domain_key, u)
                    yield TorHelper.build_splash_request(u, callback=self.parse)
